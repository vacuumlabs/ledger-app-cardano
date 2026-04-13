# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Derive Native Script Hash check
"""

import hashlib
import re

import cbor2
import pytest

from ledgered.devices import Device
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario

from tests.application_client.status_words import StatusWord
from tests.application_client.command_sender import CommandSender
from tests.application_client.response_unpacker import (
    unpack_derive_native_script_hash_response,
)

from tests.application_client.command_builder import (
    NativeScript,
    NativeScriptParamsInvalid,
    NativeScriptParamsNofK,
    NativeScriptParamsPubkey,
    NativeScriptParamsScripts,
    NativeScriptType,
)
from tests.standalone.input_files.native_script import (
    InvalidScriptTestCases,
    ValidNativeScriptTestCase,
    ValidNativeScriptTestCases,
)
from tests.standalone.utils import (
    NavContext,
    idTestFunc,
    get_device_pubkey,
    nano_navigate_without_waits,
    assert_expected_deny_and_app_alive,
)


def _resolve_key_hash(script: NativeScript) -> bytes:
    """Resolve a PUBKEY script to its 28-byte key hash.

    PUBKEY_THIRD_PARTY: the key field is already a hex-encoded key hash.
    PUBKEY_DEVICE_OWNED: the key field is a BIP44 derivation path; derive
    the public key from the device mnemonic and blake2b-224 it.
    """
    if script.type == NativeScriptType.PUBKEY_THIRD_PARTY:
        assert isinstance(script.params, NativeScriptParamsPubkey)
        return bytes.fromhex(script.params.key)

    # PUBKEY_DEVICE_OWNED — derive pubkey from path, then hash it
    assert isinstance(script.params, NativeScriptParamsPubkey)
    pubkey_bytes, _ = get_device_pubkey(script.params.key)
    return hashlib.blake2b(pubkey_bytes, digest_size=28).digest()


def _native_script_to_cbor_structure(script: NativeScript) -> list:
    """Recursively build the CBOR-encodable structure for a NativeScript.

    Cardano native script encoding:
        sig(key_hash)        -> [0, key_hash]
        all(scripts)         -> [1, [scripts...]]
        any(scripts)         -> [2, [scripts...]]
        atLeast(n, scripts)  -> [3, n, [scripts...]]
        after(slot)          -> [4, slot]
        before(slot)         -> [5, slot]
    """
    if script.type in (
        NativeScriptType.PUBKEY_DEVICE_OWNED,
        NativeScriptType.PUBKEY_THIRD_PARTY,
    ):
        return [0, _resolve_key_hash(script)]

    if script.type == NativeScriptType.ALL:
        assert isinstance(script.params, NativeScriptParamsScripts)
        return [1, [_native_script_to_cbor_structure(s) for s in script.params.scripts]]

    if script.type == NativeScriptType.ANY:
        assert isinstance(script.params, NativeScriptParamsScripts)
        return [2, [_native_script_to_cbor_structure(s) for s in script.params.scripts]]

    if script.type == NativeScriptType.N_OF_K:
        assert isinstance(script.params, NativeScriptParamsNofK)
        return [
            3,
            script.params.requiredCount,
            [_native_script_to_cbor_structure(s) for s in script.params.scripts],
        ]

    if script.type == NativeScriptType.INVALID_BEFORE:
        assert isinstance(script.params, NativeScriptParamsInvalid)
        return [4, script.params.slot]

    if script.type == NativeScriptType.INVALID_HEREAFTER:
        assert isinstance(script.params, NativeScriptParamsInvalid)
        return [5, script.params.slot]

    raise ValueError(f"Unknown NativeScriptType: {script.type}")


def _compute_expected_script_hash(script: NativeScript) -> str:
    """Compute the expected script hash: blake2b-224 of (language_tag || CBOR).

    Cardano script hashes are prefixed with a language tag byte before hashing.
    Native scripts use tag 0x00.
    """
    serialized = cbor2.dumps(_native_script_to_cbor_structure(script))
    return hashlib.blake2b(b"\x00" + serialized, digest_size=28).hexdigest()


def _native_script_step_final_label(script: NativeScript) -> str:
    if script.type in (NativeScriptType.ALL, NativeScriptType.ANY):
        assert isinstance(script.params, NativeScriptParamsScripts)
        return rf"^{len(script.params.scripts)} nested scripts$"
    if script.type == NativeScriptType.N_OF_K:
        assert isinstance(script.params, NativeScriptParamsNofK)
        return rf"^{len(script.params.scripts)} nested scripts$"
    if script.type == NativeScriptType.PUBKEY_DEVICE_OWNED:
        assert hasattr(script.params, "key")
        return rf"^{re.escape(script.params.key)}$"
    if script.type == NativeScriptType.PUBKEY_THIRD_PARTY:
        return r"^Pubkey hash \(2/2\)$"
    if script.type == NativeScriptType.INVALID_BEFORE:
        assert hasattr(script.params, "slot")
        return rf"^{script.params.slot}$"
    if script.type == NativeScriptType.INVALID_HEREAFTER:
        assert hasattr(script.params, "slot")
        return rf"^{script.params.slot}$"
    raise ValueError(f"Unexpected native script type: {script.type}")


def _native_script_step_right_clicks(script: NativeScript) -> int | None:
    if script.type in (
        NativeScriptType.INVALID_BEFORE,
        NativeScriptType.INVALID_HEREAFTER,
    ):
        assert hasattr(script.params, "slot")
        if script.params.slot > 0xFFFFFFFF:
            return 3
    return None


@pytest.mark.parametrize("testCase", ValidNativeScriptTestCases, ids=idTestFunc)
def test_derive_native_script_hash(
    device: Device,
    backend: BackendInterface,
    navigator: Navigator,
    scenario_navigator: NavigateWithScenario,
    testCase: ValidNativeScriptTestCase,
) -> None:
    """Check Derive Native Script Hash"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)
    nav_ctx = NavContext(device, navigator, scenario_navigator)
    step_counter = [0]

    _deriveNativeScriptHash_init(nav_ctx, client, testCase.name, step_counter)
    assert testCase.script is not None
    _deriveNativeScriptHash_addScript(
        nav_ctx, client, testCase.script, testCase.name, step_counter
    )

    _deriveNativeScriptHash_finishWholeNativeScript(
        nav_ctx, client, testCase, step_counter
    )


def _deriveNativeScriptHash_init(
    nav_ctx: NavContext, client: CommandSender, test_name: str, step_counter: list[int]
) -> None:
    with client.derive_script_init_async() as has_data_available:
        if has_data_available:
            pass
        elif nav_ctx.is_nano:
            snap_name = f"{test_name}/step_{step_counter[0]:02d}_init"
            step_counter[0] += 1
            nav_ctx.navigator.navigate_until_text_and_compare(
                navigate_instruction=NavInsID.RIGHT_CLICK,
                validation_instructions=[NavInsID.RIGHT_CLICK],
                text=r"^Review Script$",
                path=nav_ctx.screenshot_path,
                test_case_name=snap_name,
                screen_change_before_first_instruction=True,
                screen_change_after_last_instruction=False,
            )
        else:
            nav_ctx.navigator.navigate(
                [NavInsID.USE_CASE_REVIEW_TAP],
                screen_change_before_first_instruction=False,
            )

    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS


def _deriveNativeScriptHash_addScript(
    nav_ctx: NavContext,
    client: CommandSender,
    script: NativeScript,
    test_name: str,
    step_counter: list[int],
) -> None:
    """Send the different add commands

    Args:
        nav_ctx (NavContext): Navigation context
        client (CommandSender): The command sender instance
        script (NativeScript): The test case
        test_name (str): Test case name for snapshot paths
        step_counter (list[int]): Mutable step counter for unique snapshot names
    """

    if script.type in [
        NativeScriptType.ALL,
        NativeScriptType.ANY,
        NativeScriptType.N_OF_K,
    ]:
        _deriveScriptHash_startComplexScript(
            nav_ctx, client, script, test_name, step_counter
        )
        assert isinstance(
            script.params, (NativeScriptParamsScripts, NativeScriptParamsNofK)
        )
        for subscript in script.params.scripts:
            _deriveNativeScriptHash_addScript(
                nav_ctx, client, subscript, test_name, step_counter
            )
    else:
        _deriveNativeScriptHash_addSimpleScript(
            nav_ctx, client, script, test_name, step_counter
        )


def _deriveNativeScriptHash_addSimpleScript(
    nav_ctx: NavContext,
    client: CommandSender,
    script: NativeScript,
    test_name: str,
    step_counter: list[int],
) -> None:
    """Send the add command for a simple script

    Args:
        nav_ctx (NavContext): Navigation context
        client (CommandSender): The command sender instance
        script (NativeScript): The script
        test_name (str): Test case name for snapshot paths
        step_counter (list[int]): Mutable step counter for unique snapshot names
    """

    with client.derive_script_add_simple_async(script) as has_data_available:
        if has_data_available:
            pass
        elif nav_ctx.is_nano:
            snap_name = f"{test_name}/step_{step_counter[0]:02d}_simple"
            step_counter[0] += 1
            step_right_clicks = _native_script_step_right_clicks(script)
            if step_right_clicks is None:
                nav_ctx.navigator.navigate_until_text_and_compare(
                    navigate_instruction=NavInsID.RIGHT_CLICK,
                    validation_instructions=[NavInsID.RIGHT_CLICK],
                    text=_native_script_step_final_label(script),
                    path=nav_ctx.screenshot_path,
                    test_case_name=snap_name,
                    screen_change_before_first_instruction=True,
                    screen_change_after_last_instruction=False,
                )
            else:
                # Big-number timelocks: fixed click count without screen-change
                # waits (the last click doesn't always trigger a detectable
                # screen delta in Speculos).  Content is still covered by the
                # non-big-number timelock snapshot tests.
                nano_navigate_without_waits(
                    backend=client.backend,
                    navigator=nav_ctx.navigator,
                    instructions=[NavInsID.RIGHT_CLICK] * step_right_clicks,
                    screen_change_before_first_instruction=True,
                )
        else:
            nav_ctx.navigator.navigate(
                [NavInsID.USE_CASE_REVIEW_TAP],
                screen_change_before_first_instruction=False,
            )

    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS


def _deriveScriptHash_startComplexScript(
    nav_ctx: NavContext,
    client: CommandSender,
    script: NativeScript,
    test_name: str,
    step_counter: list[int],
) -> None:
    """Send the add command for a complex script

    Args:
        nav_ctx (NavContext): Navigation context
        client (CommandSender): The command sender instance
        script (NativeScript): The script
        test_name (str): Test case name for snapshot paths
        step_counter (list[int]): Mutable step counter for unique snapshot names
    """

    with client.derive_script_add_complex_async(script) as has_data_available:
        if has_data_available:
            pass
        elif nav_ctx.is_nano:
            snap_name = f"{test_name}/step_{step_counter[0]:02d}_complex"
            step_counter[0] += 1
            nav_ctx.navigator.navigate_until_text_and_compare(
                navigate_instruction=NavInsID.RIGHT_CLICK,
                validation_instructions=[NavInsID.RIGHT_CLICK],
                text=_native_script_step_final_label(script),
                path=nav_ctx.screenshot_path,
                test_case_name=snap_name,
                screen_change_before_first_instruction=True,
                screen_change_after_last_instruction=False,
            )
        else:
            nav_ctx.navigator.navigate(
                [NavInsID.USE_CASE_REVIEW_TAP],
                screen_change_before_first_instruction=False,
            )

    # Check the status (Asynchronous)

    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS


def _deriveNativeScriptHash_finishWholeNativeScript(
    nav_ctx: NavContext,
    client: CommandSender,
    testCase: ValidNativeScriptTestCase,
    step_counter: list[int],
) -> None:
    """Send the finish command for the whole native script

    Args:
        nav_ctx (NavContext): Navigation context
        client (CommandSender): The command sender instance
        testCase (ValidNativeScriptTestCase): The test case
        step_counter (list[int]): Mutable step counter for unique snapshot names
    """

    assert testCase.displayFormat is not None
    with client.derive_script_finish_async(
        testCase.displayFormat
    ) as has_data_available:
        if has_data_available:
            pass
        elif nav_ctx.is_nano:
            snap_name = f"{testCase.name}/step_{step_counter[0]:02d}_finish"
            step_counter[0] += 1
            nav_ctx.navigator.navigate_until_text_and_compare(
                navigate_instruction=NavInsID.RIGHT_CLICK,
                validation_instructions=[NavInsID.BOTH_CLICK],
                text=r"^Confirm hash$",
                path=nav_ctx.screenshot_path,
                test_case_name=snap_name,
                screen_change_before_first_instruction=True,
            )
        else:
            nav_ctx.navigator.navigate(
                [NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_CONFIRM],
                screen_change_before_first_instruction=False,
            )
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS
    # Check the response
    script_hash = unpack_derive_native_script_hash_response(response.data)
    if testCase.ragger_expect is not None and testCase.ragger_expect.hash is not None:
        assert testCase.ragger_expect is not None
        assert script_hash.hex() == testCase.ragger_expect.hash
    # Independently verify the hash by serializing the script to CBOR and
    # hashing it.  For PUBKEY_DEVICE_OWNED scripts the key hash is derived
    # from the device mnemonic at runtime via get_device_pubkey().
    assert testCase.script is not None
    assert script_hash.hex() == _compute_expected_script_hash(testCase.script)
    _check_ragger_expect_native_script(testCase, script_hash)


def _check_ragger_expect_native_script(
    testCase: ValidNativeScriptTestCase, script_hash: bytes
) -> None:
    if testCase.ragger_expect is None:
        pytest.fail(
            f"Missing ragger_expect for native_script fixture {testCase.name!r}"
        )
    assert testCase.ragger_expect.hash is not None
    assert script_hash.hex() == testCase.ragger_expect.hash, (
        f"Script hash mismatch for {testCase.name!r}"
    )


@pytest.mark.parametrize("testCase", InvalidScriptTestCases, ids=idTestFunc)
def test_derive_native_script_hash_deny(
    backend: BackendInterface,
    navigator: Navigator,
    scenario_navigator: NavigateWithScenario,
    device: Device,
    testCase: ValidNativeScriptTestCase,
) -> None:
    """Check that invalid native scripts are denied with the expected status word."""
    client = CommandSender(backend)
    nav_ctx = NavContext(device, navigator, scenario_navigator)
    step_counter = [0]

    _deriveNativeScriptHash_init(nav_ctx, client, testCase.name, step_counter)

    assert testCase.script is not None
    with pytest.raises(ExceptionRAPDU) as err:
        _deriveNativeScriptHash_addScript(
            nav_ctx, client, testCase.script, testCase.name, step_counter
        )

    assert testCase.unit_test_expect is not None
    assert_expected_deny_and_app_alive(
        backend, err.value, testCase.unit_test_expect.swo
    )
