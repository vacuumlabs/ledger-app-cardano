# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

import hashlib
import re
from collections.abc import Sequence
from pathlib import Path
from time import time
from typing import cast

import base58
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Changes, Bip44Coins
from bip_utils.bip.bip32.bip32_path import Bip32Path, Bip32PathParser
from ecdsa.curves import Ed25519
from ecdsa.keys import VerifyingKey
from ledgered.devices import Device
from ragger.backend import BackendInterface
from ragger.bip import CurveChoice, calculate_public_key_and_chaincode
from ragger.bip.seed import SPECULOS_MNEMONIC
from ragger.error import ExceptionRAPDU
from ragger.navigator import BaseNavInsID, Navigator, NavIns, NavInsID
from ragger.navigator.navigation_scenario import (
    NavigateWithScenario,
    NavigationScenarioData,
    UseCase,
)

from tests.application_client.command_builder import AddressType
from tests.application_client.command_sender import CommandSender
from tests.application_client.status_words import StatusWord
from tests.standalone.input_files.cvote import CVoteTestCase
from tests.standalone.input_files.derive_address import DeriveAddressTestCase
from tests.standalone.input_files.pubkey import (
    PubKeyTestCase,
    convert_ragger_bip_pubkey_to_app_pubkey,
)
from tests.standalone.input_files.signMsg import SignMsgTestCase
from tests.standalone.input_files.signOpCert import OpCertTestCase

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()
NANO_CHOICE_CONFIRM_INSTRUCTIONS = [NavInsID.BOTH_CLICK]
NANO_REVIEW_CONFIRM_INSTRUCTIONS = [NavInsID.LEFT_CLICK, NavInsID.BOTH_CLICK]

_REJECT_TEXT = r"^Reject operation$"
_WARNING_PATH = "warning"


class NavContext:
    """Bundles the device/navigator/scenario_navigator triple passed to every navigation helper."""

    def __init__(
        self,
        device: Device,
        navigator: Navigator,
        scenario_navigator: NavigateWithScenario,
    ) -> None:
        self.device = device
        self.navigator = navigator
        self.scenario_navigator = scenario_navigator

    @property
    def is_nano(self) -> bool:
        return cast(bool, self.device.is_nano)

    @property
    def screenshot_path(self) -> Path:
        return self.scenario_navigator.screenshot_path


def assert_expected_deny_and_app_alive(backend: BackendInterface, err: ExceptionRAPDU, expected_swo: int | None) -> None:
    assert expected_swo is not None
    assert err.status == expected_swo

    try:
        response = CommandSender(backend).get_version_raw()
    except ExceptionRAPDU as liveness_err:
        raise AssertionError(
            "App correctly denied the invalid input, but is not alive afterwards.\n"
            f"Expected deny SW: {hex(expected_swo)}\n"
            f"Observed deny SW: {hex(err.status)}\n"
            f"Follow-up GET_VERSION SW: {hex(liveness_err.status)}\n"
            "This usually means the app sent the correct deny response and then "
            "crashed or corrupted its APDU/session state before the next command."
        ) from liveness_err

    assert response.status == StatusWord.SWO_SUCCESS, (
        "App correctly denied the invalid input, but is not healthy afterwards.\n"
        f"Expected deny SW: {hex(expected_swo)}\n"
        f"Observed deny SW: {hex(err.status)}\n"
        f"Follow-up GET_VERSION SW: {hex(response.status)}\n"
        f"Expected GET_VERSION SW: {hex(StatusWord.SWO_SUCCESS)}"
    )


def _nano_instructions(
    instructions: Sequence[NavIns | BaseNavInsID] | None,
    default: Sequence[NavIns | BaseNavInsID],
) -> Sequence[NavIns | BaseNavInsID]:
    return list(instructions) if instructions is not None else default


def nano_navigate_without_waits(
    backend: BackendInterface,
    navigator: Navigator,
    instructions: Sequence[NavIns | BaseNavInsID],
    timeout: float = 10.0,
    screen_change_before_first_instruction: bool = True,
) -> None:
    wait_for_screen_change = getattr(backend, "wait_for_screen_change", None)
    if screen_change_before_first_instruction and callable(wait_for_screen_change):
        wait_for_screen_change(timeout)

    for instruction in instructions:
        navigator.navigate(
            [instruction],
            timeout=timeout,
            screen_change_before_first_instruction=False,
            screen_change_after_last_instruction=False,
        )


def nano_navigate_until_text_relaxed(
    backend: BackendInterface,
    navigator: Navigator,
    navigate_instruction: NavIns | BaseNavInsID,
    validation_instructions: Sequence[NavIns | BaseNavInsID],
    text: str,
    timeout: float = 300.0,
    screen_change_before_first_instruction: bool = True,
) -> None:
    compare_screen_with_text = getattr(backend, "compare_screen_with_text", None)
    wait_for_screen_change = getattr(backend, "wait_for_screen_change", None)

    if not callable(compare_screen_with_text) or not callable(wait_for_screen_change):
        navigator.navigate_until_text(
            navigate_instruction=navigate_instruction,
            validation_instructions=validation_instructions,
            text=text,
            timeout=int(timeout),
            screen_change_before_first_instruction=screen_change_before_first_instruction,
            screen_change_after_last_instruction=False,
        )
        return

    if screen_change_before_first_instruction:
        wait_for_screen_change(timeout)

    deadline = time() + timeout
    while not compare_screen_with_text(text):
        remaining = deadline - time()
        if remaining <= 0:
            raise TimeoutError(f"Timeout waiting for text {text}")

        nano_navigate_without_waits(
            backend,
            navigator,
            [navigate_instruction],
            timeout=min(remaining, 10.0),
            screen_change_before_first_instruction=False,
        )

        remaining = deadline - time()
        if remaining <= 0:
            raise TimeoutError(f"Timeout waiting for text {text}")

        try:
            wait_for_screen_change(min(remaining, 1.0))
        except TimeoutError:
            # Some Nano NBGL streaming boundaries consume the action without a
            # screenshot delta that Speculos detects reliably. Re-check screen
            # text on the next loop iteration instead of failing immediately.
            pass

    nano_navigate_without_waits(
        backend,
        navigator,
        validation_instructions,
        timeout=min(max(deadline - time(), 0.1), 10.0),
        screen_change_before_first_instruction=False,
    )


def _navigate_maybe_compare(
    ctx: NavContext,
    test_name: str,
    instructions: Sequence[NavIns | BaseNavInsID],
    do_comparison: bool = True,
    **kwargs,
) -> None:
    """Navigate with or without golden screenshot comparison."""
    if do_comparison:
        ctx.navigator.navigate_and_compare(
            ctx.screenshot_path,
            test_name,
            instructions,
            **kwargs,
        )
    else:
        ctx.navigator.navigate(
            instructions,
            **kwargs,
        )


def _navigate_until_text_optional_compare(
    ctx: NavContext,
    test_name: str,
    navigate_instruction: NavIns | BaseNavInsID,
    validation_instructions: Sequence[NavIns | BaseNavInsID],
    text: str,
    do_comparison: bool = True,
    screen_change_before_first_instruction: bool = True,
    screen_change_after_last_instruction: bool = True,
) -> None:
    if do_comparison:
        ctx.navigator.navigate_until_text_and_compare(
            navigate_instruction=navigate_instruction,
            validation_instructions=validation_instructions,
            text=text,
            path=ctx.screenshot_path,
            test_case_name=test_name,
            screen_change_before_first_instruction=screen_change_before_first_instruction,
            screen_change_after_last_instruction=screen_change_after_last_instruction,
        )
    else:
        ctx.navigator.navigate_until_text(
            navigate_instruction=navigate_instruction,
            validation_instructions=validation_instructions,
            text=text,
            screen_change_before_first_instruction=screen_change_before_first_instruction,
            screen_change_after_last_instruction=screen_change_after_last_instruction,
        )


# Check if a signature of a given message is valid
def verify_name(name: str) -> None:
    """Verify the app name, based on defines in Makefile

    Args:
        name (str): Name to be checked
    """

    name_str = ""
    lines = _read_makefile()
    name_re = re.compile(r"^APPNAME\s?=\s?\"?(?P<val>[^\"]+)\"?", re.I)
    for line in lines:
        info = name_re.match(line)
        if info:
            dinfo = info.groupdict()
            name_str = dinfo["val"]
    assert name == name_str


def verify_version(version: str) -> None:
    """Verify the app version, based on defines in Makefile

    Args:
        Version (str): Version to be checked
    """

    vers_dict = {}
    vers_str = ""
    lines = _read_makefile()
    version_re = re.compile(r"^APPVERSION_(?P<part>\w)\s?=\s?(?P<val>\d*)", re.I)
    for line in lines:
        info = version_re.match(line)
        if info:
            dinfo = info.groupdict()
            vers_dict[dinfo["part"]] = dinfo["val"]
    try:
        vers_str = f"{vers_dict['M']}.{vers_dict['N']}.{vers_dict['P']}"
    except KeyError:
        pass
    assert version == vers_str


def _read_makefile() -> list[str]:
    """Read lines from the parent Makefile"""

    parent = Path(__file__).parent.parent.parent.resolve()
    makefile = f"{parent}/Makefile"
    with open(makefile, encoding="utf-8") as f_p:
        lines = f_p.readlines()
    return lines


def idTestFunc(
    testCase: DeriveAddressTestCase | PubKeyTestCase | CVoteTestCase | OpCertTestCase | SignMsgTestCase,
) -> str:
    """Retrieve the test case name for friendly display

    Args:
        testCase (xxxTestCase): Targeted test case

    Returns:
        Test case name
    """
    return testCase.name


def _review_approve_with_warning(
    ctx: NavContext,
    test_name: str,
    target_text: str,
    warnings: Sequence[object],
    do_comparison: bool = True,
    nano_review_instructions: Sequence[NavIns | BaseNavInsID] | None = None,
) -> None:
    if not ctx.is_nano:
        detail_navigation: list[NavIns | BaseNavInsID] = [NavInsID.RIGHT_HEADER_TAP]
        for warning_index in range(min(len(warnings), 3)):
            detail_navigation += [
                NavIns(NavInsID.CHOICE_CHOOSE, (warning_index + 1,)),
                NavInsID.LEFT_HEADER_TAP,
            ]
        if len(warnings) > 3:
            detail_navigation += [
                NavIns(NavInsID.CHOICE_CHOOSE, (4,)),
                NavInsID.LEFT_HEADER_TAP,
            ]
        detail_navigation += [NavInsID.LEFT_HEADER_TAP]

        _navigate_maybe_compare(
            ctx,
            f"{test_name}/{_WARNING_PATH}/details",
            detail_navigation,
            do_comparison,
        )
        _navigate_maybe_compare(
            ctx,
            f"{test_name}/{_WARNING_PATH}",
            [NavInsID.USE_CASE_CHOICE_REJECT],
            do_comparison,
            screen_change_before_first_instruction=False,
            screen_change_after_last_instruction=False,
        )
        _navigate_until_text_optional_compare(
            ctx,
            test_name=test_name,
            navigate_instruction=NavInsID.USE_CASE_REVIEW_NEXT,
            validation_instructions=[
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS,
            ],
            text=r"^Hold to sign$",
            do_comparison=do_comparison,
            screen_change_before_first_instruction=True,
        )
        return

    nano_review_instructions = _nano_instructions(nano_review_instructions, [NavInsID.BOTH_CLICK])

    # Nano warning flow: move from the intro warning page to each warning title,
    # open its details with both buttons, return with left, then continue.
    warning_navigation: list[NavIns | BaseNavInsID] = []
    for _warning in warnings:
        warning_navigation += [
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.LEFT_CLICK,
        ]
    # Exit the warning flow and enter the actual review.
    warning_navigation.append(NavInsID.RIGHT_CLICK)
    _navigate_maybe_compare(
        ctx,
        f"{test_name}/{_WARNING_PATH}",
        warning_navigation,
        do_comparison,
        screen_change_after_last_instruction=False,
    )

    # Navigate and snapshot the transaction review screens.
    _navigate_until_text_optional_compare(
        ctx,
        test_name=test_name,
        navigate_instruction=NavInsID.RIGHT_CLICK,
        validation_instructions=nano_review_instructions,
        text=target_text,
        do_comparison=do_comparison,
        screen_change_before_first_instruction=False,
    )


def review_approve(
    ctx: NavContext,
    test_name: str,
    target_text: str | None = None,
    warnings: Sequence[object] = (),
    has_warning_screen: bool = False,
    do_comparison: bool = True,
    nano_review_instructions: Sequence[NavIns | BaseNavInsID] | None = None,
    screen_change_before_first_instruction: bool = True,
) -> None:
    if has_warning_screen or warnings:
        _review_approve_with_warning(
            ctx,
            test_name=test_name,
            target_text=target_text if target_text is not None else _REJECT_TEXT,
            warnings=warnings,
            do_comparison=do_comparison,
            nano_review_instructions=nano_review_instructions,
        )
        return

    if not ctx.is_nano:
        if screen_change_before_first_instruction:
            ctx.scenario_navigator.review_approve(
                test_name=test_name,
                custom_screen_text=target_text,
                do_comparison=do_comparison,
            )
        else:
            navigator_backend = ctx.navigator._backend  # pylint: disable=protected-access
            scenario = NavigationScenarioData(ctx.device, navigator_backend, UseCase.TX_REVIEW, True)
            if target_text is not None:
                scenario.pattern = target_text

            screen_change_after_last_instruction = scenario.post_validation_spinner is None
            _navigate_until_text_optional_compare(
                ctx,
                test_name=test_name,
                navigate_instruction=scenario.navigation,
                validation_instructions=scenario.validation,
                text=scenario.pattern,
                do_comparison=do_comparison,
                screen_change_before_first_instruction=False,
                screen_change_after_last_instruction=screen_change_after_last_instruction,
            )

            if scenario.post_validation_spinner is not None:
                navigator_backend.wait_for_text_on_screen(scenario.post_validation_spinner)
        return

    _navigate_until_text_optional_compare(
        ctx,
        test_name=test_name,
        navigate_instruction=NavInsID.RIGHT_CLICK,
        validation_instructions=_nano_instructions(
            nano_review_instructions,
            NANO_CHOICE_CONFIRM_INSTRUCTIONS if target_text is not None else NANO_REVIEW_CONFIRM_INSTRUCTIONS,
        ),
        text=target_text if target_text is not None else _REJECT_TEXT,
        do_comparison=do_comparison,
        screen_change_before_first_instruction=screen_change_before_first_instruction,
    )


def choice_approve(
    ctx: NavContext,
    test_name: str,
    confirm_text: str,
    do_comparison: bool = True,
    dismiss_status: bool = True,
) -> None:
    if not ctx.is_nano:
        instructions = [NavInsID.USE_CASE_CHOICE_CONFIRM]
        if dismiss_status:
            instructions.append(NavInsID.USE_CASE_STATUS_DISMISS)
        _navigate_maybe_compare(
            ctx,
            test_name,
            instructions,
            do_comparison,
        )
        return

    _navigate_until_text_optional_compare(
        ctx,
        test_name=test_name,
        navigate_instruction=NavInsID.RIGHT_CLICK,
        validation_instructions=NANO_CHOICE_CONFIRM_INSTRUCTIONS,
        text=confirm_text,
        do_comparison=do_comparison,
    )


def choice_reject(
    ctx: NavContext,
    test_name: str,
    reject_text: str,
    do_comparison: bool = True,
    dismiss_status: bool = True,
) -> None:
    if not ctx.is_nano:
        instructions = [NavInsID.USE_CASE_CHOICE_REJECT]
        if dismiss_status:
            instructions.append(NavInsID.USE_CASE_STATUS_DISMISS)
        _navigate_maybe_compare(
            ctx,
            test_name,
            instructions,
            do_comparison,
        )
        return

    _navigate_until_text_optional_compare(
        ctx,
        test_name=test_name,
        navigate_instruction=NavInsID.RIGHT_CLICK,
        validation_instructions=[NavInsID.LEFT_CLICK, NavInsID.BOTH_CLICK],
        text=reject_text,
        do_comparison=do_comparison,
    )


def derive_address(testCase: DeriveAddressTestCase) -> bytes:
    """Derive an address from a test case

    Args:
        testCase (DeriveAddressTestCase): The test case

    Returns:
        The derived address
    """

    if testCase.params.addrType == AddressType.BYRON:
        return _deriveAddressByron(testCase)
    return _deriveAddressShelley(testCase)


def _deriveAddressByron(testCase: DeriveAddressTestCase) -> bytes:
    """Derive the Byron address from the path."""
    # Generate seed from mnemonic
    # Use the deterministic Speculos mnemonic for reproducible tests.
    seed_bytes = Bip39SeedGenerator(SPECULOS_MNEMONIC).Generate()

    # Construct from seed
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.CARDANO_BYRON_LEDGER)

    # Derive the key for the specified path
    bip32Path: Bip32Path = Bip32PathParser.Parse(testCase.params.spendingValue).ToList()
    bip44_acc = bip44_mst_ctx.Purpose().Coin().Account(bip32Path[2])
    bip44_chg = bip44_acc.Change(Bip44Changes.CHAIN_EXT if bip32Path[3] == 0 else Bip44Changes.CHAIN_INT)
    bip44_addr = bip44_chg.AddressIndex(bip32Path[4])

    # Convert the human-readable Byron address back to the raw APDU payload.
    return base58.b58decode(cast(str, bip44_addr.PublicKey().ToAddress()))


def _deriveAddressShelley(testCase: DeriveAddressTestCase) -> bytes:
    """Derive the Shelley base address from the path"""
    params = testCase.params
    key = f"{(int(params.addrType) << 4) | int(params.netDesc.networkId):02x}"
    if params.spendingValue.startswith("m/"):
        pk, _ = get_device_pubkey(params.spendingValue)
        key += hashlib.blake2b(pk, digest_size=28).digest().hex()
    else:
        key += params.spendingValue
    if params.addrType in (AddressType.POINTER_KEY, AddressType.POINTER_SCRIPT):
        key += _appenduint32(int(params.stakingValue[0:8], 16))
        key += _appenduint32(int(params.stakingValue[8:16], 16))
        key += _appenduint32(int(params.stakingValue[16:24], 16))
    elif params.stakingValue.startswith("m/"):
        pk, _ = get_device_pubkey(params.stakingValue)
        key += hashlib.blake2b(pk, digest_size=28).digest().hex()
    else:
        key += params.stakingValue
    return bytes.fromhex(key)


def _appenduint32(value: int) -> str:
    """Append a Variable Length uint32 to a buffer"""

    if value == 0:
        return "00"

    chunks: list[int] = []
    while value:
        chunks.append(value & 0x7F)
        value >>= 7

    result = ""
    while len(chunks) > 1:
        result += f"{chunks.pop() | 0x80:02x}"
    result += f"{chunks.pop():02x}"
    return result


def get_device_pubkey(path: str) -> tuple[bytes, str]:
    """Retrieve the Public Key

    Args:
        path (str): Derivation path

    Returns:
        The Reference PK and the byte Chain Code
    """
    ref_pk, ref_chain_code = calculate_public_key_and_chaincode(CurveChoice.Ed25519Kholaw, path)
    return (
        bytes.fromhex(convert_ragger_bip_pubkey_to_app_pubkey(ref_pk)),
        ref_chain_code,
    )


def verify_signature(path: str, signature: bytes, data: bytes) -> None:
    """Check the signature validity

    Args:
        path (str): The derivation path
        signature (bytes): The received signature
        data (bytes): The signed data
    """

    ref_pk, _ = get_device_pubkey(path)
    pk: VerifyingKey = VerifyingKey.from_string(ref_pk, curve=Ed25519)
    assert pk.verify(signature, data, hashlib.sha512)
