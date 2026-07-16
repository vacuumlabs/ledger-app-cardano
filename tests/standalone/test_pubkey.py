# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

import pytest
from ledgered.devices import Device
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator
from ragger.navigator.navigation_scenario import NavigateWithScenario

from tests.application_client.command_sender import CommandSender
from tests.application_client.response_unpacker import unpack_get_pubkey_response
from tests.application_client.status_words import StatusWord
from tests.standalone.input_files.pubkey import (
    PubKeyTestCase,
    denyTestCases,
    testsByron,
    testsColdKeys,
    testsCommitteeColdKeys,
    testsCommitteeHotKeys,
    testsCVoteKeysUnusual,
    testsCVoteKeysUsual,
    testsDRepKeys,
    testsMintKeys,
    testsMultisig,
    testsShelleyUnusual,
    testsShelleyUsual,
    testsSilentExport,
    testsSilentExportRareKeys,
)
from tests.standalone.settings import SettingID, SettingValue, settings_set
from tests.standalone.utils import (
    NavContext,
    assert_expected_deny_and_app_alive,
    choice_approve,
    get_device_pubkey,
    idTestFunc,
)


@pytest.mark.parametrize(
    "testCase",
    testsByron
    + testsShelleyUsual
    + testsShelleyUnusual
    + testsMultisig
    + testsColdKeys
    + testsCVoteKeysUsual
    + testsCVoteKeysUnusual
    + testsDRepKeys
    + testsCommitteeColdKeys
    + testsCommitteeHotKeys
    + testsMintKeys,
    ids=idTestFunc,
)
def test_pubkey_confirm(
    device: Device,
    backend: BackendInterface,
    navigator: Navigator,
    scenario_navigator: NavigateWithScenario,
    testCase: PubKeyTestCase,
) -> None:
    """Check Public Key with confirmation"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Force silent pubkey export off so confirmation is required for each key.
    settings_set(
        device,
        navigator,
        {
            SettingID.SILENT_PUBKEY_EXPORT: SettingValue.DISABLED,
            SettingID.EXPERT_MODE: SettingValue.DISABLED,
        },
        backend=backend,
    )
    nav_ctx = NavContext(device, navigator, scenario_navigator)
    assert testCase.path is not None
    with client.get_pubkey_async(testCase.path):
        if testCase.nav:
            choice_approve(nav_ctx, test_name=testCase.name, confirm_text=r"^Export$")
        else:
            pass
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS

    # Check the response
    _check_pubkey_result(response.data, testCase)


@pytest.mark.parametrize("testCase", testsSilentExport, ids=idTestFunc)
def test_pubkey_without_confirmation(
    device: Device,
    backend: BackendInterface,
    navigator: Navigator,
    testCase: PubKeyTestCase,
) -> None:
    """Check Public Key without confirmation"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    settings_set(
        device,
        navigator,
        {
            SettingID.SILENT_PUBKEY_EXPORT: SettingValue.ENABLED,
            SettingID.EXPERT_MODE: SettingValue.DISABLED,
        },
        backend=backend,
    )

    assert testCase.path is not None
    with client.get_pubkey_async(testCase.path):
        pass

    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS

    # Check the response
    _check_pubkey_result(response.data, testCase)


@pytest.mark.parametrize("testCase", testsSilentExportRareKeys, ids=idTestFunc)
def test_pubkey_confirm_even_with_silent_export(
    device: Device,
    backend: BackendInterface,
    navigator: Navigator,
    scenario_navigator: NavigateWithScenario,
    testCase: PubKeyTestCase,
) -> None:
    """Rare key paths (drep, committee, mint, pool cold) always require confirmation
    even when silent pubkey export is enabled."""

    client = CommandSender(backend)

    settings_set(
        device,
        navigator,
        {
            SettingID.SILENT_PUBKEY_EXPORT: SettingValue.ENABLED,
            SettingID.EXPERT_MODE: SettingValue.DISABLED,
        },
        backend=backend,
    )
    nav_ctx = NavContext(device, navigator, scenario_navigator)
    assert testCase.path is not None
    with client.get_pubkey_async(testCase.path):
        choice_approve(nav_ctx, test_name=testCase.name, confirm_text=r"^Export$")

    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS

    _check_pubkey_result(response.data, testCase)


@pytest.mark.parametrize("testCase", denyTestCases, ids=idTestFunc)
def test_pubkey_deny(backend: BackendInterface, testCase: PubKeyTestCase) -> None:
    """Check deny behavior for invalid public-key export inputs."""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    assert testCase.path is not None
    with pytest.raises(ExceptionRAPDU) as err:
        with client.get_pubkey_async(testCase.path):
            pass
    assert_expected_deny_and_app_alive(backend, err.value, StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED)


def _check_ragger_expect_pubkey(testCase: PubKeyTestCase, public_key: bytes, chain_code: bytes) -> None:
    if testCase.ragger_expect is None:
        pytest.fail(f"Missing ragger_expect for pubkey fixture {testCase.name!r}")
    assert public_key.hex() == testCase.ragger_expect.publicKeyHex
    assert chain_code.hex() == testCase.ragger_expect.chainCodeHex


def _check_pubkey_result(data: bytes, testCase: PubKeyTestCase) -> None:
    assert testCase.path is not None
    public_key, chain_code = unpack_get_pubkey_response(data)
    ref_pk, ref_chaincode = get_device_pubkey(testCase.path)
    assert public_key.hex() == ref_pk.hex()
    assert chain_code.hex() == ref_chaincode
    _check_ragger_expect_pubkey(testCase, public_key, chain_code)
