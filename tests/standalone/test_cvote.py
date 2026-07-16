# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for CIP36 check
"""

import hashlib

import pytest
from ledgered.devices import Device
from ragger.backend import BackendInterface
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator
from ragger.navigator.navigation_scenario import NavigateWithScenario

from tests.application_client.command_builder import CLA, InsType, P1Type, P2Type
from tests.application_client.command_sender import CommandSender
from tests.application_client.response_unpacker import (
    unpack_sign_cip36_confirm_response,
)
from tests.application_client.status_words import StatusWord
from tests.standalone.input_files.cvote import (
    CVoteDenyTestCase,
    CVoteTestCase,
    cvoteDenyTestCases,
    cvoteTestCases,
)
from tests.standalone.utils import (
    NavContext,
    assert_expected_deny_and_app_alive,
    idTestFunc,
    review_approve,
    verify_signature,
)


@pytest.mark.parametrize("testCase", cvoteTestCases, ids=idTestFunc)
def test_cvote(
    device: Device,
    backend: BackendInterface,
    navigator: Navigator,
    scenario_navigator: NavigateWithScenario,
    testCase: CVoteTestCase,
) -> None:
    """Check CIP36 Vote"""
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Save the original votecast data before it gets consumed by the APDU builder
    original_votecast_data = bytes.fromhex(testCase.cVote.voteCastDataHex)

    # Send the INIT APDU
    _cvote_init(client, testCase)

    # Send the CONFIRM APDU (which includes witness path and triggers signing)
    nav_ctx = NavContext(device, navigator, scenario_navigator)
    votecast_hash, signature = _cvote_confirm(nav_ctx, client, testCase)

    # Verify the hash matches the expected Blake2b-256 hash of the votecast data
    expected_hash = hashlib.blake2b(original_votecast_data, digest_size=32).digest()
    assert votecast_hash == expected_hash, f"Hash mismatch: {votecast_hash.hex()} != {expected_hash.hex()}"

    # Check the signature validity
    # Note: The signature is over the hash, not the raw votecast data
    verify_signature(testCase.cVote.witnessPath, signature, votecast_hash)
    _check_ragger_expect_cvote(testCase, votecast_hash, signature)


def _check_ragger_expect_cvote(testCase: CVoteTestCase, votecast_hash: bytes, signature: bytes) -> None:
    if testCase.ragger_expect is None:
        pytest.fail(f"Missing ragger_expect for cvote fixture {testCase.name!r}")
    assert votecast_hash.hex() == testCase.ragger_expect.votecastHashHex, f"Vote cast hash mismatch for {testCase.name!r}"
    assert signature.hex() == testCase.ragger_expect.witnessSignatureHex, f"Witness signature mismatch for {testCase.name!r}"


def _cvote_init(client: CommandSender, testCase: CVoteTestCase) -> None:
    """cVOTE INIT

    Args:
        client (CommandSender): The command sender instance
        testCase (CVoteTestCase): The test case
    """
    with client.sign_cip36_init_async(testCase):
        pass

    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS

    if client.has_sign_cip36_chunks(testCase):
        # Send the CHUNK APDUs
        response = client.sign_cip36_chunk(testCase)
        # Check the status
        assert response and response.status == StatusWord.SWO_SUCCESS


def _cvote_confirm(nav_ctx: NavContext, client: CommandSender, testCase: CVoteTestCase) -> tuple[bytes, bytes]:
    """cVOTE CONFIRM and SIGN

    Args:
        nav_ctx (NavContext): Navigation context
        client (CommandSender): The command sender instance
        testCase (CVoteTestCase): The test case

    Return:
        tuple[bytes, bytes]: (votecast_hash, signature)
    """

    with client.sign_cip36_confirm_async(testCase):
        test_name = f"{testCase.name}/cvote_confirm"
        review_approve(
            nav_ctx,
            test_name=test_name,
            target_text="Sign vote",
            warnings=testCase.expected_warnings,
        )
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS
    votecast_hash, signature = unpack_sign_cip36_confirm_response(response.data)

    return votecast_hash, signature


@pytest.mark.parametrize("testCase", cvoteDenyTestCases, ids=idTestFunc)
def test_cvote_deny(backend: BackendInterface, testCase: CVoteDenyTestCase) -> None:
    """Check that invalid cvote inputs are denied with the expected status word."""

    if testCase.send_chunk_before_init:
        chunk_apdu = bytes([CLA, InsType.INS_SIGN_CVOTE, P1Type.P1_CVOTE_CHUNK, P2Type.P2_UNUSED, 0])
        with pytest.raises(ExceptionRAPDU) as err:
            backend.exchange_raw(chunk_apdu)
        assert_expected_deny_and_app_alive(backend, err.value, testCase.expected_swo)
        return

    if testCase.invalid_witness_path is not None:
        # Send a valid INIT using the first happy-path test case's votecast data,
        # then send a CONFIRM with the invalid witness path.
        valid_tc = cvoteTestCases[0]
        client = CommandSender(backend)
        _cvote_init(client, valid_tc)

        witness_path_bytes = pack_derivation_path(testCase.invalid_witness_path)
        confirm_apdu = (
            bytes(
                [
                    CLA,
                    InsType.INS_SIGN_CVOTE,
                    P1Type.P1_CVOTE_CONFIRM,
                    P2Type.P2_UNUSED,
                    len(witness_path_bytes),
                ]
            )
            + witness_path_bytes
        )
        with pytest.raises(ExceptionRAPDU) as err:
            backend.exchange_raw(confirm_apdu)
        assert_expected_deny_and_app_alive(backend, err.value, testCase.expected_swo)
        return

    # Malformed INIT payload.
    assert testCase.init_payload_hex is not None
    payload = bytes.fromhex(testCase.init_payload_hex)
    init_apdu = (
        bytes(
            [
                CLA,
                InsType.INS_SIGN_CVOTE,
                P1Type.P1_CVOTE_INIT,
                P2Type.P2_UNUSED,
                len(payload),
            ]
        )
        + payload
    )
    with pytest.raises(ExceptionRAPDU) as err:
        backend.exchange_raw(init_apdu)
    assert_expected_deny_and_app_alive(backend, err.value, testCase.expected_swo)
