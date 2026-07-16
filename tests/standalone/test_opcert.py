# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Operational Certificate check
"""

import pytest
from ledgered.devices import Device
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator
from ragger.navigator.navigation_scenario import NavigateWithScenario

from tests.application_client.command_builder import CLA, InsType, P1Type, P2Type
from tests.application_client.command_sender import CommandSender
from tests.application_client.response_unpacker import unpack_sign_opcert_response
from tests.application_client.status_words import StatusWord
from tests.standalone.input_files.signOpCert import (
    OpCertDenyTestCase,
    OpCertTestCase,
    opCertDenyTestCases,
    opCertTestCases,
)
from tests.standalone.utils import (
    NavContext,
    assert_expected_deny_and_app_alive,
    idTestFunc,
    review_approve,
    verify_signature,
)


@pytest.mark.parametrize("testCase", opCertTestCases, ids=idTestFunc)
def test_opCert(
    device: Device,
    backend: BackendInterface,
    navigator: Navigator,
    scenario_navigator: NavigateWithScenario,
    testCase: OpCertTestCase,
) -> None:
    """Check Sign Operational Certificate"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    nav_ctx = NavContext(device, navigator, scenario_navigator)
    with client.sign_opcert_async(testCase):
        test_name = testCase.name
        review_approve(
            nav_ctx,
            test_name=test_name,
            target_text="Sign certificate",
            warnings=testCase.expected_warnings,
        )
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS

    signature = unpack_sign_opcert_response(response.data)

    msg = b""
    msg += bytes.fromhex(testCase.opCert.kesPublicKeyHex)
    msg += testCase.opCert.issueCounter.to_bytes(8, "big")
    msg += testCase.opCert.kesPeriod.to_bytes(8, "big")

    verify_signature(testCase.opCert.path, signature, msg)
    _check_ragger_expect_opcert(testCase, signature)


def _check_ragger_expect_opcert(testCase: OpCertTestCase, signature: bytes) -> None:
    if testCase.ragger_expect is None:
        pytest.fail(f"Missing ragger_expect for opcert fixture {testCase.name!r}")
    assert signature.hex() == testCase.ragger_expect.signatureHex, f"Signature mismatch for {testCase.name!r}"


@pytest.mark.parametrize("testCase", opCertDenyTestCases, ids=idTestFunc)
def test_opcert_deny(backend: BackendInterface, testCase: OpCertDenyTestCase) -> None:
    """Check that malformed opcert APDUs are denied with the expected status word."""
    apdu = bytes(
        [
            CLA,
            InsType.INS_SIGN_OPCERT,
            P1Type.P1_UNUSED,
            P2Type.P2_UNUSED,
            len(bytes.fromhex(testCase.payload_hex)),
        ]
    ) + bytes.fromhex(testCase.payload_hex)
    with pytest.raises(ExceptionRAPDU) as err:
        backend.exchange_raw(apdu)
    assert_expected_deny_and_app_alive(backend, err.value, testCase.expected_swo)
