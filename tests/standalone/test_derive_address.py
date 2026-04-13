# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Derive Address check
"""

import pytest
from ragger.backend import BackendInterface
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.error import ExceptionRAPDU

from tests.application_client.status_words import StatusWord
from tests.application_client.command_sender import CommandSender
from tests.application_client.command_builder import P1Type
from tests.application_client.response_unpacker import unpack_derive_address_response

from tests.standalone.input_files.derive_address import DeriveAddressTestCase
from tests.standalone.input_files.derive_address import byronTestCases
from tests.standalone.input_files.derive_address import (
    shelleyTestCasesNoConfirm,
    shelleyTestCasesWithConfirm,
    denyTestCases,
)
from tests.standalone.utils import (
    idTestFunc,
    derive_address,
    assert_expected_deny_and_app_alive,
)


@pytest.mark.parametrize("mode", ["return", "display"], ids=["return", "display"])
@pytest.mark.parametrize(
    "testCase",
    byronTestCases + shelleyTestCasesNoConfirm + shelleyTestCasesWithConfirm,
    ids=idTestFunc,
)
def test_derive_address(
    backend: BackendInterface,
    scenario_navigator: NavigateWithScenario,
    testCase: DeriveAddressTestCase,
    mode: str,
) -> None:
    """Check Derive Address Return and Display (Byron and Shelley)"""

    client = CommandSender(backend)

    p1_type = (
        P1Type.P1_ADDRESS_RETURN if mode == "return" else P1Type.P1_ADDRESS_DISPLAY
    )

    # Shelley test cases without confirmation don't require UI interaction (return mode only)
    if testCase in shelleyTestCasesNoConfirm and mode == "return":
        address = client.derive_address(p1_type, testCase.params)
        assert address == derive_address(testCase)
        _check_ragger_expect_address(testCase, address)
        return

    # Byron and Shelley with confirmation require navigation
    test_name = f"{testCase.name}-{mode}"
    with client.derive_address_async(p1_type, testCase.params):
        scenario_navigator.address_review_approve(test_name=test_name)

    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS

    if mode == "return":
        address = unpack_derive_address_response(response.data)
        if testCase in byronTestCases:
            assert testCase.ragger_expect is not None
            assert address.hex() == testCase.ragger_expect.addressHex
        else:
            assert address == derive_address(testCase)
        _check_ragger_expect_address(testCase, address)


def _check_ragger_expect_address(
    testCase: DeriveAddressTestCase, address: bytes
) -> None:
    if testCase.ragger_expect is None:
        pytest.fail(
            f"Missing ragger_expect for derive_address fixture {testCase.name!r}"
        )
    assert address.hex() == testCase.ragger_expect.addressHex


@pytest.mark.parametrize("testCase", denyTestCases, ids=idTestFunc)
def test_derive_address_deny(
    backend: BackendInterface, testCase: DeriveAddressTestCase
) -> None:
    """Check deny behavior for invalid derive-address inputs."""

    client = CommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as err:
        with client.derive_address_async(testCase.p1, testCase.params):
            pass
    if testCase.expected_swo is None:
        pytest.fail(
            f"MISSING_EXPECTED_SWO [{testCase.name}] expected_swo must be set for deny fixtures"
        )
    assert_expected_deny_and_app_alive(backend, err.value, testCase.expected_swo)
