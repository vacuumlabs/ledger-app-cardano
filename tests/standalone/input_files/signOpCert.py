# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Sign Operational Certificate
"""

from dataclasses import dataclass

from tests.application_client.command_builder import (
    OpCertExpectedResult,
    OpCertTestCase,
    OperationalCertificate,
)
from tests.application_client.security_warnings import WarningBit
from tests.application_client.status_words import StatusWord


@dataclass(kw_only=True, frozen=True)
class OpCertDenyTestCase:
    """Raw-payload deny test for parse_opcert() error paths.

    The payload is the APDU body bytes (no 5-byte header) that should cause
    parse_opcert() to return false and emit a specific SWO error code.
    Using raw hex rather than OpCertTestCase allows us to express truncated
    or otherwise malformed inputs that CommandBuilder.sign_opcert() cannot produce.
    """

    name: str
    payload_hex: str  # hex-encoded APDU body (no header)
    expected_swo: StatusWord


_KES_KEY = "3d24bc547388cf2403fd978fc3d3a93d1f39acf68a9c00e40512084dc05f2822"
_KES_PERIOD = "000000000000002f"  # 47 big-endian uint64
_ISSUE_COUNTER = "000000000000002a"  # 42 big-endian uint64
# m/1853'/1815'/0'/0'  encoded as: count=4, then each hardened index as 4B big-endian
_POOL_KEY_PATH = "04" + "8000073d" + "00000717" + "80000000" + "80000000"
_WRONG_CLASS_POOL_KEY_PATH = "05" + "8000073c" + "80000717" + "80000000" + "00000002" + "00000000"
_VALID_OPCERT = _KES_KEY + _KES_PERIOD + _ISSUE_COUNTER + _POOL_KEY_PATH

# pylint: disable=line-too-long
opCertDenyTestCases: list[OpCertDenyTestCase] = [
    OpCertDenyTestCase(
        name="opcert_deny_truncated_kes_key",
        # KES key is 32 bytes; send only 16 bytes
        payload_hex=_KES_KEY[:32],
        expected_swo=StatusWord.SWO_OPCERT_PARSING_FAIL_KES_KEY,
    ),
    OpCertDenyTestCase(
        name="opcert_deny_truncated_kes_period",
        # Full KES key present but KES period (8 bytes) is cut to 4
        payload_hex=_KES_KEY + _KES_PERIOD[:8],
        expected_swo=StatusWord.SWO_OPCERT_PARSING_FAIL_KES_PERIOD,
    ),
    OpCertDenyTestCase(
        name="opcert_deny_truncated_issue_counter",
        # KES key + period present but issue counter (8 bytes) is cut to 4
        payload_hex=_KES_KEY + _KES_PERIOD + _ISSUE_COUNTER[:8],
        expected_swo=StatusWord.SWO_OPCERT_PARSING_FAIL_ISSUE_COUNTER,
    ),
    OpCertDenyTestCase(
        name="opcert_deny_invalid_pool_key_path",
        # KES key + period + counter present; path count claims 5 elements but only 0 follow
        payload_hex=_KES_KEY + _KES_PERIOD + _ISSUE_COUNTER + "05",
        expected_swo=StatusWord.SWO_OPCERT_PARSING_FAIL_POOL_KEY_PATH,
    ),
    OpCertDenyTestCase(
        name="opcert_deny_wrong_pool_key_path_class",
        # Valid BIP44 path, but not a pool cold key path.
        payload_hex=_KES_KEY + _KES_PERIOD + _ISSUE_COUNTER + _WRONG_CLASS_POOL_KEY_PATH,
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    OpCertDenyTestCase(
        name="opcert_deny_trailing_bytes",
        # Fully valid opcert followed by one extra byte
        payload_hex=_VALID_OPCERT + "ff",
        expected_swo=StatusWord.SWO_INVALID_OPCERT_LENGTH,
    ),
    OpCertDenyTestCase(
        name="opcert_deny_oversized_payload",
        # Payload exceeds MAX_OPCERT_LENGTH (32+8+8+24 = 72 bytes); send 73 bytes.
        payload_hex="aa" * 73,
        expected_swo=StatusWord.SWO_INVALID_OPCERT_LENGTH,
    ),
]

# pylint: disable=line-too-long
opCertTestCases = [
    OpCertTestCase(
        name="Sign_opcert_should_correctly_sign_operational_certificate",
        opCert=OperationalCertificate(
            "3d24bc547388cf2403fd978fc3d3a93d1f39acf68a9c00e40512084dc05f2822",
            47,
            42,
            "m/1853'/1815'/0'/0'",
        ),
        unit_test_expect=OpCertExpectedResult(
            signatureHex="ce8d7cab55217ed17f1cceb8cb487dcbe6172fdb5794cc26f78c2f1d2495598e72beb6209f113562f9488ef6e81e3e8f758ea072c3cf9c17095868f2e9213f0a",
        ),
        ragger_expect=OpCertExpectedResult(
            signatureHex="8a950f72ab94e3b2ac4df1bbd82709827ec572256fe8257c82b367fade03a225e6698bbe25b38d35f8bfc3bf8f3205f59f3614961b11574e111caa28c976e906",
        ),
    ),
    OpCertTestCase(
        name="Sign_opcert_should_correctly_sign_operational_certificate_with_warning",  # New test case added for warning path (no ledgerjs equivalent)  # noqa: E501
        opCert=OperationalCertificate(
            "3d24bc547388cf2403fd978fc3d3a93d1f39acf68a9c00e40512084dc05f2822",
            47,
            42,
            "m/1853'/1815'/0'/1000001'",
        ),
        expected_warnings=[WarningBit.WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH],
        unit_test_expect=OpCertExpectedResult(
            signatureHex="9f926e85b8f8cd124c0977504fa5c06361beb26774f14628cd2913cf9baf8d9a5c2c55835fa8fab723e1a9d2d7ea23944bb96a811b7bb6cce4bfabb778fc9308",
        ),
        ragger_expect=OpCertExpectedResult(
            signatureHex="774ecc67b60fe90d92528526bafef24d675faac9051d805a182ceea1a5bb988d425665ba6df8cae0e2199470d62b9052ac7d743a04a2b8d2c6c80ca28a2ad900",
        ),
    ),
]
