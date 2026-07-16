# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from typing import Any

from tests.unit.generators.common import (
    format_bytes_as_c_array,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_PUBKEY_DIR

FIXTURES_FILE = GENERATED_PUBKEY_DIR / "test_pubkey_fixtures.h"


@dataclass(frozen=True)
class PubKeyTestGroup:
    test_cases: list[Any]
    silent_export_enabled: bool
    expected_policy: str


# ==============================================================================
# Step 1: Load Test Cases from Ragger Tests
# ==============================================================================


def _load_public_key_test_cases() -> dict[str, PubKeyTestGroup]:
    """
    Load public key export test cases from ragger standalone tests.

    Returns:
        Dictionary mapping category names to PubKeyTestGroup metadata
    """

    from tests.standalone.input_files.pubkey import (  # type: ignore
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

    confirm_tests = (
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
        + testsMintKeys
    )

    categorized_test_cases: dict[str, PubKeyTestGroup] = {
        "test_pubkey_confirm": PubKeyTestGroup(
            test_cases=confirm_tests,
            silent_export_enabled=False,
            expected_policy="POLICY_SHOW",
        ),
        "test_pubkey_without_confirmation": PubKeyTestGroup(
            test_cases=testsSilentExport,
            silent_export_enabled=True,
            expected_policy="POLICY_HIDE",
        ),
        "test_pubkey_confirm_even_with_silent_export": PubKeyTestGroup(
            test_cases=testsSilentExportRareKeys,
            silent_export_enabled=True,
            expected_policy="POLICY_SHOW",
        ),
    }

    return categorized_test_cases


# ==============================================================================
# Step 2: Serialize Test Case to APDU Command
# ==============================================================================


def _serialize_pubkey_test_case_to_apdu(test_case: Any) -> bytes:
    """
    Serialize a pubkey test case into APDU payload bytes.

    The payload is a packed BIP44 path:
      [path_len (1B)] [index_0 (4B)] ... [index_n (4B)]

    Args:
        test_case: PubKeyTestCase object from ragger tests

    Returns:
        APDU payload bytes (no header)
    """
    path = test_case.path
    parts = path.split("/")[1:]
    data = bytearray()
    data.append(len(parts))
    for part in parts:
        hardened = part.endswith("'")
        value_str = part[:-1] if hardened else part
        value = int(value_str)
        if hardened:
            value |= 0x80000000
        data.extend(value.to_bytes(4, "big"))
    return bytes(data)


def _get_expected_response_bytes(test_case: Any) -> bytes:
    if test_case.unit_test_expect is None:
        raise ValueError(f"pubkey fixture {test_case.name!r} is missing unit_test_expect")

    return bytes.fromhex(test_case.unit_test_expect.publicKeyHex) + bytes.fromhex(test_case.unit_test_expect.chainCodeHex)


# ==============================================================================
# Step 4: Generate C Code for Fixtures
# ==============================================================================


def _generate_fixture_code_for_test_case(
    group_name: str,
    test_case: Any,
    test_number: int,
    expected_response: bytes,
) -> list[str]:
    """
    Generate C code for a single public key fixture.

    Args:
        group_name: The group name identifier
        test_case: PubKeyTestCase from ragger tests
        test_number: Sequential test number (0-based)
        expected_response: Expected public key and chain code bytes

    Returns:
        List of C code lines defining the test fixture
    """
    code_lines: list[str] = []

    code_lines.append("// ----------------------------------------------------------------------")
    code_lines.append(f"// Test group: {group_name}")
    code_lines.append(f"// Test {test_number}: {test_case.name}")
    code_lines.append(f"// Path: {test_case.path}")
    code_lines.append("// ----------------------------------------------------------------------")
    code_lines.append("")

    payload_bytes = _serialize_pubkey_test_case_to_apdu(test_case)

    safe_test_name = sanitize_c_identifier(test_case.name)

    code_lines.append(f"// Source: tests/standalone/input_files/pubkey.py > {test_case.name}")

    payload_array_name = f"PUBKEY_{group_name}_{test_number:03d}_{safe_test_name}_APDU"
    payload_array_code = format_bytes_as_c_array(
        payload_bytes,
        payload_array_name,
        bytes_per_line=16,
        return_as_list=True,
    )
    code_lines.extend(payload_array_code)
    code_lines.append("")

    public_key = expected_response[:32]
    chain_code = expected_response[32:]

    code_lines.append(f"// Public key (hex): {public_key.hex()}")
    code_lines.append(f"// Chain code (hex): {chain_code.hex()}")

    expected_array_name = f"PUBKEY_{group_name}_{test_number:03d}_{safe_test_name}_EXPECTED_RESPONSE"
    expected_array_code = format_bytes_as_c_array(
        expected_response,
        expected_array_name,
        bytes_per_line=16,
        return_as_list=True,
    )
    code_lines.extend(expected_array_code)
    code_lines.append("")

    return code_lines


# ==============================================================================
# Step 5: Build Complete C Header File
# ==============================================================================


def _build_fixtures_for_group(
    group_name: str,
    group: PubKeyTestGroup,
) -> list[str]:
    header_lines: list[str] = []
    for idx, test_case in enumerate(group.test_cases):
        expected_response = _get_expected_response_bytes(test_case)
        header_lines.extend(
            _generate_fixture_code_for_test_case(
                group_name,
                test_case,
                idx,
                expected_response,
            )
        )
    return header_lines


def generate_pubkey_fixtures() -> int:
    """Generate public key export test fixture headers.

    Returns:
        Total number of fixture entries generated.
    """
    categorized_test_cases = _load_public_key_test_cases()

    header_lines: list[str] = [
        "//",
        "// Generator: fixture_generators/pubkey_generators.py",
        "// Source: tests/standalone/input_files/pubkey.py",
        "//",
        "// To regenerate:",
        "//   cd tests/unit",
        "//   python3 generators/generate_unit_tests_from_ragger.py",
        "//",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <stdbool.h>",
        '#include "cardano_swo.h"',
        '#include "securityPolicy/securityPolicyType.h"',
        '#include "test_fixture_types.h"',
        "",
        "// ======================================================================",
        "// Public Key Export Test Fixtures",
        "// ======================================================================",
        "",
    ]

    total_fixtures = 0
    for group_name, group in categorized_test_cases.items():
        header_lines.extend(_build_fixtures_for_group(group_name, group))
        total_fixtures += len(group.test_cases)

    for group_name, group in categorized_test_cases.items():
        array_name = f"PUBKEY_FIXTURES_{group_name.upper()}"
        header_lines.append(f"static const pubkey_fixture_t {array_name}[] = {{")
        for idx, test_case in enumerate(group.test_cases):
            safe_test_name = sanitize_c_identifier(test_case.name)
            header_lines.append(f"// Source: tests/standalone/input_files/pubkey.py > {group_name} > {test_case.name}")
            header_lines.append("{")
            header_lines.append(f'    .name = "{test_case.name}",')
            header_lines.append(f"    .data = PUBKEY_{group_name}_{idx:03d}_{safe_test_name}_APDU,")
            header_lines.append(f"    .data_len = sizeof(PUBKEY_{group_name}_{idx:03d}_{safe_test_name}_APDU),")
            header_lines.append("    .check_expected = SWO_SUCCESS,")
            header_lines.append(f"    .expected_response = PUBKEY_{group_name}_{idx:03d}_{safe_test_name}_EXPECTED_RESPONSE,")
            header_lines.append(
                f"    .expected_response_len = sizeof(PUBKEY_{group_name}_{idx:03d}_{safe_test_name}_EXPECTED_RESPONSE),"
            )
            header_lines.append(f"    .silent_export_enabled = {'true' if group.silent_export_enabled else 'false'},")
            header_lines.append(f"    .expected_policy = {group.expected_policy},")
            header_lines.append("},")
        header_lines.append("};")
        header_lines.append("")

    content = "\n".join(header_lines) + "\n"
    write_generated_c_file(FIXTURES_FILE, content)
    print(f"Generated {FIXTURES_FILE}")
    return total_fixtures
