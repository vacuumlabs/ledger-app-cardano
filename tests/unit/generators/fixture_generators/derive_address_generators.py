# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from typing import Any

from tests.unit.generators.common import (
    _ensure_base58_module,
    extract_apdu_payload,
    format_bytes_as_c_array,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_DERIVE_ADDRESS_DIR

FIXTURES_FILE = GENERATED_DERIVE_ADDRESS_DIR / "test_derive_address_fixtures.h"

# ==============================================================================
# Step 1: Load Test Cases from Ragger Tests
# ==============================================================================


@dataclass(frozen=True)
class TestCaseCategory:
    p1_value: str
    type: str
    test_cases: list[Any]


def _load_address_derivation_test_cases() -> tuple[dict[str, list[Any]], dict[str, TestCaseCategory]]:
    """
    Load address derivation test cases from ragger standalone tests.

    These test cases verify that the device properly handles address
    derivation requests.

    """
    _ensure_base58_module()

    # Import  test cases from ragger standalone input files
    from tests.standalone.input_files.derive_address import (  # type: ignore
        byronTestCases,
        shelleyTestCasesNoConfirm,
        shelleyTestCasesWithConfirm,
    )

    all_test_cases = {
        "byronTestCases": byronTestCases,
        "shelleyTestCasesNoConfirm": shelleyTestCasesNoConfirm,
        "shelleyTestCasesWithConfirm": shelleyTestCasesWithConfirm,
    }
    categorized_test_cases = {
        # Byron addresses with P1_ADDRESS_RETURN (no user confirmation required)
        "test_derive_address_byron": TestCaseCategory(
            p1_value="P1_ADDRESS_RETURN",
            type="byronTestCases",
            test_cases=byronTestCases,
        ),
        "test_derive_address_byron_show": TestCaseCategory(
            p1_value="P1_ADDRESS_DISPLAY",
            type="byronTestCases",
            test_cases=byronTestCases,
        ),
        "test_derive_address_shelley": TestCaseCategory(
            p1_value="P1_ADDRESS_RETURN",
            type="shelleyTestCasesNoConfirm",
            test_cases=shelleyTestCasesNoConfirm,
        ),
        "test_derive_address_shelley_confirm": TestCaseCategory(
            p1_value="P1_ADDRESS_RETURN",
            type="shelleyTestCasesWithConfirm",
            test_cases=shelleyTestCasesWithConfirm,
        ),
        "test_derive_address_shelley_show_no_confirm": TestCaseCategory(
            p1_value="P1_ADDRESS_DISPLAY",
            type="shelleyTestCasesNoConfirm",
            test_cases=shelleyTestCasesNoConfirm,
        ),
        "test_derive_address_shelley_show_with_confirm": TestCaseCategory(
            p1_value="P1_ADDRESS_DISPLAY",
            type="shelleyTestCasesWithConfirm",
            test_cases=shelleyTestCasesWithConfirm,
        ),
    }
    return all_test_cases, categorized_test_cases


# ==============================================================================
# Step 2: Serialize Test Case to APDU Command
# ==============================================================================


def _serialize_test_case_to_apdu(test_case: Any) -> bytes:
    """
    Serialize a  test case into APDU command bytes.

    Uses CommandBuilder.derive_address() to serialize the test case with the
    same logic used by ragger tests.

    Args:
        test_case: DeriveAddressTestCase object from ragger tests

    Returns:
        Complete APDU command bytes (including header)

    Note:
        P1 parameter doesn't matter since we only need the payload.
    """
    from tests.application_client.command_builder import CommandBuilder, P1Type  # type: ignore

    command_builder = CommandBuilder()

    complete_apdu_command = command_builder.derive_address(
        P1Type.P1_ADDRESS_RETURN,  # P1 value doesn't matter for payload serialization
        test_case.params,
    )

    return complete_apdu_command


# ==============================================================================
# Step 3: Generate C Code for Fixtures
# ==============================================================================


def _generate_fixture_code_for_test_case(
    type_test: str,
    test_case: Any,
    test_number: int,
) -> list[str]:
    """
    Generate C code for a single address derivation test fixture.

    Args:
        test_case: DeriveAddressTestCase from ragger tests
        test_number: Sequential test number (0-based)

    Returns:
        List of C code lines defining the test fixture
    """
    code_lines = []

    # Add descriptive comment header
    code_lines.append("// ----------------------------------------------------------------------")
    code_lines.append(f"// Test type: {type_test}")
    code_lines.append(f"// Test {test_number}: {test_case.name}")
    code_lines.append(f"// Address Type: {test_case.params.addrType.name}")
    code_lines.append(f"// Spending: {test_case.params.spendingValue}")
    if test_case.params.stakingValue:
        code_lines.append(f"// Staking: {test_case.params.stakingValue}")
    code_lines.append("// ----------------------------------------------------------------------")
    code_lines.append("")

    # Serialize test case to APDU command using CommandBuilder
    apdu_command_bytes = _serialize_test_case_to_apdu(test_case)

    # Extract just the payload (skip the 5-byte APDU header: CLA, INS, P1, P2, Lc)
    payload_bytes = extract_apdu_payload(apdu_command_bytes)

    # Generate safe C identifier from test name
    safe_test_name = sanitize_c_identifier(test_case.name)

    # Add source traceability comment
    code_lines.append(f"// Source: tests/standalone/input_files/derive_address.py > {test_case.name}")

    # Generate C array for complete APDU command
    payload_array_name = f"DERIVE_ADDRESS_{type_test}_{test_number:03d}_{safe_test_name}_APDU"
    payload_array_code = format_bytes_as_c_array(
        payload_bytes,
        payload_array_name,
        bytes_per_line=16,
        return_as_list=True,
    )
    code_lines.extend(payload_array_code)
    code_lines.append("")

    expected = getattr(test_case, "unit_test_expect", None)
    expected_hex = getattr(expected, "addressHex", None)
    if expected_hex is None or expected_hex == "":
        raise ValueError(f"derive_address fixture {test_case.name!r} is missing unit_test_expect.addressHex")

    expected_bytes = bytes.fromhex(expected_hex)
    expected_array_name = f"DERIVE_ADDRESS_{type_test}_{test_number:03d}_{safe_test_name}_EXPECTED_ADDRESS"
    expected_array_code = format_bytes_as_c_array(
        expected_bytes,
        expected_array_name,
        bytes_per_line=16,
        return_as_list=True,
    )
    code_lines.extend(expected_array_code)
    code_lines.append("")

    return code_lines


# ==============================================================================
# Step 4: Build Complete C Header File
# ==============================================================================


def _build_fixtures() -> str:
    """
    Generate complete C file content for address derivation fixtures.

    Returns:
        Complete C file content as string
    """
    # Load test cases from ragger tests
    all_test_cases, categorized_test_cases = _load_address_derivation_test_cases()

    print(f"Generating fixtures for {len(categorized_test_cases)} categories of test cases...")
    print()

    # Start building header content
    header_lines = [
        "//",
        "// Generator: fixture_generators/derive_address_generators.py",
        "// Source: tests/standalone/input_files/derive_address.py",
        "//",
        "// To regenerate:",
        "//   cd tests/unit",
        "//   python3 generators/generate_unit_tests_from_ragger.py",
        "//",
        "// Each fixture includes source traceability comments showing:",
        "//   - Source file and category",
        "//   - Original Ragger test name",
        "//",
        f"// Total categories: {len(categorized_test_cases)}",
        "",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        '#include "test_fixture_types.h"',
        '#include "cardano_swo.h"',
        '#include "test_derive_address_common.h"',
        "",
        "// ======================================================================",
        "// Address Derivation Test Fixtures",
        "// ======================================================================",
        "",
        "",
    ]

    total_fixtures = sum(len(t) for t in all_test_cases.values())

    # Generate fixture data for each test case
    for type_test, tests in all_test_cases.items():
        print(f"Processing type: {type_test} with {len(tests)} test cases")
        for test_number, test_case in enumerate(tests):
            print(f"  [{test_number}/{len(tests)}] {test_case.name}")

            fixture_code = _generate_fixture_code_for_test_case(
                type_test,
                test_case,
                test_number,
            )
            header_lines.extend(fixture_code)

    # For each category, generate fixture arrays
    for category_name, category in categorized_test_cases.items():
        test_cases = category.test_cases

        header_lines.append(f"static const derive_address_fixture_t DERIVE_ADDRESS_FIXTURES_{category_name.upper()}[] = {{")

        for test_number, test_case in enumerate(test_cases):
            # Generate fixture struct
            # Extract just the payload (skip the 5-byte APDU header: CLA, INS, P1, P2, Lc)
            safe_test_name = sanitize_c_identifier(test_case.name)

            payload_array_name = f"DERIVE_ADDRESS_{category.type}_{test_number:03d}_{safe_test_name}_APDU"
            # Add source traceability comment
            header_lines.append(f"// Source: tests/standalone/input_files/derive_address.py > {category_name} > {test_case.name}")
            header_lines.append("{")

            header_lines.append(f'    .name = "{test_case.name}",')
            header_lines.append(f"    .p1 = {category.p1_value},")
            header_lines.append(f"    .data = {payload_array_name},")
            header_lines.append(f"    .data_len = sizeof({payload_array_name}),")
            header_lines.append("    .check_expected = SWO_SUCCESS,")
            expected = getattr(test_case, "unit_test_expect", None)
            expected_hex = getattr(expected, "addressHex", None)
            if expected_hex:
                expected_array_name = f"DERIVE_ADDRESS_{category.type}_{test_number:03d}_{safe_test_name}_EXPECTED_ADDRESS"
                header_lines.append(f"    .expected_address = {expected_array_name},")
                header_lines.append(f"    .expected_address_len = sizeof({expected_array_name}),")
            else:
                header_lines.append("    .expected_address = NULL,")
                header_lines.append("    .expected_address_len = 0,")
            header_lines.append("},")

        header_lines.append("};")
        header_lines.append("")

    return "\n".join(header_lines), total_fixtures


# ==============================================================================
# Step 5: Main Entry Point
# ==============================================================================


def generate_address_derivation_fixtures() -> None:
    """
    Generate address derivation test fixture header.

    This is the main entry point called from generate_unit_tests_from_ragger.py.
    Creates a single header file with all test fixtures.

    Returns:
        The total number of generated fixtures.
    """

    # Build header file content
    content, total_fixtures = _build_fixtures()
    write_generated_c_file(FIXTURES_FILE, content)
    print(f"Generated {FIXTURES_FILE}")
    return total_fixtures
