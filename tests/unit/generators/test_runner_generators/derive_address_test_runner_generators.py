# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from tests.unit.generators.common import (
    extract_brace_delimited_entries,
    read_file_safe,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_DERIVE_ADDRESS_DIR

# ======================================================================
# Compiled Regex Patterns (module level for performance)
# ======================================================================

# Match fixture array declarations
_FIXTURE_ARRAY_PATTERN = re.compile(
    r"^static\s+const\s+derive_address_fixture_t\s+(DERIVE_ADDRESS_FIXTURES_[A-Z0-9_]+)\s*\[\]\s*=\s*\{",
    re.MULTILINE,
)

# ======================================================================
# Data Structures
# ======================================================================


@dataclass(frozen=True)
class FixtureDetails:
    """
    Complete details of a single fixture within an array.

    """

    name: str  # .name field (e.g., "Mainnet 1")
    data_array_name: str  # .data field (e.g., "DERIVE_ADDRESS_byronTestCases_000_MAINNET_1_APDU")
    check_expected: int  # .check_expected field (e.g., SWO_SUCCESS)
    index: int  # Position in array (0-based)


@dataclass(frozen=True)
class FixtureArrayDetails:
    """
    Complete information about a fixture array.

    """

    array_name: str  # C array identifier
    fixture_count: int  # Total number of fixtures
    fixtures: list[FixtureDetails]  # Individual fixture details


# ======================================================================
# Extraction Functions
# ======================================================================


def extract_fixture_array_names_from_header(fixture_header_path: Path) -> list[str]:
    """
    Extract all fixture array names from `test_derive_address_fixtures.h`.

    Looks for patterns like:
        static const derive_address_fixture_t DERIVE_ADDRESS_FIXTURES_TEST_DERIVE_ADDRESS_BYRON[] = {

    Args:
        fixture_header_path: Path to `test_derive_address_fixtures.h`

    Returns:
        List of fixture array names in declaration order

    """
    header_content = read_file_safe(fixture_header_path)

    fixture_array_names = []
    for match in _FIXTURE_ARRAY_PATTERN.finditer(header_content):
        array_name = match.group(1)

        # Validate that array name follows expected pattern
        if not array_name.startswith("DERIVE_ADDRESS_FIXTURES_"):
            raise ValueError(f"Unexpected array name format: {array_name}")

        fixture_array_names.append(array_name)

    if not fixture_array_names:
        raise ValueError(f"No fixture arrays found in {fixture_header_path}")

    return fixture_array_names


def extract_complete_fixture_details_from_array(header_content: str, array_name: str) -> list[FixtureDetails]:
    """
    Extract complete fixture details from a specific array.

    Extracts all fields from each fixture struct:
        {
            .name = "Mainnet 1",
            .p1 = P1_ADDRESS_RETURN,
            .data = DERIVE_ADDRESS_byronTestCases_000_MAINNET_1_APDU,
            .data_len = sizeof(DERIVE_ADDRESS_byronTestCases_000_MAINNET_1_APDU),
            .check_expected = SWO_SUCCESS,
        },

    Args:
        header_content: Full content of header file
        array_name: Name of array to extract from

    Returns:
        List of FixtureDetails with all fields

    """
    # Match entire array definition
    array_pattern = re.compile(
        rf"static\s+const\s+derive_address_fixture_t\s+{re.escape(array_name)}\s*\[\]\s*=\s*\{{(.*?)\}};",
        re.DOTALL,
    )

    match = array_pattern.search(header_content)
    if not match:
        raise ValueError(f"Array {array_name} not found in header")

    array_body = match.group(1)

    fixtures = []
    for index, struct_text in enumerate(extract_brace_delimited_entries(array_body)):
        struct_body = struct_text

        # Extract .name field
        name_match = re.search(r'\.name\s*=\s*"([^"]+)"', struct_body)
        if not name_match:
            raise ValueError(f"Missing .name field in fixture {index} of array {array_name}")
        fixture_name = name_match.group(1)

        # Extract .p1 field
        p1_match = re.search(r"\.p1\s*=\s*(P1_\w+|0x[0-9A-Fa-f]+|\d+)", struct_body)
        if not p1_match:
            raise ValueError(f"Missing .p1 field in fixture {index} of array {array_name}")
        # Extract .data field (the APDU array name)
        data_match = re.search(r"\.data\s*=\s*([A-Z0-9_]+)", struct_body)
        if not data_match:
            raise ValueError(f"Missing .data field in fixture {index} of array {array_name}")
        data_array_name = data_match.group(1)

        # Validate data array name format
        if not data_array_name.startswith("DERIVE_ADDRESS_"):
            raise ValueError(f"Unexpected data array name format in fixture {index}: {data_array_name}")

        # Extract .check_expected field
        check_match = re.search(r"\.check_expected\s*=\s*(SWO_\w+|0x[0-9A-Fa-f]+|\d+)", struct_body)
        if not check_match:
            raise ValueError(f"Missing .check_expected field in fixture {index} of array {array_name}")
        check_str = check_match.group(1)

        # Convert check_expected to integer
        if check_str == "SWO_SUCCESS":
            check_expected = 0x9000
        elif check_str == "SWO_SECURITY_CONDITION_NOT_SATISFIED":
            check_expected = 0x6982
        elif check_str.startswith("0x"):
            check_expected = int(check_str, 16)
        else:
            check_expected = int(check_str)

        fixtures.append(
            FixtureDetails(
                name=fixture_name,
                data_array_name=data_array_name,
                check_expected=check_expected,
                index=index,
            )
        )

    if not fixtures:
        raise ValueError(f"No fixtures found in array {array_name}")

    return fixtures


def extract_all_fixture_array_details(
    fixture_header_path: Path,
) -> list[FixtureArrayDetails]:
    """
    Extract complete information about all fixture arrays.

    Returns array name, count, and complete fixture details for each array.

    Returns:
        List of FixtureArrayDetails objects
    """
    header_content = read_file_safe(fixture_header_path)

    # Get all array names
    array_names = extract_fixture_array_names_from_header(fixture_header_path)

    all_array_details = []

    for array_name in array_names:
        # Extract complete fixture details
        fixtures = extract_complete_fixture_details_from_array(header_content, array_name)

        # Create complete array info
        array_details = FixtureArrayDetails(array_name=array_name, fixture_count=len(fixtures), fixtures=fixtures)

        all_array_details.append(array_details)

    return all_array_details


def _build_test_file_header() -> str:
    """
    Generate C file header with includes and helper functions.

    Matches structure of test_sign_tx_allegra.c with proper includes.
    """
    return """// Unit tests for address derivation (auto-generated)

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "test_derive_address_fixtures.h"
#include "apdu_finalization_check.h"

"""


def _build_main_function(all_fixture_array_details: Sequence[FixtureArrayDetails], test_c_file: str) -> str:

    all_test_function_names = []
    all_test_function_definitions = []

    for fixture_array_details in all_fixture_array_details:
        # Extract array suffix for unique function names
        # Example: DERIVE_ADDRESS_FIXTURES_TEST_DERIVE_ADDRESS_BYRON -> byron
        array_suffix = fixture_array_details.array_name.replace("DERIVE_ADDRESS_FIXTURES_TEST_DERIVE_ADDRESS_", "").lower()

        for fixture in fixture_array_details.fixtures:
            # Build unique test name for THIS fixture
            sanitized_fixture_name = sanitize_c_identifier(fixture.name, uppercase=False, handle_leading_digit=True)
            test_function_name = f"test_derive_address_{array_suffix}_{sanitized_fixture_name}_{fixture.index}"

            # Add to list of all test names
            # Using list accumulation ensures no test is accidentally dropped
            all_test_function_names.append(test_function_name)

            test_function_definition = (
                f"static void {test_function_name}(void **state) {{\n"
                f"    (void) state;\n"
                f"    run_fixture(&{fixture_array_details.array_name}[{fixture.index}]);\n"
                f"}}"
            )
            all_test_function_definitions.append(test_function_definition)

    # Generate cmocka test registrations
    # Pattern from test_sign_tx_*.c: cmocka_unit_test(test_name),
    test_registrations = ",\n        ".join(f"cmocka_unit_test({name})" for name in all_test_function_names)

    test_definitions_block = "\n\n".join(all_test_function_definitions)

    return (
        "// ======================================================================\n"
        "// Address Derivation Tests (Auto-Generated)\n"
        "// ======================================================================\n\n"
        f"{test_definitions_block}\n\n"
        "// ======================================================================\n"
        "// Main\n"
        "// ======================================================================\n\n"
        "int main(void) {\n"
        "    const struct CMUnitTest tests[] = {\n"
        f"        {test_registrations},\n"
        "    };\n"
        f'    return _cmocka_run_group_tests("{Path(test_c_file).stem}", '
        "tests, ARRAY_LEN(tests), NULL, assert_no_pending_apdu_response);\n"
        "}\n"
    )


def generate_address_derivation_test_runners() -> int:
    """
    Generate address derivation test runner files.

    """
    fixture_header_path = GENERATED_DERIVE_ADDRESS_DIR / "test_derive_address_fixtures.h"
    test_c_file = GENERATED_DERIVE_ADDRESS_DIR / "test_derive_address.c"

    # Example: Access specific fixture data
    all_fixture_array_details = extract_all_fixture_array_details(fixture_header_path)

    main_block = _build_main_function(all_fixture_array_details, test_c_file)

    complete_file = _build_test_file_header() + main_block

    total_tests = sum(len(details.fixtures) for details in all_fixture_array_details)
    write_generated_c_file(test_c_file, complete_file)
    print(f"Generated {test_c_file} test")
    return total_tests
