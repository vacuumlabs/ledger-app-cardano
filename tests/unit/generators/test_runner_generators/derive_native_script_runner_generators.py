# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0
import re
from pathlib import Path

from tests.unit.generators.common import (
    read_file_safe,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_NATIVE_SCRIPT_DIR

# ======================================================================
# Compiled Regex Patterns (module level for performance)
# ======================================================================

# Match .name = "..." patterns in fixture structs
_NAME_PATTERN = re.compile(r'\.name\s*=\s*"([^"]+)"')


def extract_native_script_fixture_names(header_file_path: Path) -> list[str]:
    """
    Extract test case names from native script fixtures header.


    Args:
        header_file_path: Path to test_derive_native_script_fixtures.h

    Returns:
        List of test case names in order
    """
    fixture_names = []

    header_content = read_file_safe(header_file_path)

    # Extract all test case names
    for match in _NAME_PATTERN.finditer(header_content):
        test_case_name = match.group(1)
        fixture_names.append(test_case_name)

    return fixture_names


def _build_test_file_header() -> str:
    """
    Build header section of test file.

    Returns:
        Header section as string
    """
    return """// Unit tests for native script hash derivation (auto-generated)

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "test_derive_native_script_fixtures.h"
#include "test_derive_native_script_common.h"
#include "apdu_finalization_check.h"

// ======================================================================
// Native Script Hash Derivation Tests (Auto-Generated)
// ======================================================================

"""


def _build_test_functions(fixture_names: list[str]) -> tuple[str, list[str]]:
    """
    Build individual test functions for each fixture.

    Mimics structure from test_derive_address.c

    Args:
        fixture_names: List of test case names from fixtures

    Returns:
        Tuple of (test functions as string, list of function names)
    """
    test_functions_lines = []
    test_function_names = []

    for test_case_index, test_case_name in enumerate(fixture_names):
        fixture_base = test_case_name
        prefix = "Native_script_"
        if fixture_base.startswith(prefix):
            fixture_base = fixture_base[len(prefix) :]
        test_case_name_sanitized = sanitize_c_identifier(fixture_base, uppercase=False)
        test_function_name = f"test_derive_native_script_{test_case_name_sanitized}_{test_case_index}"

        test_functions_lines.extend(
            [
                f"static void {test_function_name}(void **state) {{",
                "    (void) state;",
                f"    run_fixture(&NATIVE_SCRIPT_FIXTURES[{test_case_index}]);",
                "}",
                "",
            ]
        )

        test_function_names.append(test_function_name)

    return "\n".join(test_functions_lines), test_function_names


def _build_main_function(test_function_names: list[str]) -> str:
    """
    Build main() function with CMocka test array.

    Args:
        test_function_names: List of test function names

    Returns:
        Main function as string
    """
    main_lines = [
        "// ======================================================================",
        "// Main",
        "// ======================================================================",
        "",
        "int main(void) {",
        "    const struct CMUnitTest tests[] = {",
    ]

    # Add all test functions to cmocka test array
    for test_function_name in test_function_names:
        main_lines.append(f"        cmocka_unit_test({test_function_name}),")

    main_lines.extend(
        [
            "    };",
            "    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);",
            "}",
            "",
        ]
    )

    return "\n".join(main_lines)


def generate_native_script_test_runners() -> int:
    """
    Generate native script test runner C file from existing fixtures header.

    This generator reads the already-generated test_derive_native_script_fixtures.h
    and creates the corresponding test_derive_native_script.c runner file.
    """

    fixture_header_path = GENERATED_NATIVE_SCRIPT_DIR / "test_derive_native_script_fixtures.h"
    test_c_file = GENERATED_NATIVE_SCRIPT_DIR / "test_native_script.c"

    if not fixture_header_path.exists():
        raise FileNotFoundError(
            f"Fixtures header not found: {fixture_header_path}\n"
            "Generate fixtures first using fixture_generators/derive_native_script_generators.py"
        )

    # Extract fixture names from generated header
    print(f"Reading fixtures from: {fixture_header_path}")
    fixture_names = extract_native_script_fixture_names(fixture_header_path)

    print(f"Found {len(fixture_names)} test fixtures:")
    print()

    # Display fixture names for verification
    for fixture_index, fixture_name in enumerate(fixture_names):
        print(f"  [{fixture_index:2d}] {fixture_name}")

    print()
    print(f"Generating test runner C file: {test_c_file}")
    print()

    # Build complete test file

    header_section = _build_test_file_header()
    test_functions_section, test_function_names = _build_test_functions(fixture_names)
    main_section = _build_main_function(test_function_names)

    complete_file_content = header_section + test_functions_section + main_section

    # Write test file
    write_generated_c_file(test_c_file, complete_file_content)

    print(f"Generated {test_c_file}")
    print("  - Generated test function names:")
    for function_index, function_name in enumerate(test_function_names):
        print(f"      [{function_index:2d}] {function_name}")

    print(f"  - CMocka test array with {len(test_function_names)} tests")
    print()
    return len(test_function_names)
