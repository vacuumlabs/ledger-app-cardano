# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

import re
from dataclasses import dataclass
from pathlib import Path

from tests.unit.generators.common import (
    read_file_safe,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_PUBKEY_DIR

_FIXTURE_ARRAY_PATTERN = re.compile(
    r"^static\s+const\s+pubkey_fixture_t\s+(PUBKEY_FIXTURES_[A-Z0-9_]+)\s*\[\]\s*=\s*\{",
    re.MULTILINE,
)


@dataclass(frozen=True)
class FixtureDetails:
    name: str
    index: int


@dataclass(frozen=True)
class FixtureArrayDetails:
    array_name: str
    fixtures: list[FixtureDetails]


def _extract_fixture_array_names(header_content: str) -> list[str]:
    return [match.group(1) for match in _FIXTURE_ARRAY_PATTERN.finditer(header_content)]


def _extract_fixtures_for_array(header_content: str, array_name: str) -> list[FixtureDetails]:
    array_pattern = re.compile(
        rf"static\s+const\s+pubkey_fixture_t\s+{re.escape(array_name)}\s*\[\]\s*=\s*\{{(.*?)\}};",
        re.DOTALL,
    )
    match = array_pattern.search(header_content)
    if not match:
        raise ValueError(f"Array {array_name} not found in header")

    array_body = match.group(1)
    name_matches = re.findall(r'\.name\s*=\s*"([^"]+)"', array_body)
    if not name_matches:
        raise ValueError(f"No fixtures found in array {array_name}")

    return [FixtureDetails(name=name, index=i) for i, name in enumerate(name_matches)]


def _extract_all_fixture_arrays(fixture_header_path: Path) -> list[FixtureArrayDetails]:
    header_content = read_file_safe(fixture_header_path)
    array_names = _extract_fixture_array_names(header_content)

    if not array_names:
        raise ValueError(f"No fixture arrays found in {fixture_header_path}")

    arrays: list[FixtureArrayDetails] = []
    for array_name in array_names:
        fixtures = _extract_fixtures_for_array(header_content, array_name)
        arrays.append(FixtureArrayDetails(array_name=array_name, fixtures=fixtures))

    return arrays


def _build_test_file_header() -> str:
    return """// Unit tests for public key export (auto-generated)

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include \"test_pubkey_fixtures.h\"
#include \"test_pubkey_common.h\"
#include \"apdu_finalization_check.h\"

// ======================================================================
// Public Key Export Tests (Auto-Generated)
// ======================================================================

"""


def _build_test_functions(arrays: list[FixtureArrayDetails]) -> tuple[str, list[str]]:
    test_functions: list[str] = []
    test_function_names: list[str] = []

    for array in arrays:
        array_suffix = array.array_name.replace("PUBKEY_FIXTURES_TEST_PUBKEY_", "").lower()
        for fixture in array.fixtures:
            sanitized = sanitize_c_identifier(
                fixture.name,
                uppercase=False,
                handle_leading_digit=True,
            )
            test_function_name = f"test_pubkey_{array_suffix}_{sanitized}_{fixture.index}"
            test_functions.append(
                f"static void {test_function_name}(void **state) {{\n"
                f"    (void) state;\n"
                f"    run_fixture(&{array.array_name}[{fixture.index}]);\n"
                f"}}\n"
            )
            test_function_names.append(test_function_name)

    return "\n".join(test_functions), test_function_names


def _build_main_function(test_function_names: list[str]) -> str:
    registrations = ",\n        ".join(f"cmocka_unit_test({name})" for name in test_function_names)

    return (
        "int main(void) {\n"
        "    const struct CMUnitTest tests[] = {\n"
        f"        {registrations},\n"
        "    };\n"
        "    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);\n"
        "}\n"
    )


def generate_pubkey_test_runners() -> int:
    fixture_header_path = GENERATED_PUBKEY_DIR / "test_pubkey_fixtures.h"
    test_c_file = GENERATED_PUBKEY_DIR / "test_pubkey.c"

    arrays = _extract_all_fixture_arrays(fixture_header_path)
    test_functions_section, test_function_names = _build_test_functions(arrays)
    main_section = _build_main_function(test_function_names)

    complete_file = (
        _build_test_file_header()
        + test_functions_section
        + "\n"
        + "// ======================================================================\n"
        + "// Main\n"
        + "// ======================================================================\n"
        + "\n"
        + main_section
    )

    write_generated_c_file(test_c_file, complete_file)
    print(f"Generated {test_c_file}")
    return len(test_function_names)
