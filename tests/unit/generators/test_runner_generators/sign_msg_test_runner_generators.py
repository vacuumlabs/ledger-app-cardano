# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0
import re

from tests.unit.generators.common import (
    read_file_safe,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_SIGN_MSG_DIR

_FIXTURE_ARRAY_PATTERN = re.compile(
    r"static\s+const\s+sign_msg_fixture_t\s+SIGN_MSG_FIXTURES\[\]\s*=\s*\{(.*?)\};",
    re.DOTALL,
)
_NAME_PATTERN = re.compile(r'\.name\s*=\s*"([^"]+)"')


def _extract_fixture_names(header_content: str) -> list[str]:
    match = _FIXTURE_ARRAY_PATTERN.search(header_content)
    if not match:
        raise ValueError("SIGN_MSG_FIXTURES array not found")
    body = match.group(1)
    names = _NAME_PATTERN.findall(body)
    return names


def _build_test_file_header() -> str:
    return """// Unit tests for message signing (auto-generated)

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "test_sign_msg_fixtures.h"
#include "test_sign_msg_common.h"
#include "apdu_finalization_check.h"

// ======================================================================
// CIP-8 Message Signing Tests (Auto-Generated)
// ======================================================================

"""


def _build_test_functions(names: list[str]) -> tuple[list[str], list[str]]:
    functions: list[str] = []
    registrations: list[str] = []

    for index, name in enumerate(names):
        sanitized = sanitize_c_identifier(name, uppercase=False, handle_leading_digit=True)
        if not sanitized:
            sanitized = f"fixture_{index}"
        test_function_name = f"test_sign_message_{sanitized}_{index}"
        functions.append(
            f"static void {test_function_name}(void **state) {{\n"
            f"    (void) state;\n"
            f"    run_fixture(&SIGN_MSG_FIXTURES[{index}]);\n"
            f"}}\n"
        )
        registrations.append(test_function_name)

    return functions, registrations


def _build_main_function(test_names: list[str]) -> str:
    registrations = ",\n        ".join(f"cmocka_unit_test({name})" for name in test_names)
    return (
        "// ======================================================================\n"
        "// Main\n"
        "// ======================================================================\n\n"
        "int main(void) {\n"
        "    const struct CMUnitTest tests[] = {\n"
        f"        {registrations},\n"
        "    };\n"
        "    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);\n"
        "}\n"
    )


def generate_sign_msg_test_runners() -> int:
    fixture_header = GENERATED_SIGN_MSG_DIR / "test_sign_msg_fixtures.h"
    test_c_file = GENERATED_SIGN_MSG_DIR / "test_sign_msg.c"

    header_content = read_file_safe(fixture_header)
    fixture_names = _extract_fixture_names(header_content)
    if not fixture_names:
        raise ValueError("No sign message fixtures found")

    test_sections, test_names = _build_test_functions(fixture_names)
    main_section = _build_main_function(test_names)

    complete_file = _build_test_file_header() + "\n".join(test_sections) + "\n" + main_section

    write_generated_c_file(test_c_file, complete_file)
    print(f"Generated {test_c_file}")
    return len(test_names)
