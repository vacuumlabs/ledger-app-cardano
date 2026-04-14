# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0
import re
from pathlib import Path


from tests.unit.generators.common import (
    read_file_safe,
    write_generated_c_file,
    sanitize_c_identifier,
)
from tests.unit.generators.paths import GENERATED_PUBKEY_DIR

_NAME_PATTERN = re.compile(r'\.name\s*=\s*"([^"]+)"')


def _extract_deny_fixture_names(header_path: Path, array_name: str) -> list[str]:
    if not header_path.exists():
        raise FileNotFoundError(f"Fixture header not found: {header_path}")

    header_content = read_file_safe(header_path)
    pattern = re.compile(
        rf"static\s+const\s+pubkey_fixture_t\s+{re.escape(array_name)}\[\]\s*=\s*\{{(.*?)\}};",
        re.DOTALL,
    )
    array_match = pattern.search(header_content)
    if not array_match:
        raise ValueError(f"{array_name} array not found in header")

    fixture_names = _NAME_PATTERN.findall(array_match.group(1))

    if not fixture_names:
        raise ValueError(f"No fixtures found in {array_name}")

    return fixture_names


def _build_test_file_header() -> str:
    return """// Unit tests for public key export deny tests (auto-generated)

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include \"test_pubkey_fixtures_deny.h\"
#include \"test_pubkey_common.h\"
#include \"apdu_finalization_check.h\"

// ======================================================================
// Public Key Export Deny Tests (Auto-Generated)
// ======================================================================

"""


def _build_test_functions(
    fixture_names: list[str], array_name: str, fn_prefix: str
) -> tuple[str, list[str]]:
    test_functions: list[str] = []
    test_function_names: list[str] = []

    for idx, fixture_name in enumerate(fixture_names):
        sanitized = sanitize_c_identifier(
            fixture_name, uppercase=False, handle_leading_digit=True
        )
        test_function_name = f"{fn_prefix}_{idx}_{sanitized}"

        test_functions.append(
            f"static void {test_function_name}(void **state) {{\n"
            f"    (void) state;\n"
            f"    run_fixture(&{array_name}[{idx}]);\n"
            f"}}\n"
        )
        test_function_names.append(test_function_name)

    return "\n".join(test_functions), test_function_names


def _build_main_function(test_function_names: list[str]) -> str:
    registrations = ",\n        ".join(
        f"cmocka_unit_test({name})" for name in test_function_names
    )

    return (
        "int main(void) {\n"
        "    const struct CMUnitTest tests[] = {\n"
        f"        {registrations},\n"
        "    };\n\n"
        "    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);\n"
        "}\n"
    )


def generate_pubkey_deny_test_runners() -> int:
    fixture_header_path = GENERATED_PUBKEY_DIR / "test_pubkey_fixtures_deny.h"
    test_c_file = GENERATED_PUBKEY_DIR / "test_pubkey_deny_tests.c"

    fixture_names = _extract_deny_fixture_names(
        fixture_header_path, "PUBKEY_DENY_FIXTURES"
    )
    test_functions_section, test_function_names = _build_test_functions(
        fixture_names, "PUBKEY_DENY_FIXTURES", "test_pubkey_deny"
    )

    silent_fixture_names = _extract_deny_fixture_names(
        fixture_header_path, "PUBKEY_DENY_SILENT_FIXTURES"
    )
    silent_test_functions_section, silent_test_function_names = _build_test_functions(
        silent_fixture_names, "PUBKEY_DENY_SILENT_FIXTURES", "test_pubkey_deny_silent"
    )

    all_function_names = test_function_names + silent_test_function_names
    main_section = _build_main_function(all_function_names)

    complete_file = (
        _build_test_file_header()
        + test_functions_section
        + "\n"
        + "// ======================================================================\n"
        + "// Silent export deny tests (same paths, silent_export_enabled = true)\n"
        + "// ======================================================================\n"
        + "\n"
        + silent_test_functions_section
        + "\n"
        + "// ======================================================================\n"
        + "// Main\n"
        + "// ======================================================================\n"
        + "\n"
        + main_section
    )

    write_generated_c_file(test_c_file, complete_file)
    print(f"Generated {test_c_file}")
    return len(all_function_names)
