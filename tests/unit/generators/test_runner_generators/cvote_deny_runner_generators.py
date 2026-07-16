# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
Generator for the CIP-36 cvote deny test runner.

Reads the deny fixture names from the already-generated
test_cvote_fixtures_deny.h and emits a test_cvote_deny_tests.c
with static cmocka_unit_test() registrations (one per fixture) so
the coverage checker can detect them.
"""

import re
from pathlib import Path

from tests.unit.generators.common import (
    read_file_safe,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_CVOTE_DIR

_DENY_ARRAY_PATTERN = re.compile(
    r"static\s+const\s+cvote_deny_fixture_t\s+CVOTE_DENY_FIXTURES\[\]\s*=\s*\{(.*?)\n\};",
    re.DOTALL,
)
_NAME_PATTERN = re.compile(r'\.name\s*=\s*"([^"]+)"')


def _extract_deny_fixture_names(header_path: Path) -> list[str]:
    if not header_path.exists():
        raise FileNotFoundError(f"Fixture header not found: {header_path}")
    content = read_file_safe(header_path)
    array_match = _DENY_ARRAY_PATTERN.search(content)
    if not array_match:
        raise ValueError("CVOTE_DENY_FIXTURES array not found in header")
    names = _NAME_PATTERN.findall(array_match.group(1))
    if not names:
        raise ValueError("No deny fixtures found in header")
    return names


def _build_file_header() -> str:
    return """// Unit tests for Sign CVote deny tests (auto-generated)

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "test_cvote_fixtures_deny.h"
#include "test_cvote_common.h"
#include "apdu_finalization_check.h"

// ======================================================================
// CVote Deny Tests (Auto-Generated)
// ======================================================================

"""


def _build_test_functions(fixture_names: list[str]) -> tuple[str, list[str]]:
    lines: list[str] = []
    func_names: list[str] = []
    for idx, name in enumerate(fixture_names):
        sanitized = sanitize_c_identifier(name, uppercase=False, handle_leading_digit=True)
        func_name = f"test_cvote_deny_{idx}_{sanitized}"
        lines.append(f"static void {func_name}(void **state) {{")
        lines.append("    (void) state;")
        lines.append(f"    run_cvote_deny_fixture(&CVOTE_DENY_FIXTURES[{idx}]);")
        lines.append("}")
        lines.append("")
        func_names.append(func_name)
    return "\n".join(lines), func_names


def _build_main(func_names: list[str]) -> str:
    registrations = ",\n        ".join(f"cmocka_unit_test({n})" for n in func_names)
    return (
        "int main(void) {\n"
        "    const struct CMUnitTest tests[] = {\n"
        f"        {registrations},\n"
        "    };\n\n"
        "    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);\n"
        "}\n"
    )


def generate_cvote_deny_test_runners() -> int:
    fixture_header = GENERATED_CVOTE_DIR / "test_cvote_fixtures_deny.h"
    test_c_file = GENERATED_CVOTE_DIR / "test_cvote_deny_tests.c"

    fixture_names = _extract_deny_fixture_names(fixture_header)
    test_funcs, func_names = _build_test_functions(fixture_names)
    main = _build_main(func_names)

    content = (
        _build_file_header()
        + test_funcs
        + "\n"
        + "// ======================================================================\n"
        + "// Main\n"
        + "// ======================================================================\n"
        + "\n"
        + main
    )
    write_generated_c_file(test_c_file, content)
    print(f"Generated {test_c_file} ({len(fixture_names)} deny fixtures)")

    return len(fixture_names)
