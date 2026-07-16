# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import re
from pathlib import Path

from tests.unit.generators.common import (
    read_file_safe,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_CVOTE_DIR

FIXTURE_HEADER = GENERATED_CVOTE_DIR / "test_cvote_fixtures.h"
TEST_FILE = GENERATED_CVOTE_DIR / "test_cvote.c"

_NAME_PATTERN = re.compile(r'\.name\s*=\s*"([^"]+)"')


def _extract_fixture_names(header: Path) -> list[str]:
    content = read_file_safe(header)
    # Only extract names from the CVOTE_FIXTURES array, not from chunk/init/confirm arrays
    array_match = re.search(
        r"static\s+const\s+cvote_fixture_t\s+CVOTE_FIXTURES\[\]\s*=\s*\{(.*?)\n\};",
        content,
        re.DOTALL,
    )
    if not array_match:
        raise ValueError("CVOTE_FIXTURES array not found in fixture header")
    return _NAME_PATTERN.findall(array_match.group(1))


def _build_file_header() -> str:
    return """// Unit tests for CIP-36 VoteCast signing (auto-generated)

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "test_cvote_fixtures.h"
#include "test_cvote_common.h"
#include "apdu_finalization_check.h"
#include "test_read_buffer_helpers.h"

// ======================================================================
// CIP-36 CVote Tests (Auto-Generated)
// ======================================================================

"""


def _build_test_functions(fixture_names: list[str]) -> tuple[str, list[str]]:
    lines = []
    function_names = []
    for idx, raw_name in enumerate(fixture_names):
        sanitized = sanitize_c_identifier(raw_name, uppercase=False, handle_leading_digit=True)
        if not sanitized:
            sanitized = f"fixture_{idx}"
        function_name = f"test_cvote_{sanitized}_{idx}"
        lines.extend(
            [
                f"static void {function_name}(void **state) {{",
                "    (void) state;",
                f"    run_cvote_fixture(&CVOTE_FIXTURES[{idx}]);",
                "}",
                "",
            ]
        )
        function_names.append(function_name)
    return "\n".join(lines), function_names


def _build_main(function_names: list[str]) -> str:
    lines = [
        "// ======================================================================",
        "// Main",
        "// ======================================================================",
        "",
        "int main(void) {",
        "    const struct CMUnitTest tests[] = {",
    ]
    for name in function_names:
        lines.append(f"        cmocka_unit_test({name}),")
    lines.extend(
        [
            "    };",
            "    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);",
            "}",
        ]
    )
    return "\n".join(lines)


def generate_cvote_test_runners() -> int:
    if not FIXTURE_HEADER.exists():
        raise FileNotFoundError("CVote fixtures missing. Run generate_unit_tests_from_ragger.py fixtures stage first.")

    fixture_names = _extract_fixture_names(FIXTURE_HEADER)
    if not fixture_names:
        raise RuntimeError("No cvote fixtures found")

    header = _build_file_header()
    test_funcs, func_names = _build_test_functions(fixture_names)
    main = _build_main(func_names)

    content = "\n".join([header, test_funcs, main, ""])
    write_generated_c_file(TEST_FILE, content)
    print(f"Written cvote test runner to {TEST_FILE}")
    return len(func_names)
