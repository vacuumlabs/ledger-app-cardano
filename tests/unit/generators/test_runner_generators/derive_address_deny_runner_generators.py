# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

import re
from pathlib import Path

from tests.unit.generators.common import (
    read_file_safe,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_DERIVE_ADDRESS_DIR

_DENY_ARRAY_PATTERN = re.compile(
    r"static\s+const\s+derive_address_fixture_t\s+DERIVE_ADDRESS_DENY_FIXTURES\[\]\s*=\s*\{(.*?)\};",
    re.DOTALL,
)
_NAME_PATTERN = re.compile(r'\.name\s*=\s*"([^"]+)"')


def _extract_deny_fixture_names(header_path: Path) -> list[str]:
    if not header_path.exists():
        raise FileNotFoundError(f"Fixture header not found: {header_path}")

    header_content = read_file_safe(header_path)
    array_match = _DENY_ARRAY_PATTERN.search(header_content)
    if not array_match:
        raise ValueError("DERIVE_ADDRESS_DENY_FIXTURES array not found in header")

    fixture_names = _NAME_PATTERN.findall(array_match.group(1))

    if not fixture_names:
        raise ValueError("No deny fixtures found in header")

    return fixture_names


def _build_test_file_header() -> str:
    return """//
//
// Unit tests for address derivation deny tests (auto-generated)

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>

#include "globals.h"
#include "securityPolicy/securityPolicy.h"
#include "apdu/dispatcher.h"

#include <cmocka.h>
#include "handler/derive_address.h"
#include "hexUtils.h"
#include "app_context.h"

#include "blake2b.h"

#include "test_derive_address_fixtures_deny.h"
#include "test_fixture_types.h"
#include "apdu_finalization_check.h"
#include "io_capture.h"
#include "nbgl_mock.h"
#include "test_read_buffer_helpers.h"

// ----------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------

// ----------------------------------------------------------------------
// Fixture runner
// ----------------------------------------------------------------------

static void run_deny_fixture(const derive_address_fixture_t *fixture) {
    io_capture_reset();
    nbgl_mock_reset();

    test_read_buffer_t deny_fixture_buffer = make_test_read_buffer(fixture->data, fixture->data_len);
    TRACE_BUFFER(deny_fixture_buffer.sdk_buffer.ptr, deny_fixture_buffer.sdk_buffer.size);
    TRACE("Running deny fixture: %s", fixture->name);
    apdu_response_begin(INS_DERIVE_ADDRESS);
    handler_derive_address(&deny_fixture_buffer.sdk_buffer, fixture->p1);
    apdu_response_finalize_after_handler();
    assert_read_buffer_unchanged_and_cleanup(&deny_fixture_buffer, fixture->data);
    assert_int_equal(g_last_response_swo, fixture->check_expected);
}

"""


def _build_test_functions(fixture_names: list[str]) -> tuple[str, list[str]]:
    test_functions: list[str] = []
    test_function_names: list[str] = []

    for idx, fixture_name in enumerate(fixture_names):
        sanitized = sanitize_c_identifier(fixture_name, uppercase=False, handle_leading_digit=True)
        test_function_name = f"test_derive_address_deny_{idx}_{sanitized}"

        test_functions.append(
            f"static void {test_function_name}(void **state) {{\n"
            f"    (void) state;\n"
            f"    run_deny_fixture(&DERIVE_ADDRESS_DENY_FIXTURES[{idx}]);\n"
            f"}}\n"
        )
        test_function_names.append(test_function_name)

    return "\n".join(test_functions), test_function_names


def _build_main_function(test_function_names: list[str]) -> str:
    registrations = ",\n        ".join(f"cmocka_unit_test({name})" for name in test_function_names)

    return (
        "int main(void) {\n"
        '    TRACE("Starting test_derive_address_deny_tests");\n'
        "    const struct CMUnitTest tests[] = {\n"
        f"        {registrations},\n"
        "    };\n\n"
        "    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);\n"
        "}\n"
    )


def generate_address_derivation_deny_test_runners() -> int:
    fixture_header_path = GENERATED_DERIVE_ADDRESS_DIR / "test_derive_address_fixtures_deny.h"
    test_c_file = GENERATED_DERIVE_ADDRESS_DIR / "test_derive_address_deny_tests.c"

    fixture_names = _extract_deny_fixture_names(fixture_header_path)
    test_functions_section, test_function_names = _build_test_functions(fixture_names)
    main_section = _build_main_function(test_function_names)

    complete_file = _build_test_file_header() + test_functions_section + "\n" + main_section

    write_generated_c_file(test_c_file, complete_file)

    print(f"Generated {test_c_file}")
    return len(test_function_names)
