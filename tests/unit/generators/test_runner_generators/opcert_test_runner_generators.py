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
from tests.unit.generators.paths import GENERATED_OPCERT_DIR

FIXTURE_HEADER = GENERATED_OPCERT_DIR / "test_opcert_fixtures.h"
TEST_FILE = GENERATED_OPCERT_DIR / "test_opcert.c"

_NAME_PATTERN = re.compile(r'\.name\s*=\s*"([^"]+)"')


def _extract_fixture_names(header: Path) -> list[str]:
    content = read_file_safe(header)
    return _NAME_PATTERN.findall(content)


def _build_file_header() -> str:
    return """// Unit tests for Sign Operational Certificate (auto-generated)

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <setjmp.h>

#include <cmocka.h>

#include "cardano_constants.h"
#include "buffer.h"
#include "cardano_swo.h"
#include "globals.h"
#include "../src/securityPolicy/securityPolicy.h"
#include "handler/sign_opcert.h"
#include "opcert_parse.h"
#include "opcert/opcert_types.h"
#include "test_opcert_fixtures.h"
#include "app_context.h"
#include "apdu/dispatcher.h"
#include "mem.h"
#include "apdu_finalization_check.h"
#include "test_read_buffer_helpers.h"

"""


def _build_helpers() -> str:
    return """static uint16_t g_last_swo = 0;
static uint8_t g_last_response[ED25519_SIGNATURE_LENGTH];
static size_t g_last_response_len = 0;

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    assert_true(bufferLength <= sizeof(g_last_response));
    memcpy(g_last_response, buffer, bufferLength);
    g_last_response_len = bufferLength;
    g_last_swo = swo;
    return 0;
}

int io_send_sw(uint16_t swo) {
    g_last_swo = swo;
    return 0;
}

void reset_opcert_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    g_last_swo = 0;
    g_last_response_len = 0;
    mem_utils_init(test_heap, sizeof(test_heap));
}

static void run_opcert_fixture(const opcert_fixture_t *fixture) {
    assert_non_null(fixture);
    assert_non_null(fixture->payload);
    reset_opcert_context();

    parsed_opcert_t parsed = {0};
    buffer_t parsed_buffer = {
        .ptr = (uint8_t *) fixture->payload,
        .size = fixture->payload_len,
        .offset = 0,
    };
    assert_true(parse_opcert(&parsed_buffer, &parsed));
    warning_bits_t warnings = 0;
    security_policy_t policy = policyForSignOpCert(&parsed.poolColdKeyPath, &warnings);
    assert_int_not_equal(policy, POLICY_DENY);
    assert_int_equal(warnings, fixture->expected_warning_bits);

    test_read_buffer_t opcert_buffer = make_test_read_buffer(fixture->payload, fixture->payload_len);
    apdu_response_begin(INS_SIGN_OPCERT);
    handler_sign_opcert(&opcert_buffer.sdk_buffer);
    apdu_response_finalize_after_handler();
    assert_read_buffer_unchanged_and_cleanup(&opcert_buffer, fixture->payload);
    assert_int_equal(g_last_swo, SWO_SUCCESS);
    assert_int_equal(g_last_response_len, ED25519_SIGNATURE_LENGTH);
    if (fixture->expected_signature == NULL || fixture->expected_signature_len == 0) {
        fprintf(stderr, "UNIT_CAPTURE [%s] signatureHex=", fixture->name);
        for (size_t i = 0; i < g_last_response_len; i++) fprintf(stderr, "%02x", g_last_response[i]);
        fprintf(stderr, "\\n");
        fail_msg("Missing unit expected result for opcert fixture '%s'", fixture->name);
    }
    assert_int_equal(fixture->expected_signature_len, ED25519_SIGNATURE_LENGTH);
    assert_memory_equal(g_last_response, fixture->expected_signature, fixture->expected_signature_len);
}

"""


def _build_test_functions(fixture_names: list[str]) -> tuple[str, list[str]]:
    lines = []
    function_names = []
    for idx, raw_name in enumerate(fixture_names):
        sanitized = sanitize_c_identifier(raw_name, uppercase=False)
        prefix = "sign_opcert_"
        if sanitized.startswith(prefix):
            sanitized = sanitized[len(prefix) :]
        function_name = f"test_opCert_{sanitized}_{idx}"
        lines.extend(
            [
                f"static void {function_name}(void **state) {{",
                "    (void) state;",
                f"    run_opcert_fixture(&OPCERT_FIXTURES[{idx}]);",
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


def generate_opcert_test_runners() -> int:
    if not FIXTURE_HEADER.exists():
        raise FileNotFoundError("Opcert fixtures missing. Run generate_unit_tests_from_ragger.py fixtures stage first.")

    fixture_names = _extract_fixture_names(FIXTURE_HEADER)
    if not fixture_names:
        raise RuntimeError("No opcert fixtures found")

    header = _build_file_header()
    helpers = _build_helpers()
    test_funcs, func_names = _build_test_functions(fixture_names)
    main = _build_main(func_names)

    content = "\n".join([header, helpers, test_funcs, main, ""])
    write_generated_c_file(TEST_FILE, content)
    print(f"Written opcert test runner to {TEST_FILE}")
    return len(func_names)
