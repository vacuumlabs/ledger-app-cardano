# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
Generator for the native-script deny test runner.

Reads the deny fixture names from the already-generated
test_derive_native_script_deny_fixtures.h and emits a
test_native_script_deny_tests.c that uses static cmocka_unit_test()
registrations (one per fixture) so the coverage checker can detect them.
"""

import re
from pathlib import Path

from tests.unit.generators.common import (
    read_file_safe,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_NATIVE_SCRIPT_DIR

_DENY_ARRAY_PATTERN = re.compile(
    r"static\s+const\s+native_script_test_case_t\s+NATIVE_SCRIPT_FIXTURES\[\]\s*=\s*\{(.*?)\n\};",
    re.DOTALL,
)
_NAME_PATTERN = re.compile(r'\.name\s*=\s*"([^"]+)"')


def _extract_deny_fixture_names(header_path: Path) -> list[str]:
    if not header_path.exists():
        raise FileNotFoundError(f"Fixture header not found: {header_path}")
    content = read_file_safe(header_path)
    array_match = _DENY_ARRAY_PATTERN.search(content)
    if not array_match:
        raise ValueError("NATIVE_SCRIPT_FIXTURES array not found in header")
    names = _NAME_PATTERN.findall(array_match.group(1))
    if not names:
        raise ValueError("No deny fixtures found in header")
    return names


def _build_file_preamble() -> str:
    # Preserve the full C logic from the original hand-written runner, but
    # replace the dynamic _cmocka_run_group_tests main with static registrations.
    return r"""// Unit tests for native script hash derivation - deny tests (auto-generated)

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <cmocka.h>

#include "globals.h"
#include "securityPolicy/securityPolicy.h"
#include "apdu/dispatcher.h"
#include "handler/derive_address.h"
#include "hexUtils.h"
#include "mock_crypto/crypto_mock_data.h"
#include "blake2b.h"
#include "mem.h"

#include "test_derive_native_script_deny_fixtures.h"
#include "deriveNativeScriptHash/deriveNativeScriptHash_types.h"
#include "handler/derive_native_script_hash.h"
#include "app_context.h"
#include "test_native_script_utils.h"
#include "nbgl_mock.h"
#include "apdu_finalization_check.h"
#include "test_read_buffer_helpers.h"

// ======================================================================
// Fixture runner (shared logic)
// ======================================================================

// Recursive fixture runner for deny tests
void run_recursive_fixture_deny(const native_script_t *script, uint16_t expected_response) {
    if (script == NULL) {
        TRACE("  NULL script!");
    } else {
        TRACE("Running script type: %d", script->type);
        switch (script->type) {
            case NATIVE_SCRIPT_TYPE_INVALID_HEREAFTER:
            case NATIVE_SCRIPT_TYPE_INVALID_BEFORE:
            case NATIVE_SCRIPT_TYPE_PUBKEY_DEVICE_OWNED:
            case NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY: {
                test_read_buffer_t native_script_simple_buffer = make_test_read_buffer(
                    script->impl.simple.apdu_payload,
                    script->impl.simple.apdu_payload_length
                );
                run_derive_native_script_apdu(&native_script_simple_buffer.sdk_buffer, P1_NATIVE_SCRIPT_ADD_SIMPLE);
                assert_read_buffer_unchanged_and_cleanup(
                    &native_script_simple_buffer,
                    script->impl.simple.apdu_payload
                );
                if (get_last_swo() != SWO_SUCCESS) {
                    assert_int_equal(get_last_swo(), expected_response);
                }
            } break;
            case NATIVE_SCRIPT_TYPE_ALL: {
                TRACE("  ALL");

                uint8_t apdu_buffer[64] = {0};
                size_t apdu_length = 0;
                build_complex_script_start_buffer(
                    apdu_buffer,
                    &apdu_length,
                    NATIVE_SCRIPT_ALL,
                    (uint32_t) script->impl.complex.params.all.scripts_count,
                    0  // required_count unused for ALL
                );

                buffer_t buf = {
                    .ptr = apdu_buffer,
                    .size = apdu_length,
                    .offset = 0,
                };

                run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
                if (get_last_swo() != SWO_SUCCESS) {
                    assert_int_equal(get_last_swo(), expected_response);
                }

                for (size_t i = 0; i < script->impl.complex.params.all.scripts_count; i++) {
                    run_recursive_fixture_deny(script->impl.complex.params.all.scripts[i],
                                          expected_response);
                }
                break;
            }
            case NATIVE_SCRIPT_TYPE_ANY: {
                TRACE("  ANY");

                uint8_t apdu_buffer[64] = {0};
                size_t apdu_length = 0;
                build_complex_script_start_buffer(
                    apdu_buffer,
                    &apdu_length,
                    NATIVE_SCRIPT_ANY,
                    (uint32_t) script->impl.complex.params.any.scripts_count,
                    0  // required_count unused for ANY
                );

                buffer_t buf = {
                    .ptr = apdu_buffer,
                    .size = apdu_length,
                    .offset = 0,
                };

                TRACE_BUFFER(buf.ptr, buf.size);
                run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
                if (get_last_swo() != SWO_SUCCESS) {
                    assert_int_equal(get_last_swo(), expected_response);
                }

                for (size_t i = 0; i < script->impl.complex.params.any.scripts_count; i++) {
                    run_recursive_fixture_deny(script->impl.complex.params.any.scripts[i],
                                          expected_response);
                }
                break;
            }
            case NATIVE_SCRIPT_TYPE_N_OF_K: {
                TRACE("  N_OF_K");

                uint8_t apdu_buffer[64] = {0};
                size_t apdu_length = 0;
                TRACE("    scripts_count=%u, required_count=%u",
                      script->impl.complex.params.n_of_k.scripts_count,
                      script->impl.complex.params.n_of_k.required_count);
                build_complex_script_start_buffer(
                    apdu_buffer,
                    &apdu_length,
                    NATIVE_SCRIPT_N_OF_K,
                    (uint32_t) script->impl.complex.params.n_of_k.scripts_count,
                    (uint32_t) script->impl.complex.params.n_of_k.required_count);

                buffer_t buf = {
                    .ptr = apdu_buffer,
                    .size = apdu_length,
                    .offset = 0,
                };

                run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
                if (get_last_swo() != SWO_SUCCESS) {
                    assert_int_equal(get_last_swo(), expected_response);
                }

                for (size_t i = 0; i < script->impl.complex.params.n_of_k.scripts_count; i++) {
                    run_recursive_fixture_deny(script->impl.complex.params.n_of_k.scripts[i],
                                          expected_response);
                }
                break;
            }
            default:
                TRACE("  Unknown script type!");
                assert_true(false);
        }
    }
}

static inline void run_fixture(const native_script_test_case_t *fixture) {
    reset_context();
    assert_true(test_mem_init());
    reset_response_buffer();
    nbgl_mock_reset();
    nbgl_mock_set_streaming_start_auto_complete(true, true);

    // Check not null
    TRACE("Running derive address fixture: %s", fixture->name);
    assert_true(fixture->root_script != NULL);

    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    TRACE("Expected response: 0x%04X", fixture->expected_response);
    // Send all scripts recursively
    run_recursive_fixture_deny(fixture->root_script, fixture->expected_response);

    // Send finish APDU if last operation succeeded
    if (get_last_swo() == SWO_SUCCESS){
        test_read_buffer_t native_script_finish_buffer = make_test_read_buffer(
            fixture->finish_apdu_payload,
            fixture->finish_apdu_payload_length
        );
        run_derive_native_script_apdu(&native_script_finish_buffer.sdk_buffer, P1_NATIVE_SCRIPT_FINISH);
        assert_read_buffer_unchanged_and_cleanup(
            &native_script_finish_buffer,
            fixture->finish_apdu_payload
        );
        assert_int_equal(get_last_swo(), fixture->expected_response);
    }
}

// ======================================================================
// Per-fixture test functions (auto-generated)
// ======================================================================

"""


def _build_test_functions(fixture_names: list[str]) -> tuple[str, list[str]]:
    lines: list[str] = []
    func_names: list[str] = []
    for idx, name in enumerate(fixture_names):
        sanitized = sanitize_c_identifier(name, uppercase=False, handle_leading_digit=True)
        func_name = f"test_derive_native_script_hash_deny_{idx}_{sanitized}"
        lines.append(f"static void {func_name}(void **state) {{")
        lines.append("    (void) state;")
        lines.append(f"    run_fixture(&NATIVE_SCRIPT_FIXTURES[{idx}]);")
        lines.append("}")
        lines.append("")
        func_names.append(func_name)
    return "\n".join(lines), func_names


def _build_main(func_names: list[str]) -> str:
    registrations = ",\n        ".join(f"cmocka_unit_test({n})" for n in func_names)
    return (
        "// ======================================================================\n"
        "// Main\n"
        "// ======================================================================\n"
        "\n"
        "int main(void) {\n"
        "    const struct CMUnitTest tests[] = {\n"
        f"        {registrations},\n"
        "    };\n\n"
        "    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);\n"
        "}\n"
    )


def generate_native_script_deny_test_runners() -> int:
    fixture_header = GENERATED_NATIVE_SCRIPT_DIR / "test_derive_native_script_deny_fixtures.h"
    test_c_file = GENERATED_NATIVE_SCRIPT_DIR / "test_native_script_deny_tests.c"

    fixture_names = _extract_deny_fixture_names(fixture_header)
    preamble = _build_file_preamble()
    test_funcs, func_names = _build_test_functions(fixture_names)
    main = _build_main(func_names)

    content = preamble + test_funcs + "\n" + main
    write_generated_c_file(test_c_file, content)
    print(f"Generated {test_c_file} ({len(fixture_names)} deny fixtures)")

    return len(fixture_names)
