# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0


from tests.unit.generators.common import (
    extract_apdu_payload,
    format_bytes_as_c_array,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_SIGN_MSG_DIR


def _load_sign_msg_deny_test_cases() -> list:
    from tests.standalone.input_files.signMsg import signMsgDenyTestCases  # type: ignore

    return signMsgDenyTestCases


def _build_file_header() -> str:
    return """// Unit tests for CIP-8 Message Signing deny cases (auto-generated)

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "test_sign_msg_common.h"
#include "apdu_finalization_check.h"
#include "test_read_buffer_helpers.h"

// ======================================================================
// CIP-8 Message Signing Deny Tests (Auto-Generated)
// ======================================================================

"""


def _build_deny_helpers() -> list[str]:
    return [
        "// ======================================================================",
        "// Deny Test Helpers",
        "// ======================================================================",
        "",
        "static void run_deny_init_fixture(const uint8_t *init_data, size_t init_data_len, uint16_t expected_swo) {",
        "    reset_sign_msg_test_state();",
        "    test_read_buffer_t init_buffer = make_test_read_buffer(init_data, init_data_len);",
        "    apdu_response_begin(INS_SIGN_MSG);",
        "    handler_sign_msg(&init_buffer.sdk_buffer, P1_SIGN_MSG_INIT);",
        "    apdu_response_finalize_after_handler();",
        "    assert_read_buffer_unchanged_and_cleanup(&init_buffer, init_data);",
        "    assert_int_equal(g_last_response_swo, expected_swo);",
        "}",
        "",
        "static void run_deny_chunk_fixture(const uint8_t *chunk_data, size_t chunk_data_len, uint16_t expected_swo) {",
        "    test_read_buffer_t chunk_buffer = make_test_read_buffer(chunk_data, chunk_data_len);",
        "    apdu_response_begin(INS_SIGN_MSG);",
        "    handler_sign_msg(&chunk_buffer.sdk_buffer, P1_SIGN_MSG_CHUNK);",
        "    apdu_response_finalize_after_handler();",
        "    assert_read_buffer_unchanged_and_cleanup(&chunk_buffer, chunk_data);",
        "    assert_int_equal(g_last_response_swo, expected_swo);",
        "}",
        "",
        "static void run_deny_confirm_fixture(const uint8_t *confirm_data, size_t confirm_data_len, uint16_t expected_swo) {",
        "    test_read_buffer_t confirm_buffer = make_test_read_buffer(confirm_data, confirm_data_len);",
        "    apdu_response_begin(INS_SIGN_MSG);",
        "    handler_sign_msg(&confirm_buffer.sdk_buffer, P1_SIGN_MSG_CONFIRM);",
        "    apdu_response_finalize_after_handler();",
        "    assert_read_buffer_unchanged_and_cleanup(&confirm_buffer, confirm_data);",
        "    assert_int_equal(g_last_response_swo, expected_swo);",
        "}",
        "",
        "// ======================================================================",
        "// Deny Test Fixtures",
        "// ======================================================================",
        "",
    ]


def _build_deny_test_functions() -> tuple[list[str], list[str]]:
    from tests.application_client.command_builder import CommandBuilder  # type: ignore
    from tests.standalone.input_files.signMsg import (  # type: ignore
        SignMsgTestCase,
        build_sign_msg_chunk_apdu_for_deny,
        build_sign_msg_confirm_apdu_for_deny,
        build_sign_msg_init_apdu_for_deny,
    )

    deny_test_cases = _load_sign_msg_deny_test_cases()
    if len(deny_test_cases) == 0:
        return [], []

    body_lines: list[str] = []
    registrations: list[str] = []

    for index, test_case in enumerate(deny_test_cases):
        safe_test_name = sanitize_c_identifier(test_case.name, uppercase=True)
        test_function_name = (
            f"test_sign_message_deny_{sanitize_c_identifier(test_case.name, uppercase=False, handle_leading_digit=True)}_{index}"
        )

        if test_case.send_confirm_without_init:
            # Send CONFIRM with no prior INIT (req_type mismatch)
            confirm_array_name = f"SIGN_MSG_DENY_{index:03d}_{safe_test_name}_CONFIRM_APDU"
            confirm_payload = extract_apdu_payload(build_sign_msg_confirm_apdu_for_deny(test_case))
            body_lines.extend(
                format_bytes_as_c_array(
                    confirm_payload,
                    confirm_array_name,
                    bytes_per_line=16,
                    return_as_list=True,
                )
            )
            body_lines.append("")
            body_lines.append(f"static void {test_function_name}(void **state) {{")
            body_lines.append("    (void) state;")
            body_lines.append("    reset_sign_msg_test_state();")
            confirm_size = "0" if len(confirm_payload) == 0 else f"sizeof({confirm_array_name})"
            body_lines.append(
                f"    run_deny_confirm_fixture({confirm_array_name}, {confirm_size}, {test_case.expected_swo.name});"
            )
            body_lines.append("}")
            body_lines.append("")

        elif test_case.send_chunk_when_in_confirm:
            # Send INIT+all CHUNKs (reaching CONFIRM state), then send extra CHUNK
            init_array_name = f"SIGN_MSG_DENY_{index:03d}_{safe_test_name}_INIT_APDU"
            chunk_array_name = f"SIGN_MSG_DENY_{index:03d}_{safe_test_name}_CHUNK_APDU"
            body_lines.extend(
                format_bytes_as_c_array(
                    extract_apdu_payload(build_sign_msg_init_apdu_for_deny(test_case)),
                    init_array_name,
                    bytes_per_line=16,
                    return_as_list=True,
                )
            )
            body_lines.append("")
            body_lines.extend(
                format_bytes_as_c_array(
                    extract_apdu_payload(build_sign_msg_chunk_apdu_for_deny(test_case, 0)),
                    chunk_array_name,
                    bytes_per_line=16,
                    return_as_list=True,
                )
            )
            body_lines.append("")
            body_lines.append(f"static void {test_function_name}(void **state) {{")
            body_lines.append("    (void) state;")
            body_lines.append("    reset_sign_msg_test_state();")
            body_lines.append("    // Send INIT successfully")
            body_lines.append(f"    run_deny_init_fixture({init_array_name}, sizeof({init_array_name}), SWO_SUCCESS);")
            body_lines.append("    // Send CHUNK successfully (transitions to CONFIRM state)")
            body_lines.append(f"    run_deny_chunk_fixture({chunk_array_name}, sizeof({chunk_array_name}), SWO_SUCCESS);")
            body_lines.append("    // Send extra CHUNK while already in CONFIRM state")
            body_lines.append(
                f"    run_deny_chunk_fixture({chunk_array_name}, sizeof({chunk_array_name}), {test_case.expected_swo.name});"
            )
            body_lines.append("}")
            body_lines.append("")

        elif test_case.send_chunk_without_init:
            # Send CHUNK without INIT
            chunk_array_name = f"SIGN_MSG_DENY_{index:03d}_{safe_test_name}_CHUNK_APDU"
            body_lines.extend(
                format_bytes_as_c_array(
                    extract_apdu_payload(build_sign_msg_chunk_apdu_for_deny(test_case, 0)),
                    chunk_array_name,
                    bytes_per_line=16,
                    return_as_list=True,
                )
            )
            body_lines.append("")
            body_lines.append(f"static void {test_function_name}(void **state) {{")
            body_lines.append("    (void) state;")
            body_lines.append("    reset_sign_msg_test_state();")
            body_lines.append(
                f"    run_deny_chunk_fixture({chunk_array_name}, sizeof({chunk_array_name}), {test_case.expected_swo.name});"
            )
            body_lines.append("}")
            body_lines.append("")

        elif test_case.send_confirm_without_chunks:
            # Send INIT then CONFIRM (skip CHUNK phase)
            init_array_name = f"SIGN_MSG_DENY_{index:03d}_{safe_test_name}_INIT_APDU"
            confirm_array_name = f"SIGN_MSG_DENY_{index:03d}_{safe_test_name}_CONFIRM_APDU"
            body_lines.extend(
                format_bytes_as_c_array(
                    extract_apdu_payload(build_sign_msg_init_apdu_for_deny(test_case)),
                    init_array_name,
                    bytes_per_line=16,
                    return_as_list=True,
                )
            )
            body_lines.append("")
            confirm_payload = extract_apdu_payload(build_sign_msg_confirm_apdu_for_deny(test_case))
            body_lines.extend(
                format_bytes_as_c_array(
                    confirm_payload,
                    confirm_array_name,
                    bytes_per_line=16,
                    return_as_list=True,
                )
            )
            body_lines.append("")
            body_lines.append(f"static void {test_function_name}(void **state) {{")
            body_lines.append("    (void) state;")
            body_lines.append("    reset_sign_msg_test_state();")
            body_lines.append("    // Send INIT successfully")
            body_lines.append(f"    run_deny_init_fixture({init_array_name}, sizeof({init_array_name}), SWO_SUCCESS);")
            body_lines.append("    // Try to send CONFIRM before all chunks received (empty payload)")
            confirm_size = "0" if len(confirm_payload) == 0 else f"sizeof({confirm_array_name})"
            body_lines.append(
                f"    run_deny_confirm_fixture({confirm_array_name}, {confirm_size}, {test_case.expected_swo.name});"
            )
            body_lines.append("}")
            body_lines.append("")

        elif test_case.send_init_when_active:
            # Send a valid INIT, then send another INIT while session is active
            init_array_name = f"SIGN_MSG_DENY_{index:03d}_{safe_test_name}_INIT_APDU"
            body_lines.extend(
                format_bytes_as_c_array(
                    extract_apdu_payload(build_sign_msg_init_apdu_for_deny(test_case)),
                    init_array_name,
                    bytes_per_line=16,
                    return_as_list=True,
                )
            )
            body_lines.append("")
            body_lines.append(f"static void {test_function_name}(void **state) {{")
            body_lines.append("    (void) state;")
            body_lines.append("    reset_sign_msg_test_state();")
            body_lines.append("    // Send INIT successfully")
            body_lines.append(f"    run_deny_init_fixture({init_array_name}, sizeof({init_array_name}), SWO_SUCCESS);")
            body_lines.append("    // Send INIT again while session is already active (do NOT reset state)")
            body_lines.append("    {")
            body_lines.append(
                f"        test_read_buffer_t buf = make_test_read_buffer({init_array_name}, sizeof({init_array_name}));"
            )
            body_lines.append("        apdu_response_begin(INS_SIGN_MSG);")
            body_lines.append("        handler_sign_msg(&buf.sdk_buffer, P1_SIGN_MSG_INIT);")
            body_lines.append("        apdu_response_finalize_after_handler();")
            body_lines.append(f"        assert_int_equal(g_last_response_swo, {test_case.expected_swo.name});")
            body_lines.append(f"        assert_read_buffer_unchanged_and_cleanup(&buf, {init_array_name});")
            body_lines.append("    }")
            body_lines.append("}")
            body_lines.append("")

        elif (
            test_case.truncate_chunk_data_at is not None
            or test_case.invalid_chunk_size is not None
            or (test_case.msgData.isAscii and not all(32 <= b < 127 for b in bytes.fromhex(test_case.msgData.messageHex)))
        ):
            # Send INIT successfully, then CHUNK with invalid size, truncated data, or non-ASCII data
            init_array_name = f"SIGN_MSG_DENY_{index:03d}_{safe_test_name}_INIT_APDU"
            chunk_array_name = f"SIGN_MSG_DENY_{index:03d}_{safe_test_name}_CHUNK_APDU"
            body_lines.extend(
                format_bytes_as_c_array(
                    extract_apdu_payload(build_sign_msg_init_apdu_for_deny(test_case)),
                    init_array_name,
                    bytes_per_line=16,
                    return_as_list=True,
                )
            )
            body_lines.append("")
            body_lines.extend(
                format_bytes_as_c_array(
                    extract_apdu_payload(build_sign_msg_chunk_apdu_for_deny(test_case, 0)),
                    chunk_array_name,
                    bytes_per_line=16,
                    return_as_list=True,
                )
            )
            body_lines.append("")
            body_lines.append(f"static void {test_function_name}(void **state) {{")
            body_lines.append("    (void) state;")
            body_lines.append("    reset_sign_msg_test_state();")
            body_lines.append("    // Send INIT successfully")
            body_lines.append(f"    run_deny_init_fixture({init_array_name}, sizeof({init_array_name}), SWO_SUCCESS);")
            if test_case.truncate_chunk_data_at is not None:
                body_lines.append("    // Send CHUNK with truncated data (size header present, data cut short)")
            elif test_case.invalid_chunk_size is not None:
                body_lines.append("    // Send CHUNK with invalid size")
            else:
                body_lines.append("    // Send CHUNK with non-ASCII data")
            body_lines.append(
                f"    run_deny_chunk_fixture({chunk_array_name}, sizeof({chunk_array_name}), {test_case.expected_swo.name});"
            )
            body_lines.append("}")
            body_lines.append("")

        elif test_case.send_confirm_with_payload:
            # Send INIT, all CHUNKs successfully, then CONFIRM with payload
            init_array_name = f"SIGN_MSG_DENY_{index:03d}_{safe_test_name}_INIT_APDU"
            confirm_array_name = f"SIGN_MSG_DENY_{index:03d}_{safe_test_name}_CONFIRM_APDU"
            transient_success_case = SignMsgTestCase(
                name=test_case.name,
                msgData=test_case.msgData,
            )
            chunk_payloads = CommandBuilder().build_sign_msg_chunk_payloads(transient_success_case)
            body_lines.extend(
                format_bytes_as_c_array(
                    extract_apdu_payload(build_sign_msg_init_apdu_for_deny(test_case)),
                    init_array_name,
                    bytes_per_line=16,
                    return_as_list=True,
                )
            )
            body_lines.append("")
            chunk_array_names = []
            for chunk_idx, chunk_payload in enumerate(chunk_payloads):
                chunk_arr = f"SIGN_MSG_DENY_{index:03d}_{safe_test_name}_CHUNK_{chunk_idx}_APDU"
                chunk_array_names.append(chunk_arr)
                body_lines.extend(
                    format_bytes_as_c_array(
                        chunk_payload,
                        chunk_arr,
                        bytes_per_line=16,
                        return_as_list=True,
                    )
                )
                body_lines.append("")
            body_lines.extend(
                format_bytes_as_c_array(
                    extract_apdu_payload(build_sign_msg_confirm_apdu_for_deny(test_case)),
                    confirm_array_name,
                    bytes_per_line=16,
                    return_as_list=True,
                )
            )
            body_lines.append("")
            body_lines.append(f"static void {test_function_name}(void **state) {{")
            body_lines.append("    (void) state;")
            body_lines.append("    reset_sign_msg_test_state();")
            body_lines.append("    // Send INIT successfully")
            body_lines.append(f"    run_deny_init_fixture({init_array_name}, sizeof({init_array_name}), SWO_SUCCESS);")
            for chunk_idx, chunk_arr in enumerate(chunk_array_names):
                body_lines.append(f"    // Send CHUNK {chunk_idx} successfully")
                body_lines.append(f"    run_deny_chunk_fixture({chunk_arr}, sizeof({chunk_arr}), SWO_SUCCESS);")
            body_lines.append("    // Try to send CONFIRM with non-empty payload")
            body_lines.append(
                f"    run_deny_confirm_fixture({confirm_array_name}, "
                f"sizeof({confirm_array_name}), {test_case.expected_swo.name});"
            )
            body_lines.append("}")
            body_lines.append("")

        else:
            # INIT-only deny test
            init_array_name = f"SIGN_MSG_DENY_{index:03d}_{safe_test_name}_INIT_APDU"
            body_lines.extend(
                format_bytes_as_c_array(
                    extract_apdu_payload(build_sign_msg_init_apdu_for_deny(test_case)),
                    init_array_name,
                    bytes_per_line=16,
                    return_as_list=True,
                )
            )
            body_lines.append("")
            body_lines.append(f"static void {test_function_name}(void **state) {{")
            body_lines.append("    (void) state;")
            body_lines.append(
                f"    run_deny_init_fixture({init_array_name}, sizeof({init_array_name}), {test_case.expected_swo.name});"
            )
            body_lines.append("}")
            body_lines.append("")

        registrations.append(test_function_name)

    return body_lines, registrations


def _build_main(func_names: list[str]) -> str:
    registrations = ",\n        ".join(f"cmocka_unit_test({n})" for n in func_names)
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


def generate_sign_msg_deny_test_runners() -> int:
    test_c_file = GENERATED_SIGN_MSG_DIR / "test_sign_msg_deny_tests.c"

    body_lines, func_names = _build_deny_test_functions()
    if not func_names:
        raise ValueError("No sign message deny test cases found")

    content = (
        _build_file_header() + "\n".join(_build_deny_helpers()) + "\n" + "\n".join(body_lines) + "\n" + _build_main(func_names)
    )

    write_generated_c_file(test_c_file, content)
    print(f"Generated {test_c_file}")
    return len(func_names)
