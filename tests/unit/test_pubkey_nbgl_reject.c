/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "apdu/dispatcher.h"
#include "app_context.h"
#include "app_mem_utils.h"
#include "bip44.h"
#include "buffer.h"
#include "cardano_constants.h"
#include "cardano_swo.h"
#include "globals.h"
#include "handler/get_public_key.h"
#include "io_capture.h"
#include "nbgl_mock.h"
#include "securityPolicy/securityWarnings.h"
#include "test_pubkey_fixtures.h"
#include "ui_display_pubkey.h"
#include "apdu_finalization_check.h"
#include "test_read_buffer_helpers.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    io_capture_reset();
    nbgl_mock_reset();
    assert_true(mem_utils_init(test_heap, sizeof(test_heap)));
}

static uint32_t harden_path(uint32_t value) {
    return value | HARDENED_BIP32;
}

static size_t write_standard_payment_path(uint8_t *out, size_t out_size) {
    const uint32_t path[] = {
        harden_path(PURPOSE_SHELLEY),
        harden_path(ADA_COIN_TYPE),
        harden_path(0),
        0,
        0,
    };
    const size_t path_len = sizeof(path) / sizeof(path[0]);
    const size_t required = 1 + path_len * 4;
    assert_true(required <= out_size);
    out[0] = (uint8_t) path_len;
    for (size_t i = 0; i < path_len; i++) {
        out[1 + i * 4] = (uint8_t) ((path[i] >> 24) & 0xFF);
        out[2 + i * 4] = (uint8_t) ((path[i] >> 16) & 0xFF);
        out[3 + i * 4] = (uint8_t) ((path[i] >> 8) & 0xFF);
        out[4 + i * 4] = (uint8_t) (path[i] & 0xFF);
    }
    return required;
}

static void test_get_public_key_when_request_already_active(void **state) {
    (void) state;
    reset_test_context();

    G_context.req_type = REQUEST_EXPORT_PUBKEY;  // simulate active request

    uint8_t path_raw[32];
    size_t path_len = write_standard_payment_path(path_raw, sizeof(path_raw));
    test_read_buffer_t pubkey_buffer = make_test_read_buffer(path_raw, path_len);
    apdu_response_begin(INS_GET_PUBLIC_KEY);
    handler_get_public_key(&pubkey_buffer.sdk_buffer);
    apdu_response_finalize_after_handler();
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
}

static void test_get_public_key_truncated_path(void **state) {
    (void) state;
    reset_test_context();

    // 1-byte payload: path length byte = 5 but no path components follow
    uint8_t path_raw[1] = {5};
    test_read_buffer_t pubkey_buffer = make_test_read_buffer(path_raw, sizeof(path_raw));
    apdu_response_begin(INS_GET_PUBLIC_KEY);
    handler_get_public_key(&pubkey_buffer.sdk_buffer);
    apdu_response_finalize_after_handler();
    assert_int_equal(g_last_response_swo, SWO_BIP44_PATH_PARSING_FAIL);
}

static void test_get_public_key_trailing_bytes(void **state) {
    (void) state;
    reset_test_context();

    uint8_t path_raw[32];
    size_t path_len = write_standard_payment_path(path_raw, sizeof(path_raw));
    path_raw[path_len] = 0x00;

    test_read_buffer_t pubkey_buffer = make_test_read_buffer(path_raw, path_len + 1);
    apdu_response_begin(INS_GET_PUBLIC_KEY);
    handler_get_public_key(&pubkey_buffer.sdk_buffer);
    apdu_response_finalize_after_handler();
    assert_int_equal(g_last_response_swo, SWO_WRONG_DATA_LENGTH);
}

static void test_nbgl_reject_on_pubkey_export_resets_context(void **state) {
    (void) state;
    reset_test_context();

    const bool final_decisions[] = {false};
    nbgl_mock_set_final_decisions(final_decisions, ARRAY_LEN(final_decisions));

    const pubkey_fixture_t *fixture = &PUBKEY_FIXTURES_TEST_PUBKEY_CONFIRM[3];
    test_read_buffer_t pubkey_buffer = make_test_read_buffer(fixture->data, fixture->data_len);

    apdu_response_begin(INS_GET_PUBLIC_KEY);
    handler_get_public_key(&pubkey_buffer.sdk_buffer);
    apdu_response_finalize_after_handler();
    assert_read_buffer_unchanged_and_cleanup(&pubkey_buffer, fixture->data);
    nbgl_mock_assert_all_final_decisions_consumed();

    assert_int_equal(g_last_response_swo, SWO_CONDITIONS_NOT_SATISFIED);
    assert_int_equal(g_last_response_len, 0);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_pubkey_review_title_matrix(void **state) {
    (void) state;

    const struct {
        const char *name;
        bip44_path_t path;
        warning_bits_t warnings;
        const char *expected_title;
    } test_cases[] = {
        {
            .name = "usual public key",
            .path =
                {
                    .length = 3,
                    .path =
                        {
                            1852 + HARDENED_BIP32,
                            ADA_COIN_TYPE + HARDENED_BIP32,
                            0 + HARDENED_BIP32,
                        },
                },
            .warnings = 0,
            .expected_title = "Export Public key",
        },
        {
            .name = "unusual public key",
            .path =
                {
                    .length = 3,
                    .path =
                        {
                            1852 + HARDENED_BIP32,
                            ADA_COIN_TYPE + HARDENED_BIP32,
                            101 + HARDENED_BIP32,
                        },
                },
            .warnings = ((warning_bits_t) 1 << WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH),
            .expected_title = "Export UNUSUAL Public key",
        },
        {
            .name = "usual cold public key",
            .path =
                {
                    .length = 4,
                    .path =
                        {
                            1853 + HARDENED_BIP32,
                            ADA_COIN_TYPE + HARDENED_BIP32,
                            0 + HARDENED_BIP32,
                            0 + HARDENED_BIP32,
                        },
                },
            .warnings = 0,
            .expected_title = "Export Cold public key",
        },
        {
            .name = "unusual cold public key",
            .path =
                {
                    .length = 4,
                    .path =
                        {
                            1853 + HARDENED_BIP32,
                            ADA_COIN_TYPE + HARDENED_BIP32,
                            0 + HARDENED_BIP32,
                            101 + HARDENED_BIP32,
                        },
                },
            .warnings = ((warning_bits_t) 1 << WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH),
            .expected_title = "Export UNUSUAL Cold public key",
        },
    };

    for (size_t i = 0; i < ARRAY_LEN(test_cases); i++) {
        reset_test_context();
        G_context.req_type = REQUEST_EXPORT_PUBKEY;
        G_context.pk_info.path = test_cases[i].path;

        const bool final_decisions[] = {false};
        nbgl_mock_set_final_decisions(final_decisions, ARRAY_LEN(final_decisions));

        apdu_response_begin(INS_GET_PUBLIC_KEY);
        ui_display_pubkey(POLICY_SHOW, test_cases[i].warnings);
        apdu_response_finalize_after_handler();
        nbgl_mock_assert_all_final_decisions_consumed();

        assert_string_equal(nbgl_mock_last_choice_message(), test_cases[i].expected_title);
        assert_int_equal(g_last_response_swo, SWO_CONDITIONS_NOT_SATISFIED);
        assert_int_equal(G_context.req_type, REQUEST_NONE);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_public_key_when_request_already_active),
        cmocka_unit_test(test_get_public_key_truncated_path),
        cmocka_unit_test(test_get_public_key_trailing_bytes),
        cmocka_unit_test(test_nbgl_reject_on_pubkey_export_resets_context),
        cmocka_unit_test(test_pubkey_review_title_matrix),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
