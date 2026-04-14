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
#include "buffer.h"
#include "cardano_swo.h"
#include "globals.h"
#include "handler/derive_address.h"
#include "io_capture.h"
#include "nbgl_mock.h"
#include "apdu_finalization_check.h"
#include "test_read_buffer_helpers.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static const uint8_t SHELLEY_DISPLAY_APDU_PAYLOAD[] = {
    0x00, 0x03, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x65,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80,
    0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
};

static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    io_capture_reset();
    nbgl_mock_reset();
    assert_true(mem_utils_init(test_heap, sizeof(test_heap)));
}

// REWARD_KEY (0x0E) + network 0x03 + no payment part + STAKING_PART_KEY_HASH (0x33) + 28 zero
// bytes. policyForShowDeriveAddress denies REWARD_KEY unless staking part is KEY_PATH.
static const uint8_t REWARD_KEY_HASH_STAKING_DISPLAY_APDU[] = {
    0x0E,  // address type: REWARD_KEY
    0x03,  // network id: testnet
    0x33,  // staking part type: STAKING_PART_KEY_HASH
    // 28-byte staking key hash (all zeros)
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
};

static void test_nbgl_reject_on_address_review_resets_context(void **state) {
    (void) state;
    reset_test_context();

    const bool final_decisions[] = {false};
    nbgl_mock_set_final_decisions(final_decisions, ARRAY_LEN(final_decisions));

    test_read_buffer_t derive_address_buffer =
        make_test_read_buffer(SHELLEY_DISPLAY_APDU_PAYLOAD, sizeof(SHELLEY_DISPLAY_APDU_PAYLOAD));

    apdu_response_begin(INS_DERIVE_ADDRESS);
    handler_derive_address(&derive_address_buffer.sdk_buffer, P1_ADDRESS_DISPLAY);
    apdu_response_finalize_after_handler();
    assert_read_buffer_unchanged_and_cleanup(&derive_address_buffer, SHELLEY_DISPLAY_APDU_PAYLOAD);
    nbgl_mock_assert_all_final_decisions_consumed();

    assert_int_equal(g_last_response_swo, SWO_CONDITIONS_NOT_SATISFIED);
    assert_int_equal(g_last_response_len, 0);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.derive_address_state, DERIVE_ADDRESS_STATE_NONE);
}

static void test_derive_address_rejects_when_request_already_active(void **state) {
    (void) state;
    reset_test_context();

    G_context.req_type = REQUEST_SIGN_TRANSACTION;

    test_read_buffer_t derive_address_buffer =
        make_test_read_buffer(SHELLEY_DISPLAY_APDU_PAYLOAD, sizeof(SHELLEY_DISPLAY_APDU_PAYLOAD));

    apdu_response_begin(INS_DERIVE_ADDRESS);
    handler_derive_address(&derive_address_buffer.sdk_buffer, P1_ADDRESS_DISPLAY);
    apdu_response_finalize_after_handler();
    assert_read_buffer_unchanged_and_cleanup(&derive_address_buffer, SHELLEY_DISPLAY_APDU_PAYLOAD);

    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(g_last_response_len, 0);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.derive_address_state, DERIVE_ADDRESS_STATE_NONE);
}

static void test_derive_address_parse_failure(void **state) {
    (void) state;
    reset_test_context();

    // Single byte 0xFF: not a valid address type → buffer_read_address_params returns false
    uint8_t payload[1] = {0xFF};
    test_read_buffer_t buf = make_test_read_buffer(payload, sizeof(payload));
    apdu_response_begin(INS_DERIVE_ADDRESS);
    handler_derive_address(&buf.sdk_buffer, P1_ADDRESS_DISPLAY);
    apdu_response_finalize_after_handler();

    assert_int_equal(g_last_response_swo, SWO_DERIVE_ADDRESS_PARSING_FAIL_ADDRESS_PARAMS);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_derive_address_trailing_bytes(void **state) {
    (void) state;
    reset_test_context();

    // Append a trailing byte to an otherwise valid SHELLEY_DISPLAY_APDU_PAYLOAD
    uint8_t payload[sizeof(SHELLEY_DISPLAY_APDU_PAYLOAD) + 1];
    memcpy(payload, SHELLEY_DISPLAY_APDU_PAYLOAD, sizeof(SHELLEY_DISPLAY_APDU_PAYLOAD));
    payload[sizeof(SHELLEY_DISPLAY_APDU_PAYLOAD)] = 0xFF;

    test_read_buffer_t buf = make_test_read_buffer(payload, sizeof(payload));
    apdu_response_begin(INS_DERIVE_ADDRESS);
    handler_derive_address(&buf.sdk_buffer, P1_ADDRESS_DISPLAY);
    apdu_response_finalize_after_handler();

    assert_int_equal(g_last_response_swo, SWO_WRONG_DATA_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_derive_address_display_policy_deny(void **state) {
    (void) state;
    reset_test_context();

    test_read_buffer_t buf = make_test_read_buffer(REWARD_KEY_HASH_STAKING_DISPLAY_APDU,
                                                   sizeof(REWARD_KEY_HASH_STAKING_DISPLAY_APDU));
    apdu_response_begin(INS_DERIVE_ADDRESS);
    handler_derive_address(&buf.sdk_buffer, P1_ADDRESS_DISPLAY);
    apdu_response_finalize_after_handler();

    assert_int_equal(g_last_response_swo, SWO_SECURITY_CONDITION_NOT_SATISFIED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_nbgl_reject_on_address_review_resets_context),
        cmocka_unit_test(test_derive_address_rejects_when_request_already_active),
        cmocka_unit_test(test_derive_address_parse_failure),
        cmocka_unit_test(test_derive_address_trailing_bytes),
        cmocka_unit_test(test_derive_address_display_policy_deny),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
