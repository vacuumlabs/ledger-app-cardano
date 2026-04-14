/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "addressUtils/bip44.h"
#include "apdu/dispatcher.h"
#include "app_context.h"
#include "app_mem_utils.h"
#include "buffer.h"
#include "cardano_swo.h"
#include "globals.h"
#include "handler/sign_cvote.h"
#include "io_capture.h"
#include "nbgl_mock.h"
#include "apdu_finalization_check.h"
#include "test_read_buffer_helpers.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static uint32_t harden(uint32_t value) {
    return value | HARDENED_BIP32;
}

static size_t write_bip44_path(uint8_t *out,
                               size_t out_size,
                               const uint32_t *path,
                               size_t path_len) {
    const size_t required = 1 + 4 * path_len;
    assert_true(required <= out_size);
    assert_true(path_len <= BIP44_MAX_PATH_ELEMENTS);

    out[0] = (uint8_t) path_len;
    for (size_t i = 0; i < path_len; i++) {
        out[1 + i * 4] = (uint8_t) ((path[i] >> 24) & 0xFFu);
        out[2 + i * 4] = (uint8_t) ((path[i] >> 16) & 0xFFu);
        out[3 + i * 4] = (uint8_t) ((path[i] >> 8) & 0xFFu);
        out[4 + i * 4] = (uint8_t) (path[i] & 0xFFu);
    }
    return required;
}

static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    io_capture_reset();
    nbgl_mock_reset();
    assert_true(mem_utils_init(test_heap, sizeof(test_heap)));
}

static void run_sign_cvote_apdu(const uint8_t *data, size_t data_len, uint8_t p1) {
    test_read_buffer_t cvote_buffer = make_test_read_buffer(data, data_len);
    apdu_response_begin(INS_SIGN_CVOTE);
    handler_sign_cvote(&cvote_buffer.sdk_buffer, p1);
    apdu_response_finalize_after_handler();
    assert_read_buffer_unchanged_and_cleanup(&cvote_buffer, data);
}

static void test_nbgl_reject_on_cvote_confirm_resets_context(void **state) {
    (void) state;
    reset_test_context();

    // INIT payload: [remaining bytes=34] || [votePlanId(32)] || [proposalIndex(1)] ||
    // [payloadTag(1)]
    uint8_t init_payload[4 + 34] = {0};
    init_payload[3] = 34;      // big-endian u32
    init_payload[4 + 32] = 7;  // proposal index
    init_payload[4 + 33] = 1;  // payload type tag
    run_sign_cvote_apdu(init_payload, sizeof(init_payload), P1_CVOTE_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(G_context.state.cvote_state, VOTECAST_STATE_CONFIRM);

    const bool final_decisions[] = {false};
    nbgl_mock_set_final_decisions(final_decisions, ARRAY_LEN(final_decisions));

    const uint32_t witness_path[] = {
        harden(PURPOSE_CVOTE_KEY),
        harden(ADA_COIN_TYPE),
        harden(0),
        0,
        1,
    };
    uint8_t confirm_payload[1 + 4 * BIP44_MAX_PATH_ELEMENTS] = {0};
    const size_t confirm_payload_len = write_bip44_path(confirm_payload,
                                                        sizeof(confirm_payload),
                                                        witness_path,
                                                        ARRAY_LEN(witness_path));
    run_sign_cvote_apdu(confirm_payload, confirm_payload_len, P1_CVOTE_CONFIRM);
    nbgl_mock_assert_all_final_decisions_consumed();

    assert_int_equal(g_last_response_swo, SWO_CONDITIONS_NOT_SATISFIED);
    assert_int_equal(g_last_response_len, 0);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.cvote_state, VOTECAST_STATE_NONE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_nbgl_reject_on_cvote_confirm_resets_context),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
