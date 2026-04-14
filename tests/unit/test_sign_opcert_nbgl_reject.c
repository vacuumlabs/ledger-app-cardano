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
#include "handler/sign_opcert.h"
#include "io_capture.h"
#include "nbgl_mock.h"
#include "test_opcert_fixtures.h"
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

static void test_nbgl_reject_on_sign_opcert_review_resets_context(void **state) {
    (void) state;
    reset_test_context();

    const bool final_decisions[] = {false};
    nbgl_mock_set_final_decisions(final_decisions, ARRAY_LEN(final_decisions));

    const opcert_fixture_t *fixture = &OPCERT_FIXTURES[0];
    test_read_buffer_t opcert_buffer =
        make_test_read_buffer(fixture->payload, fixture->payload_len);

    apdu_response_begin(INS_SIGN_OPCERT);
    handler_sign_opcert(&opcert_buffer.sdk_buffer);
    apdu_response_finalize_after_handler();
    assert_read_buffer_unchanged_and_cleanup(&opcert_buffer, fixture->payload);
    nbgl_mock_assert_all_final_decisions_consumed();

    assert_int_equal(g_last_response_swo, SWO_CONDITIONS_NOT_SATISFIED);
    assert_int_equal(g_last_response_len, 0);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.opcert_state, OPCERT_STATE_NONE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_nbgl_reject_on_sign_opcert_review_resets_context),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
