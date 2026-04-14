/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "globals.h"
#include "handler/derive_native_script_hash.h"
#include "cardano_swo.h"
#include "mem.h"
#include "securityPolicy.h"
#include "apdu/dispatcher.h"
#include "app_context.h"
#include "apdu_finalization_check.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];
static uint16_t g_last_swo = 0;

static inline bool test_mem_init(void) {
    return mem_utils_init(test_heap, sizeof(test_heap));
}

static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    g_last_swo = 0;
    assert_true(test_mem_init());
}

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    (void) buffer;
    (void) bufferLength;
    g_last_swo = swo;
    return 0;
}

int io_send_sw(uint16_t swo) {
    g_last_swo = swo;
    return 0;
}

void nbgl_useCaseSpinner(const char *text) {
    (void) text;
}

void nbgl_useCaseStatus(const char *text, bool success, void (*callback)(void)) {
    (void) text;
    (void) success;
    if (callback != NULL) {
        callback();
    }
}

void ui_menu_main(void) {
}

void ui_display_transaction(void) {
}

void ui_display_native_script_hash(void) {
}

void ui_start_native_script_streaming(void) {
    apdu_response_send_data(NULL, 0, SWO_SUCCESS);
}

// Verify that reset_app_context() handles the stale-deferred state:
// apdu_response_deferred() was called but the UX callback never fired
// (sent=false, deferred=true). reset_app_context() must set sent=true so
// that the next apdu_response_begin() sees a completed deferred response
// and clears the state cleanly instead of asserting.
static void test_reset_app_context_cleans_stale_deferred_state(void **state) {
    (void) state;
    reset_test_context();

    // Simulate a handler that defers the response then fails before the UX
    // callback fires — e.g. an OOM error after apdu_response_deferred().
    apdu_response_begin(INS_GET_PUBLIC_KEY);
    apdu_response_deferred();
    // Do NOT fire the UX callback — call reset directly instead.
    reset_app_context();

    // The next command must be able to start cleanly without asserting.
    // apdu_response_begin() asserts that the previous response was completed;
    // if reset_app_context() did not fix up the stale deferred state this
    // would fire LEDGER_ASSERT.
    apdu_response_begin(INS_GET_PUBLIC_KEY);
    // Send a response so apdu_response_assert_sent_or_deferred() is satisfied.
    apdu_response_send_sw(SWO_SUCCESS);
    apdu_response_assert_sent_or_deferred();
}

static void test_native_script_finish_before_script_completion_resets_context(void **state) {
    (void) state;
    reset_test_context();

    buffer_t init_buf = {
        .ptr = NULL,
        .size = 0,
        .offset = 0,
    };
    apdu_response_begin(INS_DERIVE_NATIVE_SCRIPT_HASH);
    handler_derive_native_script_hash(&init_buf, P1_NATIVE_SCRIPT_INIT);
    apdu_response_assert_sent_or_deferred();
    assert_int_equal(g_last_swo, SWO_SUCCESS);

    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32};
    buffer_t finish_buf = {
        .ptr = finish_payload,
        .size = sizeof(finish_payload),
        .offset = 0,
    };

    apdu_response_begin(INS_DERIVE_NATIVE_SCRIPT_HASH);
    handler_derive_native_script_hash(&finish_buf, P1_NATIVE_SCRIPT_FINISH);
    apdu_response_assert_sent_or_deferred();

    assert_int_equal(g_last_swo, SWO_NATIVE_SCRIPT_PARSING_FAIL_NESTING);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_reset_app_context_cleans_stale_deferred_state),
        cmocka_unit_test(test_native_script_finish_before_script_completion_resets_context),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
