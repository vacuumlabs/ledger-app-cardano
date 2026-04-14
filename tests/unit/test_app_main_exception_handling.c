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
#include "app_main.h"
#include "app_context.h"
#include "cardano_swo.h"

enum {
    TEST_UNHANDLED_EXCEPTION = 0x1234,
};

static uint16_t g_last_response_swo = 0;

void ui_all_cleanup(void) {
}

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    (void) buffer;
    (void) bufferLength;
    g_last_response_swo = swo;
    return 0;
}

int io_send_sw(uint16_t swo) {
    g_last_response_swo = swo;
    return 0;
}

static void reset_test_state(void) {
    memset(&G_context, 0, sizeof(G_context));
    apdu_response_state_force_reset();
    g_last_response_swo = 0;
}

static void test_app_main_handle_unexpected_exception_without_response_sends_unknown(void **state) {
    (void) state;
    reset_test_state();

    app_main_handle_unexpected_exception(TEST_UNHANDLED_EXCEPTION);
    assert_int_equal(g_last_response_swo, SWO_UNKNOWN);

    apdu_response_begin(INS_GET_VERSION);
    apdu_response_send_sw(SWO_SUCCESS);
    apdu_response_finalize_after_handler();
}

static void test_app_main_handle_unexpected_exception_after_response_does_not_double_send(void **state) {
    (void) state;
    reset_test_state();

    apdu_response_begin(INS_SIGN_TX);
    apdu_response_send_sw(SWO_SECURITY_CONDITION_NOT_SATISFIED);
    app_main_handle_unexpected_exception(TEST_UNHANDLED_EXCEPTION);

    assert_int_equal(g_last_response_swo, SWO_SECURITY_CONDITION_NOT_SATISFIED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(
            test_app_main_handle_unexpected_exception_without_response_sends_unknown),
        cmocka_unit_test(
            test_app_main_handle_unexpected_exception_after_response_does_not_double_send),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
