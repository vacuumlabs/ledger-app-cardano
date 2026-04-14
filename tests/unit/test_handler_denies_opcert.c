/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Handcrafted unit tests for sign_opcert handler interleaving failures.
 * These paths require controlling the request state before calling the
 * handler, which is not possible via the ragger-generated deny fixtures.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "test_opcert_common.h"
#include "apdu_finalization_check.h"

// A valid opcert payload: KES key (32) + KES period (8) + issue counter (8) + path (17)
// m/1853'/1815'/0'/0'  => count=4, 0x8000073d 0x00000717 0x80000000 0x80000000
static const uint8_t VALID_OPCERT_PAYLOAD[] = {
    // 32 bytes KES public key
    0x3d,
    0x24,
    0xbc,
    0x54,
    0x73,
    0x88,
    0xcf,
    0x24,
    0x03,
    0xfd,
    0x97,
    0x8f,
    0xc3,
    0xd3,
    0xa9,
    0x3d,
    0x1f,
    0x39,
    0xac,
    0xf6,
    0x8a,
    0x9c,
    0x00,
    0xe4,
    0x05,
    0x12,
    0x08,
    0x4d,
    0xc0,
    0x5f,
    0x28,
    0x22,
    // 8 bytes KES period (47)
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x2f,
    // 8 bytes issue counter (42)
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x2a,
    // path count=4, m/1853'/1815'/0'/0'
    0x04,
    0x80,
    0x00,
    0x07,
    0x3d,
    0x00,
    0x00,
    0x07,
    0x17,
    0x80,
    0x00,
    0x00,
    0x00,
    0x80,
    0x00,
    0x00,
    0x00,
};

static void test_opcert_signing_during_tx_signing(void **state) {
    (void) state;
    reset_opcert_common_context();
    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = TX_STATE_APPROVED;

    buffer_t buf = {
        .ptr = (uint8_t *) VALID_OPCERT_PAYLOAD,
        .size = sizeof(VALID_OPCERT_PAYLOAD),
        .offset = 0,
    };
    apdu_response_begin(INS_SIGN_OPCERT);
    handler_sign_opcert(&buf);
    apdu_response_finalize_after_handler();
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
}

static void test_opcert_rejects_when_session_active(void **state) {
    (void) state;
    reset_opcert_common_context();
    G_context.req_type = REQUEST_SIGN_TRANSACTION;
    G_context.state.tx_state = 0;

    buffer_t buf = {
        .ptr = (uint8_t *) VALID_OPCERT_PAYLOAD,
        .size = sizeof(VALID_OPCERT_PAYLOAD),
        .offset = 0,
    };
    apdu_response_begin(INS_SIGN_OPCERT);
    handler_sign_opcert(&buf);
    apdu_response_finalize_after_handler();
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_opcert_signing_during_tx_signing),
        cmocka_unit_test(test_opcert_rejects_when_session_active),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
