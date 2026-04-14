/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <cmocka.h>

#include "buffer.h"
#include "cardano_swo.h"
#include "globals.h"
#include "app_context.h"
#include "opcert_parse.h"
#include "opcert/opcert_types.h"
#include "handler/sign_opcert.h"
#include "test_fixture_types.h"
#include "app_mem_utils.h"
#include "io_capture.h"
#include "apdu_finalization_check.h"
#include "cardano_constants.h"

// ----------------------------------------------------------------------
// Test state
// ----------------------------------------------------------------------

#define TEST_OPCERT_HEAP_SIZE (8 * 1024)
static uint8_t test_opcert_heap[TEST_OPCERT_HEAP_SIZE];

static inline void reset_opcert_common_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    G_context.req_type = REQUEST_NONE;
    io_capture_reset();
    assert_true(mem_utils_init(test_opcert_heap, sizeof(test_opcert_heap)));
}

// ----------------------------------------------------------------------
// Deny fixture runner — exercises the full handler on malformed or policy-denied payloads
// and verifies the expected SWO error is emitted.
// ----------------------------------------------------------------------

static inline void run_opcert_deny_fixture(const opcert_deny_fixture_t *fixture) {
    assert_non_null(fixture);
    assert_non_null(fixture->payload);
    reset_opcert_common_context();

    buffer_t buf = {
        .ptr = (uint8_t *) fixture->payload,
        .size = fixture->payload_len,
        .offset = 0,
    };
    apdu_response_begin(INS_SIGN_OPCERT);
    handler_sign_opcert(&buf);
    apdu_response_finalize_after_handler();
    assert_int_equal(g_last_response_swo, fixture->expected_swo);
}
