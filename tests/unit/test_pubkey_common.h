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
#include "handler/get_public_key.h"
#include "keyDerivation.h"
#include "securityPolicy/securityPolicyType.h"
#include "securityPolicy/securityWarnings.h"
#include "test_fixture_types.h"
#include "cardano_settings.h"
#include "app_mem_utils.h"
#include "io_capture.h"
#include "nbgl_mock.h"
#include "test_read_buffer_helpers.h"

// ----------------------------------------------------------------------
// Test state
// ----------------------------------------------------------------------

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static inline void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    G_context.req_type = REQUEST_NONE;
    io_capture_reset();
    nbgl_mock_reset();
    assert_true(mem_utils_init(test_heap, sizeof(test_heap)));
}

// ----------------------------------------------------------------------
// Fixture runner
// ----------------------------------------------------------------------

static inline void run_fixture(const pubkey_fixture_t *fixture) {
    assert_non_null(fixture);
    assert_non_null(fixture->data);
    assert_true(fixture->data_len > 0);
    reset_context();

    unit_test_silent_pubkey_export_enabled = fixture->silent_export_enabled;

    test_read_buffer_t pubkey_buffer = make_test_read_buffer(fixture->data, fixture->data_len);

    apdu_response_begin(INS_GET_PUBLIC_KEY);
    handler_get_public_key(&pubkey_buffer.sdk_buffer);
    apdu_response_finalize_after_handler();
    assert_read_buffer_unchanged_and_cleanup(&pubkey_buffer, fixture->data);
    assert_int_equal(g_last_response_swo, fixture->check_expected);

    if (fixture->check_expected == SWO_SUCCESS) {
        assert_non_null(fixture->expected_response);
        assert_true(fixture->expected_response_len > 0);
        assert_int_equal(g_last_response_len, fixture->expected_response_len);
        assert_memory_equal(g_last_response,
                            fixture->expected_response,
                            fixture->expected_response_len);
    }
}
