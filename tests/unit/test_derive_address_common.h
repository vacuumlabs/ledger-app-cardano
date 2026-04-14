/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <setjmp.h>

#include "globals.h"
#include "securityPolicy/securityPolicy.h"
#include "apdu/dispatcher.h"
#include "globals.h"

#include <cmocka.h>
#include "handler/derive_address.h"
#include "hexUtils.h"
#include "mock_crypto/crypto_mock_data.h"
#include "blake2b.h"
#include "mem.h"
#include "app_context.h"

#include "test_fixture_types.h"
#include "handler/derive_address.h"
#include "io_capture.h"
#include "nbgl_mock.h"
#include "test_read_buffer_helpers.h"

// ----------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------

// ----------------------------------------------------------------------
// Simple mocks for IO and UI plumbing so we can drive the handler
// ----------------------------------------------------------------------

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static inline bool test_mem_init(void) {
    return mem_utils_init(test_heap, sizeof(test_heap));
}

extern bool app_mem_init(void);
static inline void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
}

// ----------------------------------------------------------------------
// Fixture runner
// ----------------------------------------------------------------------

static inline void run_fixture(const derive_address_fixture_t *fixture) {
    assert_non_null(fixture);
    assert_non_null(fixture->data);
    assert_true(fixture->data_len > 0);
    reset_context();
    assert_true(test_mem_init());
    io_capture_reset();
    nbgl_mock_reset();

    TRACE("Running derive address fixture: %s\n", fixture->name);

    // Mock the handler call with fixture data
    // The handler should reject and return the expected status word
    test_read_buffer_t derive_address_buffer =
        make_test_read_buffer(fixture->data, fixture->data_len);
    TRACE_BUFFER(derive_address_buffer.sdk_buffer.ptr, derive_address_buffer.sdk_buffer.size);
    apdu_response_begin(INS_DERIVE_ADDRESS);
    handler_derive_address(&derive_address_buffer.sdk_buffer, fixture->p1);
    apdu_response_finalize_after_handler();
    assert_read_buffer_unchanged_and_cleanup(&derive_address_buffer, fixture->data);
    assert_int_equal(g_last_response_swo, fixture->check_expected);

    if (fixture->check_expected == SWO_SUCCESS && fixture->p1 == P1_ADDRESS_RETURN) {
        if (fixture->expected_address == NULL || fixture->expected_address_len == 0) {
            fprintf(stderr, "UNIT_CAPTURE [%s] expectedAddressHex=", fixture->name);
            for (size_t i = 0; i < g_last_response_len; i++)
                fprintf(stderr, "%02x", g_last_response[i]);
            fprintf(stderr, "\n");
            fail_msg("Missing unit expected result for derive_address fixture '%s'", fixture->name);
        }

        assert_int_equal(g_last_response_len, fixture->expected_address_len);
        assert_memory_equal(g_last_response,
                            fixture->expected_address,
                            fixture->expected_address_len);
    }
}
