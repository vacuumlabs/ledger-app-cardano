/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <cmocka.h>

#include "handler/sign_tx.h"
#include "handler/sign_tx_aux_data.h"
#include "buffer.h"
#include "cardano_swo.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "dispatcher.h"
#include "securityPolicy/securityPolicy.h"
#include "tx_utils.h"
#include "tx_parse.h"
#include "app_context.h"
#include "apdu_finalization_check.h"
#include "hexUtils.h"
#include "utils/utils.h"
#include "ui_display_tx.h"

// P1 constants now defined in dispatcher.h (included via globals.h)

// ----------------------------------------------------------------------
// Simple mocks for IO plumbing so we can drive the handler
// UI mocks (NBGL functions, ui_display_*, ui_menu_main) are provided by
// the cardano_sign_tx_core library which includes nbgl_mock.c
// ----------------------------------------------------------------------

static uint16_t g_last_swo = 0;

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

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

static void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    g_last_swo = 0;
}

static inline void run_sign_tx_apdu(buffer_t *buffer, uint8_t p1) {
    apdu_response_begin(INS_SIGN_TX);
    handler_sign_tx(buffer, p1);
    apdu_response_finalize_after_handler();
}

static inline void run_sign_tx_witness_apdu(buffer_t *buffer) {
    apdu_response_begin(INS_SIGN_TX);
    handler_sign_tx_witness(buffer);
    apdu_response_finalize_after_handler();
}

static inline void run_sign_tx_aux_data_apdu(buffer_t *buffer, uint8_t p2) {
    apdu_response_begin(INS_SIGN_TX);
    handler_sign_tx_aux_data(buffer, p2);
    apdu_response_finalize_after_handler();
}

typedef struct {
    const char *hex_payload;
    uint8_t p1;
    uint8_t p2;
    bool more;
} apdu_segment_t;

typedef struct {
    const char *name;
    const char *init_hex;
    const apdu_segment_t *chunks;
    size_t chunk_count;
    uint16_t expected_swo;
    bool expect_init_failure;
    bool has_required_expert_mode;
    bool required_expert_mode;
    const char *skip_reason;
} sign_tx_deny_fixture_t;

#include "test_sign_tx_fixtures_deny.h"
#include "app_mem_utils.h"

// Accesses the body slot directly because this may be called in any tx state (including NONE).
static inline void tx_context_cleanup(void) {
    APP_MEM_FREE_AND_NULL((void **) &G_context.tx_info.body.raw_tx);
    G_context.tx_info.body.total_ui_pairs = 0;
}

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];
extern bool unit_test_expert_mode_enabled;

// ----------------------------------------------------------------------
// Fixture runner
// ----------------------------------------------------------------------

static void run_sign_tx_deny_fixture(const sign_tx_deny_fixture_t *fixture) {
    reset_context();
    assert_true(mem_utils_init(test_heap, sizeof(test_heap)));
    const bool previous_expert_mode = unit_test_expert_mode_enabled;
    if (fixture->has_required_expert_mode) {
        unit_test_expert_mode_enabled = fixture->required_expert_mode;
    }

    uint8_t init_raw[512];
    size_t init_len = hex_to_bytes(fixture->init_hex, init_raw, sizeof(init_raw));
    buffer_t init_buf = {
        .ptr = init_raw,
        .size = init_len,
        .offset = 0,
    };

    g_last_swo = 0;
    run_sign_tx_apdu(&init_buf, P1_TX_INIT);

    if (fixture->expect_init_failure) {
        assert_int_equal(g_last_swo, fixture->expected_swo);
        assert_int_equal(G_context.req_type, REQUEST_NONE);
        tx_context_cleanup();
        unit_test_expert_mode_enabled = previous_expert_mode;
        return;
    }

    assert_int_equal(g_last_swo, SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
    if (fixture->chunk_count > 0 && fixture->chunks[0].p1 == P1_TX_AUX_DATA) {
        assert_int_equal(G_context.state.tx_state, TX_STATE_AUX_DATA);
    } else {
        assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);
    }

    bool failure_seen = false;
    for (size_t i = 0; i < fixture->chunk_count; i++) {
        const apdu_segment_t *segment = &fixture->chunks[i];
        uint8_t chunk_raw[512];
        size_t chunk_len = hex_to_bytes(segment->hex_payload, chunk_raw, sizeof(chunk_raw));
        buffer_t chunk_buf = {
            .ptr = chunk_raw,
            .size = chunk_len,
            .offset = 0,
        };
        g_last_swo = 0;
        if (segment->p1 == P1_TX_SIGN_WITNESS) {
            run_sign_tx_witness_apdu(&chunk_buf);
        } else if (segment->p1 == P1_TX_AUX_DATA) {
            run_sign_tx_aux_data_apdu(&chunk_buf, segment->p2);
        } else {
            run_sign_tx_apdu(&chunk_buf, segment->p1);
        }
        if (g_last_swo != 0) {
            if (g_last_swo == SWO_SUCCESS) {
                continue;
            }
            assert_int_equal(g_last_swo, fixture->expected_swo);
            failure_seen = true;
            break;
        }
    }

    assert_true(failure_seen);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    tx_context_cleanup();
    unit_test_expert_mode_enabled = previous_expert_mode;
}

static void test_sign_tx_deny_fixture(void **state) {
    const sign_tx_deny_fixture_t *fixture = (const sign_tx_deny_fixture_t *) *state;
    assert_non_null(fixture);
    if (fixture->skip_reason != NULL) {
        print_message("[SKIP] %s: %s\n", fixture->name, fixture->skip_reason);
        skip();
        return;
    }
    run_sign_tx_deny_fixture(fixture);
}

int main(void) {
    const size_t test_count = ARRAY_LEN(SIGN_TX_DENY_FIXTURES);
    struct CMUnitTest tests[ARRAY_LEN(SIGN_TX_DENY_FIXTURES)];
    size_t skipped_count = 0;

    for (size_t i = 0; i < test_count; i++) {
        tests[i] = (struct CMUnitTest){
            .name = SIGN_TX_DENY_FIXTURES[i].name,
            .test_func = test_sign_tx_deny_fixture,
            .initial_state = (void *) &SIGN_TX_DENY_FIXTURES[i],
        };
        if (SIGN_TX_DENY_FIXTURES[i].skip_reason != NULL) {
            skipped_count++;
        }
    }

    int result = cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);

    if (skipped_count > 0) {
        print_message("\n");
        print_message(
            "================================================================================\n");
        print_message("WARNING: %zu/%zu TESTS WERE SKIPPED!\n", skipped_count, test_count);
        print_message(
            "================================================================================\n");
        print_message("\nThese tests are not yet implemented. See skip_reason in test fixtures.\n");
        print_message("Test coverage is incomplete until all skipped tests are enabled.\n");
        print_message(
            "================================================================================\n");
        print_message("\n");
        // Return non-zero to make test harness visible of skipped tests
        return 1;
    }

    return result;
}
