/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Unit tests for NBGL rejection paths in ui_display_native_script_hash.c:
 *   1. derive_native_script_hash_streaming_continue_choice(false) — user rejects an
 *      intermediate script display page (e.g. the "ALL script" overview page).
 *   2. derive_native_script_hash_streaming_finish_continue(false) — user rejects the
 *      final script-hash display page before the confirmation screen.
 *   3. derive_native_script_hash_review_choice(false) — user rejects on the final
 *      "Confirm hash" screen.
 *
 * All three paths were previously unreachable from any unit test, leading to
 * incorrect LCOV_EXCL_LINE annotations.  These tests remove the need for those
 * exclusions.
 *
 * Fixture: TC3 "Native_script_ALL_script" — ALL(pubkey0, pubkey1), bech32 display.
 * APDU sequence:
 *   INIT              → streaming-start callback (auto-confirmed by mock)
 *   START_COMPLEX ALL 2 → streaming-continue[0] (ALL overview page)
 *   ADD_SIMPLE pubkey0  → streaming-continue[1]
 *   ADD_SIMPLE pubkey1  → streaming-continue[2]
 *   FINISH bech32       → streaming-continue[3] (hash page, streaming_finish_continue)
 *                         → if confirmed: streaming-finish → review_choice
 */

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
#include "cardano_swo.h"
#include "globals.h"
#include "handler/derive_native_script_hash.h"
#include "nbgl_mock.h"
#include "apdu_finalization_check.h"
#include "test_native_script_utils.h"
#include "test_read_buffer_helpers.h"

// ======================================================================
// Fixture data (TC3: ALL(pubkey0, pubkey1), bech32 finish)
// Source: tests/unit/generated/native_script/test_derive_native_script_fixtures.h
// ======================================================================

// START_COMPLEX: ALL, 2 children  [type=0x01, count=0x00000002]
static const uint8_t TC3_START_ALL_2[] = {0x01, 0x00, 0x00, 0x00, 0x02};

// ADD_SIMPLE: pubkey_third_party (type byte 0x00 + 28-byte hash)
static const uint8_t TC3_PUBKEY0[] = {
    0x00, 0x00, 0xC4, 0xB9, 0x26, 0x56, 0x45, 0xFD, 0xE9, 0x53, 0x6C, 0x07, 0x95, 0xAD, 0xBC,
    0xC5, 0x29, 0x17, 0x67, 0xA0, 0xC6, 0x1F, 0xD6, 0x24, 0x48, 0x34, 0x1D, 0x7E, 0x03, 0x86,
};
static const uint8_t TC3_PUBKEY1[] = {
    0x00, 0x00, 0x02, 0x41, 0xF2, 0xD1, 0x96, 0xF5, 0x2A, 0x92, 0xFB, 0xD2, 0x18, 0x3D, 0x03,
    0xB3, 0x70, 0xC3, 0x0B, 0x69, 0x60, 0xCF, 0xDE, 0xAE, 0x36, 0x4F, 0xFA, 0xBA, 0xC8, 0x89,
};

// FINISH: display format = BECH32 (0x01)
static const uint8_t TC3_FINISH_BECH32[] = {0x01};

// ======================================================================
// Test state
// ======================================================================

static void reset_test_context(void) {
    reset_context();
    reset_response_buffer();
    assert_true(test_mem_init());
    nbgl_mock_reset();
}

// ======================================================================
// Helpers
// ======================================================================

static void run_apdu(const uint8_t *data, size_t data_len, uint8_t p1) {
    test_read_buffer_t buf = make_test_read_buffer(data, data_len);
    apdu_response_begin(INS_DERIVE_NATIVE_SCRIPT_HASH);
    handler_derive_native_script_hash(&buf.sdk_buffer, p1);
    apdu_response_finalize_after_handler();
    assert_read_buffer_unchanged_and_cleanup(&buf, data);
}

/**
 * Send INIT + START_COMPLEX + two ADD_SIMPLE APDUs, all confirmed.
 * After this the next APDU (FINISH) will trigger the hash display page
 * via streaming-continue (streaming_finish_continue).
 *
 * Streaming-continue call indices (zero-based) after INIT:
 *   0: ALL overview page (START_COMPLEX response)
 *   1: pubkey0 page (ADD_SIMPLE response)
 *   2: pubkey1 page (ADD_SIMPLE response)
 *   3: hash page (FINISH response) → streaming_finish_continue
 */
static void send_init_and_all_scripts(void) {
    nbgl_mock_set_streaming_start_auto_complete(true, true);

    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    run_apdu(TC3_START_ALL_2, sizeof(TC3_START_ALL_2), P1_NATIVE_SCRIPT_START_COMPLEX);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    run_apdu(TC3_PUBKEY0, sizeof(TC3_PUBKEY0), P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    run_apdu(TC3_PUBKEY1, sizeof(TC3_PUBKEY1), P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);
}

// ======================================================================
// Test 1: streaming_continue_choice(false)
//
// Reject at the ALL overview page (first streaming-continue call, index 0).
// Covers the !confirm branch in derive_native_script_hash_streaming_continue_choice.
// ======================================================================
static void test_streaming_continue_reject_resets_context(void **state) {
    (void) state;
    reset_test_context();

    nbgl_mock_set_streaming_start_auto_complete(true, true);
    // Reject at the first nbgl_useCaseReviewStreamingContinue call (ALL overview page).
    nbgl_mock_set_streaming_continue_reject_at_call(0);

    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_DERIVE_NATIVE_SCRIPT_HASH);

    // START_COMPLEX triggers display_complex_script_content → streaming-continue → reject
    run_apdu(TC3_START_ALL_2, sizeof(TC3_START_ALL_2), P1_NATIVE_SCRIPT_START_COMPLEX);

    assert_int_equal(get_last_swo(), SWO_CONDITIONS_NOT_SATISFIED);
    assert_int_equal(get_response_buffer_length(), 0);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// ======================================================================
// Test 2: streaming_finish_continue(false)
//
// Confirm all intermediate pages, then reject on the hash display page.
// Covers the !confirm branch in derive_native_script_hash_streaming_finish_continue.
// ======================================================================
static void test_streaming_finish_reject_resets_context(void **state) {
    (void) state;
    reset_test_context();

    send_init_and_all_scripts();

    // The FINISH APDU calls ui_display_native_script_hash with UI_SCRIPT_DISPLAY_SCRIPT_HASH,
    // which calls nbgl_useCaseReviewStreamingContinue → streaming_finish_continue.
    // nbgl_mock_set_streaming_continue_reject_at_call() resets the internal call counter,
    // so the FINISH APDU's continue call is index 0 relative to this fresh counter.
    nbgl_mock_set_streaming_continue_reject_at_call(0);

    run_apdu(TC3_FINISH_BECH32, sizeof(TC3_FINISH_BECH32), P1_NATIVE_SCRIPT_FINISH);
    nbgl_mock_assert_all_final_decisions_consumed();

    assert_int_equal(get_last_swo(), SWO_CONDITIONS_NOT_SATISFIED);
    assert_int_equal(get_response_buffer_length(), 0);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// ======================================================================
// Test 3: review_choice(false)
//
// Confirm all intermediate pages and the hash display page, then reject
// on the final "Confirm hash" screen.
// Covers the !confirm branch in derive_native_script_hash_review_choice.
// ======================================================================
static void test_final_review_reject_resets_context(void **state) {
    (void) state;
    reset_test_context();

    send_init_and_all_scripts();

    // Inject rejection at the final review (nbgl_useCaseReviewStreamingFinish callback).
    const bool final_decisions[] = {false};
    nbgl_mock_set_final_decisions(final_decisions, ARRAY_LEN(final_decisions));

    run_apdu(TC3_FINISH_BECH32, sizeof(TC3_FINISH_BECH32), P1_NATIVE_SCRIPT_FINISH);

    assert_int_equal(get_last_swo(), SWO_CONDITIONS_NOT_SATISFIED);
    assert_int_equal(get_response_buffer_length(), 0);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// ======================================================================
// Main
// ======================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_streaming_continue_reject_resets_context),
        cmocka_unit_test(test_streaming_finish_reject_resets_context),
        cmocka_unit_test(test_final_review_reject_resets_context),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
