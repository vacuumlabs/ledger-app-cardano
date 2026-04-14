/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Handcrafted unit tests for sign_cvote handler parser and interleaving
 * failures.  These paths are not reachable via the ragger CommandBuilder
 * (which always produces well-formed APDUs), so they must be exercised
 * with manually crafted byte buffers here.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "test_cvote_common.h"
#include "apdu_finalization_check.h"

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

static inline void run_cvote_apdu(const uint8_t *data, size_t len, uint8_t p1) {
    buffer_t buf = {.ptr = (uint8_t *) data, .size = len, .offset = 0};
    apdu_response_begin(INS_SIGN_CVOTE);
    handler_sign_cvote(&buf, p1);
    apdu_response_finalize_after_handler();
}

// A minimal valid INIT payload: 4-byte big-endian total length = 33 bytes,
// followed by exactly 33 bytes of votecast chunk data.
// The 33 bytes cover VOTE_PLAN_ID_SIZE(32) + proposal_index(1).
// Payload type tag is absent — so the INIT will succeed up to and including
// the proposal_index read, then fail on payload_type_tag.
//
// vote_plan_id (32 bytes): all zeros
// proposal_index: 0x00
// total_len field = 33  =>  expected_chunk_size = min(33, 250) = 33
// chunk data = 33 bytes (matches)

static const uint8_t CVOTE_INIT_NO_PAYLOAD_TYPE_TAG[] = {
    0x00,
    0x00,
    0x00,
    0x21,  // total_len = 33
    // 32 bytes vote_plan_id (all zeros)
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,  // proposal_index = 0
    // payload_type_tag byte is missing
};

static const uint8_t CVOTE_INIT_NO_PROPOSAL_INDEX[] = {
    0x00,
    0x00,
    0x00,
    0x20,  // total_len = 32
    // 32 bytes vote_plan_id (all zeros)  — proposal_index byte is missing
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
};

static const uint8_t CVOTE_INIT_NO_VOTE_PLAN_ID[] = {
    0x00,
    0x00,
    0x00,
    0x1f,  // total_len = 31 (< 32 needed for vote_plan_id)
    // 31 bytes — too short to read the full vote_plan_id
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
};

// A valid short INIT (total_len == chunk_size == 34):
// vote_plan_id(32) + proposal_index(1) + payload_type_tag(1)
static const uint8_t CVOTE_INIT_VALID_SHORT[] = {
    0x00, 0x00, 0x00, 0x22,  // total_len = 34
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,  // proposal_index
    0x00,  // payload_type_tag
};

// Confirm payload: path m/1694'/1815'/0'/0/1  (5 elements)
// count=5 | 0x800006a6 | 0x80000717 | 0x80000000 | 0x00000000 | 0x00000001
static const uint8_t CVOTE_CONFIRM_VALID_PATH[] = {
    0x05, 0x80, 0x00, 0x06, 0xa6, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

// Confirm payload with trailing garbage byte
static const uint8_t CVOTE_CONFIRM_TRAILING_BYTE[] = {
    0x05, 0x80, 0x00, 0x06, 0xa6, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0xff,  // trailing garbage
};

// Confirm payload: truncated path (only 1 element specified but count says 5)
static const uint8_t CVOTE_CONFIRM_TRUNCATED_PATH[] = {
    0x05,
    0x80,
    0x00,
    0x06,
    0xa6,
    // remaining 4 elements missing
};

// ----------------------------------------------------------------------
// INIT parser failure tests
// ----------------------------------------------------------------------

static void test_cvote_init_rejects_truncated_length_field(void **state) {
    (void) state;
    reset_cvote_test_state();
    // Only 2 bytes — can't read the 4-byte total_len field.
    static const uint8_t buf[] = {0x00, 0x00};
    run_cvote_apdu(buf, sizeof(buf), P1_CVOTE_INIT);
    assert_int_equal(g_last_response_swo, SWO_CVOTE_PARSING_FAIL_REMAINING_VOTECAST_BYTES);
}

static void test_cvote_init_rejects_missing_vote_plan_id(void **state) {
    (void) state;
    reset_cvote_test_state();
    run_cvote_apdu(CVOTE_INIT_NO_VOTE_PLAN_ID, sizeof(CVOTE_INIT_NO_VOTE_PLAN_ID), P1_CVOTE_INIT);
    assert_int_equal(g_last_response_swo, SWO_CVOTE_PARSING_FAIL_VOTE_PLAN_ID);
}

static void test_cvote_init_rejects_missing_proposal_index(void **state) {
    (void) state;
    reset_cvote_test_state();
    run_cvote_apdu(CVOTE_INIT_NO_PROPOSAL_INDEX,
                   sizeof(CVOTE_INIT_NO_PROPOSAL_INDEX),
                   P1_CVOTE_INIT);
    assert_int_equal(g_last_response_swo, SWO_CVOTE_PARSING_FAIL_PROPOSAL_INDEX);
}

static void test_cvote_init_rejects_missing_payload_type_tag(void **state) {
    (void) state;
    reset_cvote_test_state();
    run_cvote_apdu(CVOTE_INIT_NO_PAYLOAD_TYPE_TAG,
                   sizeof(CVOTE_INIT_NO_PAYLOAD_TYPE_TAG),
                   P1_CVOTE_INIT);
    assert_int_equal(g_last_response_swo, SWO_CVOTE_PARSING_FAIL_PAYLOAD_TYPE_TAG);
}

// ----------------------------------------------------------------------
// CHUNK parser failure tests
// ----------------------------------------------------------------------

static void test_cvote_chunk_rejects_wrong_size(void **state) {
    (void) state;
    reset_cvote_test_state();

    // Send a valid INIT that expects more chunks (total_len > first chunk)
    // total_len = 300 (> MAX_VOTECAST_CHUNK_SIZE=250), so first chunk = 250
    // but we only send CVOTE_INIT_VALID_SHORT (34 bytes) with a different length here.
    // Use a total_len of 300: first chunk must be exactly 250 bytes.
    // We send 34 bytes instead — wrong chunk size.
    static const uint8_t init_expecting_chunks[] = {
        0x00,
        0x00,
        0x01,
        0x2c,  // total_len = 300
        // First chunk must be 250 bytes but we only provide 34 bytes here.
        // This triggers the chunk-size mismatch check (line 82-87 in sign_cvote.c).
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };
    run_cvote_apdu(init_expecting_chunks, sizeof(init_expecting_chunks), P1_CVOTE_INIT);
    // This should fail because chunk_size (34) != expected (250)
    assert_int_equal(g_last_response_swo, SWO_WRONG_DATA_LENGTH);
}

static void test_cvote_chunk_rejects_wrong_size_in_chunk_phase(void **state) {
    (void) state;
    reset_cvote_test_state();

    // Build a valid INIT that expects a follow-up chunk:
    // total_len = 300, first chunk = 250 bytes
    static const uint8_t long_init[4 + 250] = {
        0x00,
        0x00,
        0x01,
        0x2c,  // total_len = 300
        // 250 bytes of chunk data (first 32 = vote_plan_id, then proposal_index, payload_type_tag,
        // rest padding) vote_plan_id (32 bytes)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,  // proposal_index
        0x00,  // payload_type_tag
        // remaining 216 bytes padding
    };
    run_cvote_apdu(long_init, sizeof(long_init), P1_CVOTE_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);

    // remaining_votecast_bytes = 300 - 250 = 50, so expected_chunk_size = 50.
    // Send only 10 bytes — wrong size.
    static const uint8_t bad_chunk[10] = {0};
    run_cvote_apdu(bad_chunk, sizeof(bad_chunk), P1_CVOTE_CHUNK);
    assert_int_equal(g_last_response_swo, SWO_WRONG_DATA_LENGTH);
}

// ----------------------------------------------------------------------
// CONFIRM parser failure tests
// ----------------------------------------------------------------------

static void test_cvote_confirm_rejects_truncated_path(void **state) {
    (void) state;
    reset_cvote_test_state();

    run_cvote_apdu(CVOTE_INIT_VALID_SHORT, sizeof(CVOTE_INIT_VALID_SHORT), P1_CVOTE_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);

    run_cvote_apdu(CVOTE_CONFIRM_TRUNCATED_PATH,
                   sizeof(CVOTE_CONFIRM_TRUNCATED_PATH),
                   P1_CVOTE_CONFIRM);
    assert_int_equal(g_last_response_swo, SWO_BIP44_PATH_PARSING_FAIL);
}

static void test_cvote_confirm_rejects_trailing_bytes(void **state) {
    (void) state;
    reset_cvote_test_state();

    run_cvote_apdu(CVOTE_INIT_VALID_SHORT, sizeof(CVOTE_INIT_VALID_SHORT), P1_CVOTE_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);

    run_cvote_apdu(CVOTE_CONFIRM_TRAILING_BYTE,
                   sizeof(CVOTE_CONFIRM_TRAILING_BYTE),
                   P1_CVOTE_CONFIRM);
    assert_int_equal(g_last_response_swo, SWO_WRONG_DATA_LENGTH);
}

// ----------------------------------------------------------------------
// Interleaving guard tests
// ----------------------------------------------------------------------

static void test_cvote_init_rejects_when_session_active(void **state) {
    (void) state;
    reset_cvote_test_state();
    // INIT when a session is already active (req_type != REQUEST_NONE).
    G_context.req_type = REQUEST_CVOTE;
    G_context.state.cvote_state = VOTECAST_STATE_CHUNK;
    run_cvote_apdu(CVOTE_INIT_VALID_SHORT, sizeof(CVOTE_INIT_VALID_SHORT), P1_CVOTE_INIT);
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
}

static void test_cvote_chunk_rejects_wrong_state(void **state) {
    (void) state;
    reset_cvote_test_state();

    // Send a valid INIT (total_len == chunk_size, so transitions to CONFIRM state)
    run_cvote_apdu(CVOTE_INIT_VALID_SHORT, sizeof(CVOTE_INIT_VALID_SHORT), P1_CVOTE_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    // State is now CONFIRM — send CHUNK when in CONFIRM state.
    run_cvote_apdu(CVOTE_INIT_VALID_SHORT, sizeof(CVOTE_INIT_VALID_SHORT), P1_CVOTE_CHUNK);
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
}

static void test_cvote_confirm_rejects_wrong_request_type(void **state) {
    (void) state;
    reset_cvote_test_state();
    // req_type is NONE — send CONFIRM without any INIT.
    run_cvote_apdu(CVOTE_CONFIRM_VALID_PATH, sizeof(CVOTE_CONFIRM_VALID_PATH), P1_CVOTE_CONFIRM);
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
}

static void test_cvote_confirm_rejects_wrong_state(void **state) {
    (void) state;
    reset_cvote_test_state();

    // Send a valid INIT that expects follow-up chunks (state -> CHUNK)
    static const uint8_t long_init[4 + 250] = {
        0x00, 0x00, 0x01, 0x2c,  // total_len = 300
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    run_cvote_apdu(long_init, sizeof(long_init), P1_CVOTE_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    // State is CHUNK — send CONFIRM when state is CHUNK.
    run_cvote_apdu(CVOTE_CONFIRM_VALID_PATH, sizeof(CVOTE_CONFIRM_VALID_PATH), P1_CVOTE_CONFIRM);
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
}

// ----------------------------------------------------------------------
// Main
// ----------------------------------------------------------------------

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_cvote_init_rejects_truncated_length_field),
        cmocka_unit_test(test_cvote_init_rejects_missing_vote_plan_id),
        cmocka_unit_test(test_cvote_init_rejects_missing_proposal_index),
        cmocka_unit_test(test_cvote_init_rejects_missing_payload_type_tag),
        cmocka_unit_test(test_cvote_chunk_rejects_wrong_size),
        cmocka_unit_test(test_cvote_chunk_rejects_wrong_size_in_chunk_phase),
        cmocka_unit_test(test_cvote_confirm_rejects_truncated_path),
        cmocka_unit_test(test_cvote_confirm_rejects_trailing_bytes),
        cmocka_unit_test(test_cvote_init_rejects_when_session_active),
        cmocka_unit_test(test_cvote_chunk_rejects_wrong_state),
        cmocka_unit_test(test_cvote_confirm_rejects_wrong_request_type),
        cmocka_unit_test(test_cvote_confirm_rejects_wrong_state),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
