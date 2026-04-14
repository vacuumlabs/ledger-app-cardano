/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Handcrafted unit tests for sign_msg handler parser and interleaving
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

#include "test_sign_msg_common.h"
#include "apdu_finalization_check.h"

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

static inline void run_sign_msg_apdu(const uint8_t *data, size_t len, uint8_t p1) {
    buffer_t buf = {.ptr = (uint8_t *) data, .size = len, .offset = 0};
    apdu_response_begin(INS_SIGN_MSG);
    handler_sign_msg(&buf, p1);
    apdu_response_assert_sent_or_deferred();
}

// ----------------------------------------------------------------------
// Minimal valid APDU payloads (no APDU header — handler receives cdata only)
//
// INIT format: [4B msgLength BE] [BIP44 path] [1B hashPayload] [1B isAscii] [1B addrFieldType]
// Path m/1852'/1815'/0'/0/1 encoded as: count=5 then 5 x 4-byte LE path elements.
//
// KEY_HASH (addrFieldType=0x02), msgLength=0, hashPayload=FLAG_INCLUDED_NO(0x01),
// isAscii=FLAG_INCLUDED_NO(0x01):
// ----------------------------------------------------------------------

// Valid INIT for an empty message (msgLength=0, KEY_HASH address field)
static const uint8_t SIGN_MSG_INIT_EMPTY_KEYHASH[] = {
    0x00, 0x00, 0x00, 0x00,  // msgLength = 0
    0x05,                    // path length = 5
    0x80, 0x00, 0x07, 0x3C,  // 1852'
    0x80, 0x00, 0x07, 0x17,  // 1815'
    0x80, 0x00, 0x00, 0x00,  // 0'
    0x00, 0x00, 0x00, 0x00,  // 0
    0x00, 0x00, 0x00, 0x01,  // 1
    0x01,                    // hashPayload = FLAG_INCLUDED_NO
    0x01,                    // isAscii = FLAG_INCLUDED_NO
    0x02,                    // addressFieldType = KEY_HASH
};

// Valid INIT for a 4-byte message (msgLength=4, KEY_HASH, non-hashed)
static const uint8_t SIGN_MSG_INIT_4BYTE_KEYHASH[] = {
    0x00, 0x00, 0x00, 0x04,  // msgLength = 4
    0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x01,  // hashPayload = FLAG_INCLUDED_NO
    0x01,  // isAscii = FLAG_INCLUDED_NO
    0x02,  // addressFieldType = KEY_HASH
};

// Valid INIT with trailing garbage byte appended
static const uint8_t SIGN_MSG_INIT_TRAILING_GARBAGE[] = {
    0x00, 0x00, 0x00, 0x00, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x02,
    0xFF,  // trailing garbage byte
};

// Valid CHUNK for a 4-byte message with one trailing garbage byte appended
static const uint8_t SIGN_MSG_CHUNK_4BYTE_TRAILING[] = {
    0x00,
    0x00,
    0x00,
    0x04,  // chunkSize = 4
    0xDE,
    0xAD,
    0xBE,
    0xEF,  // data
    0xFF,  // trailing garbage
};

// Valid CHUNK for a 4-byte message: [4B chunkSize BE] [4B data]
static const uint8_t SIGN_MSG_CHUNK_4BYTE[] = {
    0x00,
    0x00,
    0x00,
    0x04,  // chunkSize = 4
    0xDE,
    0xAD,
    0xBE,
    0xEF,  // data
};

// Truncated CHUNK: only the 4-byte size header, no data bytes
static const uint8_t SIGN_MSG_CHUNK_SIZE_HEADER_ONLY[] = {
    0x00,
    0x00,
    0x00,
    0x04,  // chunkSize = 4, but no data follows
};

// Empty CHUNK: zero bytes (cannot even read the 4-byte size header).
// Use a single-byte array but pass size=0 to the handler.
static const uint8_t SIGN_MSG_CHUNK_EMPTY_BUF[] = {0x00};
static const size_t SIGN_MSG_CHUNK_EMPTY_LEN = 0;

// ----------------------------------------------------------------------
// INIT trailing bytes test
// ----------------------------------------------------------------------

static void test_sign_msg_init_rejects_trailing_bytes(void **state) {
    (void) state;
    reset_sign_msg_test_state();
    run_sign_msg_apdu(SIGN_MSG_INIT_TRAILING_GARBAGE,
                      sizeof(SIGN_MSG_INIT_TRAILING_GARBAGE),
                      P1_SIGN_MSG_INIT);
    assert_int_equal(g_last_response_swo, SWO_WRONG_DATA_LENGTH);
}

// ----------------------------------------------------------------------
// Interleaving guard tests
// ----------------------------------------------------------------------

static void test_sign_msg_init_rejects_when_already_active(void **state) {
    (void) state;
    reset_sign_msg_test_state();
    // Send a valid INIT — session becomes active
    run_sign_msg_apdu(SIGN_MSG_INIT_EMPTY_KEYHASH,
                      sizeof(SIGN_MSG_INIT_EMPTY_KEYHASH),
                      P1_SIGN_MSG_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    // Send INIT again while session is active — must be rejected
    run_sign_msg_apdu(SIGN_MSG_INIT_EMPTY_KEYHASH,
                      sizeof(SIGN_MSG_INIT_EMPTY_KEYHASH),
                      P1_SIGN_MSG_INIT);
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
}

static void test_sign_msg_confirm_rejects_without_init(void **state) {
    (void) state;
    reset_sign_msg_test_state();
    // Send CONFIRM with no prior INIT (req_type == REQUEST_NONE).
    // Use a single-byte buf but pass size=0 — CONFIRM payload must be empty anyway.
    static const uint8_t placeholder[] = {0x00};
    run_sign_msg_apdu(placeholder, 0, P1_SIGN_MSG_CONFIRM);
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
}

static void test_sign_msg_chunk_rejects_when_in_confirm_state(void **state) {
    (void) state;
    reset_sign_msg_test_state();
    // INIT with a 4-byte message
    run_sign_msg_apdu(SIGN_MSG_INIT_4BYTE_KEYHASH,
                      sizeof(SIGN_MSG_INIT_4BYTE_KEYHASH),
                      P1_SIGN_MSG_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    // Send the single CHUNK — this exhausts remainingBytes, transitioning to CONFIRM state
    run_sign_msg_apdu(SIGN_MSG_CHUNK_4BYTE, sizeof(SIGN_MSG_CHUNK_4BYTE), P1_SIGN_MSG_CHUNK);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(G_context.state.sign_msg_state, SIGN_MSG_STATE_CONFIRM);
    // Send another CHUNK when already in CONFIRM state — must be rejected
    run_sign_msg_apdu(SIGN_MSG_CHUNK_4BYTE, sizeof(SIGN_MSG_CHUNK_4BYTE), P1_SIGN_MSG_CHUNK);
    assert_int_equal(g_last_response_swo, SWO_COMMAND_NOT_ALLOWED);
}

// ----------------------------------------------------------------------
// Truncated CHUNK tests
// ----------------------------------------------------------------------

static void test_sign_msg_chunk_rejects_truncated_after_size_header(void **state) {
    (void) state;
    reset_sign_msg_test_state();
    run_sign_msg_apdu(SIGN_MSG_INIT_4BYTE_KEYHASH,
                      sizeof(SIGN_MSG_INIT_4BYTE_KEYHASH),
                      P1_SIGN_MSG_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    // CHUNK has size header claiming 4 bytes but no data — buffer_can_read fails
    run_sign_msg_apdu(SIGN_MSG_CHUNK_SIZE_HEADER_ONLY,
                      sizeof(SIGN_MSG_CHUNK_SIZE_HEADER_ONLY),
                      P1_SIGN_MSG_CHUNK);
    assert_int_equal(g_last_response_swo, SWO_SIGN_MSG_PARSING_FAIL_CHUNK_DATA);
}

static void test_sign_msg_chunk_rejects_trailing_bytes(void **state) {
    (void) state;
    reset_sign_msg_test_state();
    run_sign_msg_apdu(SIGN_MSG_INIT_4BYTE_KEYHASH,
                      sizeof(SIGN_MSG_INIT_4BYTE_KEYHASH),
                      P1_SIGN_MSG_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    // CHUNK has correct size header and data but one trailing garbage byte — deny_unconsumed_bytes
    // fires
    run_sign_msg_apdu(SIGN_MSG_CHUNK_4BYTE_TRAILING,
                      sizeof(SIGN_MSG_CHUNK_4BYTE_TRAILING),
                      P1_SIGN_MSG_CHUNK);
    assert_int_equal(g_last_response_swo, SWO_WRONG_DATA_LENGTH);
}

static void test_sign_msg_chunk_rejects_missing_size_header(void **state) {
    (void) state;
    reset_sign_msg_test_state();
    run_sign_msg_apdu(SIGN_MSG_INIT_4BYTE_KEYHASH,
                      sizeof(SIGN_MSG_INIT_4BYTE_KEYHASH),
                      P1_SIGN_MSG_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    // CHUNK with zero bytes — buffer_read_u32 for chunk size fails
    run_sign_msg_apdu(SIGN_MSG_CHUNK_EMPTY_BUF, SIGN_MSG_CHUNK_EMPTY_LEN, P1_SIGN_MSG_CHUNK);
    assert_int_equal(g_last_response_swo, SWO_SIGN_MSG_PARSING_FAIL_CHUNK_SIZE);
}

// ----------------------------------------------------------------------
// Main
// ----------------------------------------------------------------------

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sign_msg_init_rejects_trailing_bytes),
        cmocka_unit_test(test_sign_msg_init_rejects_when_already_active),
        cmocka_unit_test(test_sign_msg_confirm_rejects_without_init),
        cmocka_unit_test(test_sign_msg_chunk_rejects_when_in_confirm_state),
        cmocka_unit_test(test_sign_msg_chunk_rejects_truncated_after_size_header),
        cmocka_unit_test(test_sign_msg_chunk_rejects_trailing_bytes),
        cmocka_unit_test(test_sign_msg_chunk_rejects_missing_size_header),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
