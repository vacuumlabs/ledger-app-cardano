/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <cmocka.h>

#include "apdu/dispatcher.h"
#include "app_context.h"
#include "buffer.h"
#include "cardano_constants.h"
#include "cardano_swo.h"
#include "globals.h"
#include "handler/sign_cvote.h"
#include "securityPolicy/securityPolicyType.h"
#include "test_fixture_types.h"
#include "mock_crypto/crypto_mock_data.h"
#include "app_mem_utils.h"
#include "io_capture.h"
#include "nbgl_mock.h"
#include "test_read_buffer_helpers.h"

// ----------------------------------------------------------------------
// Test state
// ----------------------------------------------------------------------

#define CVOTE_TEST_HEAP_SIZE (23 * 1024)
static uint8_t cvote_test_heap[CVOTE_TEST_HEAP_SIZE];

static inline void reset_cvote_test_state(void) {
    reset_app_context();
    io_capture_reset();
    nbgl_mock_reset();
    assert_true(mem_utils_init(cvote_test_heap, sizeof(cvote_test_heap)));
    G_context.state.cvote_state = VOTECAST_STATE_NONE;
    G_context.req_type = REQUEST_NONE;
}

// ----------------------------------------------------------------------
// Fixture runner
// ----------------------------------------------------------------------

static inline void run_cvote_fixture(const cvote_fixture_t *fixture) {
    assert_non_null(fixture);
    assert_non_null(fixture->init_data);
    assert_true(fixture->init_data_len > 0);
    assert_non_null(fixture->confirm_data);
    assert_true(fixture->confirm_data_len > 0);

    reset_cvote_test_state();
    reset_mock_signature_state();

    // Send INIT APDU
    test_read_buffer_t init_buffer =
        make_test_read_buffer(fixture->init_data, fixture->init_data_len);
    apdu_response_begin(INS_SIGN_CVOTE);
    handler_sign_cvote(&init_buffer.sdk_buffer, P1_CVOTE_INIT);
    apdu_response_finalize_after_handler();
    assert_read_buffer_unchanged_and_cleanup(&init_buffer, fixture->init_data);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);

    // Send CHUNK APDUs
    for (size_t chunk_idx = 0; chunk_idx < fixture->chunk_count; chunk_idx++) {
        const cvote_chunk_t *chunk = &fixture->chunks[chunk_idx];
        test_read_buffer_t chunk_buffer = make_test_read_buffer(chunk->data, chunk->data_len);
        apdu_response_begin(INS_SIGN_CVOTE);
        handler_sign_cvote(&chunk_buffer.sdk_buffer, P1_CVOTE_CHUNK);
        apdu_response_finalize_after_handler();
        assert_read_buffer_unchanged_and_cleanup(&chunk_buffer, chunk->data);
        assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    }

    // Send CONFIRM APDU (contains witness path; UI auto-confirms and calls finalize_sign_cvote)
    test_read_buffer_t confirm_buffer =
        make_test_read_buffer(fixture->confirm_data, fixture->confirm_data_len);
    apdu_response_begin(INS_SIGN_CVOTE);
    handler_sign_cvote(&confirm_buffer.sdk_buffer, P1_CVOTE_CONFIRM);
    apdu_response_finalize_after_handler();
    assert_read_buffer_unchanged_and_cleanup(&confirm_buffer, fixture->confirm_data);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);

    // Response: 32-byte votecast hash + 64-byte witness signature
    assert_int_equal(g_last_response_len, VOTECAST_HASH_LENGTH + ED25519_SIGNATURE_LENGTH);

    // Verify the signature was computed over the expected message
    assert_non_null(g_mock_last_signature_entry);
    assert_true(g_mock_last_signed_message_len > 0);
    assert_int_equal(g_mock_last_signed_message_len, g_mock_last_signature_entry->message_len);
    assert_memory_equal(g_mock_last_signed_message,
                        g_mock_last_signature_entry->message,
                        g_mock_last_signature_entry->message_len);

    if (fixture->expected_votecast_hash == NULL || fixture->expected_votecast_hash_len == 0 ||
        fixture->expected_witness_signature == NULL ||
        fixture->expected_witness_signature_len == 0) {
        fprintf(stderr, "UNIT_CAPTURE [%s] votecastHashHex=", fixture->name);
        for (size_t i = 0; i < VOTECAST_HASH_LENGTH; i++)
            fprintf(stderr, "%02x", g_last_response[i]);
        fprintf(stderr, "\n");
        fprintf(stderr, "UNIT_CAPTURE [%s] witnessSignatureHex=", fixture->name);
        for (size_t i = 0; i < ED25519_SIGNATURE_LENGTH; i++)
            fprintf(stderr, "%02x", g_last_response[VOTECAST_HASH_LENGTH + i]);
        fprintf(stderr, "\n");
        fail_msg("Missing unit expected result for cvote fixture '%s'", fixture->name);
    }

    assert_int_equal(fixture->expected_votecast_hash_len, VOTECAST_HASH_LENGTH);
    assert_memory_equal(g_last_response,
                        fixture->expected_votecast_hash,
                        fixture->expected_votecast_hash_len);
    assert_int_equal(fixture->expected_witness_signature_len, ED25519_SIGNATURE_LENGTH);
    assert_memory_equal(g_last_response + VOTECAST_HASH_LENGTH,
                        fixture->expected_witness_signature,
                        fixture->expected_witness_signature_len);
}

// ----------------------------------------------------------------------
// Deny fixture runner
// ----------------------------------------------------------------------

static inline void run_cvote_deny_fixture(const cvote_deny_fixture_t *fixture) {
    assert_non_null(fixture);
    reset_cvote_test_state();
    reset_mock_signature_state();

    if (fixture->phase == CVOTE_DENY_PHASE_CHUNK) {
        // Send CHUNK without prior INIT — should fail immediately.
        buffer_t buf = {
            .ptr = (uint8_t *) fixture->apdu_data,
            .size = fixture->apdu_data_len,
            .offset = 0,
        };
        apdu_response_begin(INS_SIGN_CVOTE);
        handler_sign_cvote(&buf, P1_CVOTE_CHUNK);
        apdu_response_finalize_after_handler();
        assert_int_equal(g_last_response_swo, fixture->expected_swo);
        return;
    }

    if (fixture->phase == CVOTE_DENY_PHASE_INIT) {
        // Malformed INIT payload — should fail during INIT.
        buffer_t buf = {
            .ptr = (uint8_t *) fixture->apdu_data,
            .size = fixture->apdu_data_len,
            .offset = 0,
        };
        apdu_response_begin(INS_SIGN_CVOTE);
        handler_sign_cvote(&buf, P1_CVOTE_INIT);
        apdu_response_finalize_after_handler();
        assert_int_equal(g_last_response_swo, fixture->expected_swo);
        return;
    }

    // CVOTE_DENY_PHASE_CONFIRM: valid INIT + optional chunks, then malformed CONFIRM.
    assert_non_null(fixture->apdu_data);
    assert_true(fixture->apdu_data_len > 0);
    buffer_t init_buf = {
        .ptr = (uint8_t *) fixture->apdu_data,
        .size = fixture->apdu_data_len,
        .offset = 0,
    };
    apdu_response_begin(INS_SIGN_CVOTE);
    handler_sign_cvote(&init_buf, P1_CVOTE_INIT);
    apdu_response_finalize_after_handler();
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);

    for (size_t chunk_idx = 0; chunk_idx < fixture->chunk_count; chunk_idx++) {
        const cvote_chunk_t *chunk = &fixture->chunks[chunk_idx];
        buffer_t chunk_buf = {
            .ptr = (uint8_t *) chunk->data,
            .size = chunk->data_len,
            .offset = 0,
        };
        apdu_response_begin(INS_SIGN_CVOTE);
        handler_sign_cvote(&chunk_buf, P1_CVOTE_CHUNK);
        apdu_response_finalize_after_handler();
        assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    }

    assert_non_null(fixture->confirm_data);
    assert_true(fixture->confirm_data_len > 0);
    buffer_t confirm_buf = {
        .ptr = (uint8_t *) fixture->confirm_data,
        .size = fixture->confirm_data_len,
        .offset = 0,
    };
    apdu_response_begin(INS_SIGN_CVOTE);
    handler_sign_cvote(&confirm_buf, P1_CVOTE_CONFIRM);
    apdu_response_finalize_after_handler();
    assert_int_equal(g_last_response_swo, fixture->expected_swo);
}
