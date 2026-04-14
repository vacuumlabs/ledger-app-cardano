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
#include "handler/sign_msg.h"
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

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static inline void reset_sign_msg_test_state(void) {
    reset_app_context();
    io_capture_reset();
    nbgl_mock_reset();
    assert_true(mem_utils_init(test_heap, sizeof(test_heap)));
    G_context.state.sign_msg_state = SIGN_MSG_STATE_NONE;
    G_context.req_type = REQUEST_NONE;
}

static inline void print_sign_msg_expected_capture(const sign_msg_fixture_t *fixture,
                                                   const uint8_t *signature,
                                                   const uint8_t *public_key,
                                                   const uint8_t *address_field,
                                                   size_t address_field_len) {
    fprintf(stderr, "UNIT_CAPTURE [%s] signatureHex=", fixture->name);
    for (size_t i = 0; i < ED25519_SIGNATURE_LENGTH; i++) fprintf(stderr, "%02x", signature[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "UNIT_CAPTURE [%s] signingPublicKeyHex=", fixture->name);
    for (size_t i = 0; i < PUBLIC_KEY_LENGTH; i++) fprintf(stderr, "%02x", public_key[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "UNIT_CAPTURE [%s] addressFieldHex=", fixture->name);
    for (size_t i = 0; i < address_field_len; i++) fprintf(stderr, "%02x", address_field[i]);
    fprintf(stderr, "\n");
}

// ----------------------------------------------------------------------
// Fixture runner
// ----------------------------------------------------------------------

static inline void run_fixture(const sign_msg_fixture_t *fixture) {
    assert_non_null(fixture);
    assert_non_null(fixture->init_data);
    assert_true(fixture->init_data_len > 0);
    if (fixture->confirm_data_len > 0) {
        assert_non_null(fixture->confirm_data);
    }
    reset_sign_msg_test_state();
    reset_mock_signature_state();

    test_read_buffer_t init_buffer =
        make_test_read_buffer(fixture->init_data, fixture->init_data_len);
    apdu_response_begin(INS_SIGN_MSG);
    handler_sign_msg(&init_buffer.sdk_buffer, P1_SIGN_MSG_INIT);
    apdu_response_finalize_after_handler();
    assert_read_buffer_unchanged_and_cleanup(&init_buffer, fixture->init_data);
    assert_int_equal(g_last_response_swo, fixture->check_expected);
    assert_int_equal(G_context.sign_msg_info.warnings, fixture->expected_warning_bits);

    for (size_t chunk_idx = 0; chunk_idx < fixture->chunk_count; chunk_idx++) {
        const sign_msg_chunk_t *chunk = &fixture->chunks[chunk_idx];
        test_read_buffer_t chunk_buffer = make_test_read_buffer(chunk->data, chunk->data_len);
        apdu_response_begin(INS_SIGN_MSG);
        handler_sign_msg(&chunk_buffer.sdk_buffer, P1_SIGN_MSG_CHUNK);
        apdu_response_finalize_after_handler();
        assert_read_buffer_unchanged_and_cleanup(&chunk_buffer, chunk->data);
        assert_int_equal(g_last_response_swo, fixture->check_expected);
    }

    test_read_buffer_t confirm_buffer =
        make_test_read_buffer(fixture->confirm_data, fixture->confirm_data_len);
    apdu_response_begin(INS_SIGN_MSG);
    handler_sign_msg(&confirm_buffer.sdk_buffer, P1_SIGN_MSG_CONFIRM);
    apdu_response_finalize_after_handler();
    assert_read_buffer_unchanged_and_cleanup(&confirm_buffer, fixture->confirm_data);
    assert_int_equal(g_last_response_swo, fixture->check_expected);

    assert_true(g_last_response_len > 0);

    assert_non_null(g_mock_last_signature_entry);
    assert_true(g_mock_last_signed_message_len > 0);
    assert_int_equal(g_mock_last_signed_message_len, g_mock_last_signature_entry->message_len);
    assert_memory_equal(g_mock_last_signed_message,
                        g_mock_last_signature_entry->message,
                        g_mock_last_signature_entry->message_len);

    const uint8_t *response_ptr = g_last_response;
    assert_true(g_last_response_len >= ED25519_SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + 4);

    const uint8_t *signed_message_signature = response_ptr;
    const uint8_t *signed_message_public_key = signed_message_signature + ED25519_SIGNATURE_LENGTH;
    const uint8_t *address_length_ptr = signed_message_public_key + PUBLIC_KEY_LENGTH;

    const size_t address_field_len =
        ((size_t) address_length_ptr[0] << 24) | ((size_t) address_length_ptr[1] << 16) |
        ((size_t) address_length_ptr[2] << 8) | (size_t) address_length_ptr[3];

    const uint8_t *address_field = address_length_ptr + 4;
    assert_true(g_last_response_len >=
                ED25519_SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + 4 + address_field_len);

    if (fixture->expected == NULL) {
        print_sign_msg_expected_capture(fixture,
                                        signed_message_signature,
                                        signed_message_public_key,
                                        address_field,
                                        address_field_len);
        fail_msg("Missing unit expected result for sign_msg fixture '%s'", fixture->name);
    }

    assert_int_equal(fixture->expected->signature_len, ED25519_SIGNATURE_LENGTH);
    assert_memory_equal(signed_message_signature,
                        fixture->expected->signature,
                        fixture->expected->signature_len);
    assert_int_equal(fixture->expected->public_key_len, PUBLIC_KEY_LENGTH);
    assert_memory_equal(signed_message_public_key,
                        fixture->expected->public_key,
                        fixture->expected->public_key_len);
    assert_int_equal(fixture->expected->address_field_len, address_field_len);
    assert_memory_equal(address_field,
                        fixture->expected->address_field,
                        fixture->expected->address_field_len);
}
