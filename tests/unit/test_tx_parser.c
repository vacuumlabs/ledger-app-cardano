/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "globals.h"
#include "sign_tx_ctx.h"
#include "tx_parse.h"
#include "tx_constants.h"
#include "cardano_constants.h"
#include "cardano_swo.h"
#include "mem.h"
#include "app_context.h"

void tx_handle_parse_error(uint16_t swo);
void tx_processing_setup_state(const tx_processing_mode_t *mode, warning_bits_t *warning_bits);
bool tx_process_inputs(buffer_t *buf, tx_processing_state_t *state);
bool tx_process_collateral_inputs(buffer_t *buf, tx_processing_state_t *state);
bool tx_process_required_signers(buffer_t *buf, tx_processing_state_t *state);
bool tx_process_reference_inputs(buffer_t *buf, tx_processing_state_t *state);

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];
static uint16_t g_last_swo = 0;

static inline bool test_mem_init(void) {
    return mem_utils_init(test_heap, sizeof(test_heap));
}

static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    // Set body-stage state so tx_body_ctx() accessor assertions pass in tests.
    G_context.state.tx_state = TX_STATE_CHUNKS;
    g_last_swo = 0;
    assert_true(test_mem_init());
}

int io_send_sw(uint16_t swo) {
    g_last_swo = swo;
    return 0;
}

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    (void) buffer;
    (void) bufferLength;
    g_last_swo = swo;
    return 0;
}

static void test_parse_tx_fails_on_missing_inputs(void **state) {
    (void) state;
    reset_test_context();

    uint8_t empty_tx = 0;
    // num_inputs=0 with ORDINARY_TX would be denied by policyForSignTxInit (no inputs = no replay
    // protection). Use num_inputs=1 so init policy passes; the empty buffer then fails at inputs.
    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.networkId = MAINNET_NETWORK_ID;
    G_context.tx_info.tx_params.protocolMagic = MAINNET_PROTOCOL_MAGIC;
    G_context.tx_info.tx_params.num_inputs = 1;
    G_context.tx_info.tx_params.num_outputs = 0;
    tx_body_ctx()->raw_tx = &empty_tx;
    G_context.tx_info.raw_tx_total_length = 0;
    tx_body_ctx()->raw_tx_current_length = 0;
    apdu_response_begin(INS_SIGN_TX);
    bool ok = tx_validate();
    apdu_response_finalize_after_handler();
    assert_false(ok);
    assert_int_equal(g_last_swo, SWO_TX_PARSING_FAIL_INPUTS);
}

static void test_parse_tx_rejects_oversized_buffer(void **state) {
    (void) state;
    reset_test_context();

    apdu_response_begin(INS_SIGN_TX);
    tx_handle_parse_error(SWO_INVALID_TX_LENGTH);
    apdu_response_finalize_after_handler();
    assert_int_equal(g_last_swo, SWO_INVALID_TX_LENGTH);
}

static void test_parse_error_mapping_fee(void **state) {
    (void) state;
    reset_test_context();

    apdu_response_begin(INS_SIGN_TX);
    tx_handle_parse_error(SWO_TX_PARSING_FAIL_FEE);
    apdu_response_finalize_after_handler();
    assert_int_equal(g_last_swo, SWO_TX_PARSING_FAIL_FEE);
}

static void test_parse_error_mapping_buffer_not_fully_consumed(void **state) {
    (void) state;
    reset_test_context();

    apdu_response_begin(INS_SIGN_TX);
    tx_handle_parse_error(SWO_TX_PARSING_FAIL_BUFFER_NOT_FULLY_CONSUMED);
    apdu_response_finalize_after_handler();
    assert_int_equal(g_last_swo, SWO_TX_PARSING_FAIL_BUFFER_NOT_FULLY_CONSUMED);
}

static void test_process_inputs_field_pass1_success(void **state) {
    (void) state;
    reset_test_context();

    uint8_t raw_input[TX_HASH_LENGTH + sizeof(uint32_t)] = {0};
    for (size_t i = 0; i < TX_HASH_LENGTH; i++) {
        raw_input[i] = (uint8_t) (i + 1);
    }
    raw_input[TX_HASH_LENGTH + 0] = 0x00;
    raw_input[TX_HASH_LENGTH + 1] = 0x00;
    raw_input[TX_HASH_LENGTH + 2] = 0x00;
    raw_input[TX_HASH_LENGTH + 3] = 0x2A;

    buffer_t buf = {
        .ptr = raw_input,
        .size = sizeof(raw_input),
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_PLUTUS_TX;
    G_context.tx_info.tx_params.num_inputs = 1;

    tx_processing_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .ui_count_pairs = true,
        .ui_render = false,
    };
    warning_bits_t warnings = 0;
    tx_processing_setup_state(&mode, &warnings);

    bool ok = tx_process_inputs(&buf, &tx_body_ctx()->processing_state);
    assert_true(ok);
    assert_int_equal(buf.offset, sizeof(raw_input));
    assert_int_equal(tx_body_ctx()->total_ui_pairs, 0);  // ordinary mode hides inputs
}

static void test_process_inputs_field_parse_error_sends_inputs_swo(void **state) {
    (void) state;
    reset_test_context();

    uint8_t too_short_input[TX_HASH_LENGTH + sizeof(uint32_t) - 1] = {0};
    buffer_t buf = {
        .ptr = too_short_input,
        .size = sizeof(too_short_input),
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_PLUTUS_TX;
    G_context.tx_info.tx_params.num_inputs = 1;

    tx_processing_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .ui_count_pairs = true,
        .ui_render = false,
    };
    warning_bits_t warnings = 0;
    tx_processing_setup_state(&mode, &warnings);

    apdu_response_begin(INS_SIGN_TX);
    bool ok = tx_process_inputs(&buf, &tx_body_ctx()->processing_state);
    apdu_response_finalize_after_handler();
    assert_false(ok);
    assert_int_equal(g_last_swo, SWO_TX_PARSING_FAIL_INPUTS);
}

static void test_process_collateral_inputs_field_pass1_success(void **state) {
    (void) state;
    reset_test_context();

    uint8_t raw_input[TX_HASH_LENGTH + sizeof(uint32_t)] = {0};
    raw_input[TX_HASH_LENGTH + 3] = 0x2A;

    buffer_t buf = {
        .ptr = raw_input,
        .size = sizeof(raw_input),
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_PLUTUS_TX;
    G_context.tx_info.tx_params.num_collateral_inputs = 1;

    tx_processing_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .ui_count_pairs = true,
        .ui_render = false,
    };
    warning_bits_t warnings = 0;
    tx_processing_setup_state(&mode, &warnings);

    bool ok = tx_process_collateral_inputs(&buf, &tx_body_ctx()->processing_state);
    assert_true(ok);
    assert_int_equal(buf.offset, sizeof(raw_input));
    assert_int_equal(tx_body_ctx()->total_ui_pairs, 0);  // non-expert mode hides collateral inputs
}

static void test_process_reference_inputs_field_parse_error_sends_reference_swo(void **state) {
    (void) state;
    reset_test_context();

    uint8_t too_short_input[TX_HASH_LENGTH + sizeof(uint32_t) - 1] = {0};
    buffer_t buf = {
        .ptr = too_short_input,
        .size = sizeof(too_short_input),
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.num_reference_inputs = 1;

    tx_processing_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .ui_count_pairs = true,
        .ui_render = false,
    };
    warning_bits_t warnings = 0;
    tx_processing_setup_state(&mode, &warnings);

    apdu_response_begin(INS_SIGN_TX);
    bool ok = tx_process_reference_inputs(&buf, &tx_body_ctx()->processing_state);
    apdu_response_finalize_after_handler();
    assert_false(ok);
    assert_int_equal(g_last_swo, SWO_TX_PARSING_FAIL_REFERENCE_INPUTS);
}

static void test_process_required_signers_field_pass1_success(void **state) {
    (void) state;
    reset_test_context();

    uint8_t raw_signer[1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    raw_signer[0] = REQUIRED_SIGNER_WITH_HASH;
    for (size_t i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
        raw_signer[1 + i] = (uint8_t) (0xA0 + i);
    }

    buffer_t buf = {
        .ptr = raw_signer,
        .size = sizeof(raw_signer),
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.num_required_signers = 1;

    tx_processing_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .ui_count_pairs = true,
        .ui_render = false,
    };
    warning_bits_t warnings = 0;
    tx_processing_setup_state(&mode, &warnings);

    bool ok = tx_process_required_signers(&buf, &tx_body_ctx()->processing_state);
    assert_true(ok);
    assert_int_equal(buf.offset, sizeof(raw_signer));
    assert_int_equal(tx_body_ctx()->total_ui_pairs, 0);  // non-expert mode hides required signers
}

static void test_process_required_signers_field_parse_error_sends_required_swo(void **state) {
    (void) state;
    reset_test_context();

    uint8_t invalid_required_signer_type = 0xFF;
    buffer_t buf = {
        .ptr = &invalid_required_signer_type,
        .size = sizeof(invalid_required_signer_type),
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.num_required_signers = 1;

    tx_processing_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .ui_count_pairs = true,
        .ui_render = false,
    };
    warning_bits_t warnings = 0;
    tx_processing_setup_state(&mode, &warnings);

    apdu_response_begin(INS_SIGN_TX);
    bool ok = tx_process_required_signers(&buf, &tx_body_ctx()->processing_state);
    apdu_response_finalize_after_handler();
    assert_false(ok);
    assert_int_equal(g_last_swo, SWO_TX_PARSING_FAIL_REQUIRED_SIGNERS);
}

static void test_mode_allows_rendering_with_validation(void **state) {
    (void) state;
    reset_test_context();

    uint8_t empty = 0;
    buffer_t buf = {
        .ptr = &empty,
        .size = 0,
        .offset = 0,
    };

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.num_inputs = 0;

    tx_processing_mode_t mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .ui_count_pairs = false,
        .ui_render = true,
    };
    warning_bits_t warnings = 0;
    tx_processing_setup_state(&mode, &warnings);

    bool ok = tx_process_inputs(&buf, &tx_body_ctx()->processing_state);
    assert_true(ok);
}

static void test_validate_from_raw_success(void **state) {
    (void) state;
    reset_test_context();

    uint8_t raw_tx[91] = {0};
    size_t offset = 0;

    // key 0: one input (tx hash + index)
    for (size_t i = 0; i < TX_HASH_LENGTH; i++) {
        raw_tx[offset++] = (uint8_t) (0x10 + i);
    }
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x01;

    // key 1: one output, prefixed by output payload length (45 bytes)
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x2D;
    // destination type: third-party
    raw_tx[offset++] = DESTINATION_THIRD_PARTY;
    // address length: 29 bytes
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x1D;
    // enterprise key address header (mainnet) + key hash bytes
    raw_tx[offset++] = 0x61;
    for (size_t i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
        raw_tx[offset++] = (uint8_t) (0x40 + i);
    }
    // ADA amount
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x16;
    raw_tx[offset++] = 0xE3;
    raw_tx[offset++] = 0x60;  // 1_500_000
    // output format
    raw_tx[offset++] = ARRAY_LEGACY;
    // datum absent
    raw_tx[offset++] = 1;  // FLAG_INCLUDED_NO
    // ref script absent
    raw_tx[offset++] = 1;  // FLAG_INCLUDED_NO
    // num asset groups
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;

    // key 2: fee
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x02;
    raw_tx[offset++] = 0x97;
    raw_tx[offset++] = 0xB0;  // 170_000

    assert_int_equal(offset, sizeof(raw_tx));

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.networkId = MAINNET_NETWORK_ID;
    G_context.tx_info.tx_params.protocolMagic = MAINNET_PROTOCOL_MAGIC;
    G_context.tx_info.tx_params.num_inputs = 1;
    G_context.tx_info.tx_params.num_outputs = 1;
    G_context.tx_info.tx_params.includeTtl = false;
    tx_body_ctx()->raw_tx = raw_tx;
    G_context.tx_info.raw_tx_total_length = sizeof(raw_tx);
    tx_body_ctx()->raw_tx_current_length = sizeof(raw_tx);

    bool ok = tx_validate();

    assert_true(ok);
    assert_true(tx_body_ctx()->total_ui_pairs >= (UI_PAIRS_OUTPUT_BASE + UI_PAIRS_FEE));

    bool hash_nonzero = false;
    for (size_t i = 0; i < TX_HASH_LENGTH; i++) {
        if (G_context.tx_info.tx_hash[i] != 0) {
            hash_nonzero = true;
            break;
        }
    }
    assert_true(hash_nonzero);
}

static void test_validate_fails_on_truncated_fee(void **state) {
    (void) state;
    reset_test_context();

    uint8_t raw_tx[TX_HASH_LENGTH + 4 + 2 + 45 + 4] = {0};  // inputs + outputs + 4 bytes of fee
    size_t offset = 0;
    // one input
    offset += TX_HASH_LENGTH + 4;
    // one output (45 bytes)
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x2D;  // output total length
    // destination type: third-party
    raw_tx[offset++] = DESTINATION_THIRD_PARTY;
    // address length: 29 bytes
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x1D;
    // address bytes
    for (size_t i = 0; i < 29; i++) {
        raw_tx[offset++] = (uint8_t) (0x40 + i);
    }
    // ADA amount (8 bytes)
    for (int i = 0; i < 8; i++) raw_tx[offset++] = 0x00;
    // output format
    raw_tx[offset++] = ARRAY_LEGACY;
    // datum absent
    raw_tx[offset++] = 1;  // FLAG_INCLUDED_NO
    // ref script absent
    raw_tx[offset++] = 1;  // FLAG_INCLUDED_NO
    // num asset groups
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    // fee (truncated: only 4 bytes instead of 8)
    offset += 4;

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.num_inputs = 1;
    G_context.tx_info.tx_params.num_outputs = 1;
    tx_body_ctx()->raw_tx = raw_tx;
    G_context.tx_info.raw_tx_total_length = offset;
    tx_body_ctx()->raw_tx_current_length = offset;

    apdu_response_begin(INS_SIGN_TX);
    bool ok = tx_validate();
    apdu_response_finalize_after_handler();
    assert_false(ok);
    assert_int_equal(g_last_swo, SWO_TX_PARSING_FAIL_FEE);
}

static void test_validate_fails_on_truncated_ttl(void **state) {
    (void) state;
    reset_test_context();

    uint8_t raw_tx[TX_HASH_LENGTH + 4 + 2 + 45 + 8 + 4] = {
        0};  // inputs + outputs + fee + 4 bytes of ttl
    size_t offset = 0;
    offset += TX_HASH_LENGTH + 4;  // input
    // one output (45 bytes)
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x2D;  // output total length
    // destination type: third-party
    raw_tx[offset++] = DESTINATION_THIRD_PARTY;
    // address length: 29 bytes
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x1D;
    // address bytes
    for (size_t i = 0; i < 29; i++) {
        raw_tx[offset++] = (uint8_t) (0x40 + i);
    }
    // ADA amount (8 bytes)
    for (int i = 0; i < 8; i++) raw_tx[offset++] = 0x00;
    // output format
    raw_tx[offset++] = ARRAY_LEGACY;
    // datum absent
    raw_tx[offset++] = 1;  // FLAG_INCLUDED_NO
    // ref script absent
    raw_tx[offset++] = 1;  // FLAG_INCLUDED_NO
    // num asset groups
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    offset += 8;  // fee
    // ttl (truncated: only 4 bytes instead of 8)
    offset += 4;

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.num_inputs = 1;
    G_context.tx_info.tx_params.num_outputs = 1;
    G_context.tx_info.tx_params.includeTtl = true;
    tx_body_ctx()->raw_tx = raw_tx;
    G_context.tx_info.raw_tx_total_length = offset;
    tx_body_ctx()->raw_tx_current_length = offset;

    apdu_response_begin(INS_SIGN_TX);
    bool ok = tx_validate();
    apdu_response_finalize_after_handler();
    assert_false(ok);
    assert_int_equal(g_last_swo, SWO_TX_PARSING_FAIL_TTL);
}

static void test_validate_fails_on_truncated_withdrawals(void **state) {
    (void) state;
    reset_test_context();

    uint8_t raw_tx[TX_HASH_LENGTH + 4 + 2 + 45 + 8 + 4] = {0};
    size_t offset = 0;
    offset += TX_HASH_LENGTH + 4;  // input
    // one output (45 bytes)
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x2D;  // output total length
    // destination type: third-party
    raw_tx[offset++] = DESTINATION_THIRD_PARTY;
    // address length: 29 bytes
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x1D;
    // address bytes
    for (size_t i = 0; i < 29; i++) {
        raw_tx[offset++] = (uint8_t) (0x40 + i);
    }
    // ADA amount (8 bytes)
    for (int i = 0; i < 8; i++) raw_tx[offset++] = 0x00;
    // output format
    raw_tx[offset++] = ARRAY_LEGACY;
    // datum absent
    raw_tx[offset++] = 1;  // FLAG_INCLUDED_NO
    // ref script absent
    raw_tx[offset++] = 1;  // FLAG_INCLUDED_NO
    // num asset groups
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    offset += 8;  // fee
    // withdrawal: only 4 bytes of amount, credential missing
    offset += 4;

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.num_inputs = 1;
    G_context.tx_info.tx_params.num_outputs = 1;
    G_context.tx_info.tx_params.num_withdrawals = 1;
    tx_body_ctx()->raw_tx = raw_tx;
    G_context.tx_info.raw_tx_total_length = offset;
    tx_body_ctx()->raw_tx_current_length = offset;

    apdu_response_begin(INS_SIGN_TX);
    bool ok = tx_validate();
    apdu_response_finalize_after_handler();
    assert_false(ok);
    assert_int_equal(g_last_swo, SWO_TX_PARSING_FAIL_WITHDRAWALS);
}

static void test_validate_from_raw_with_tokens_and_mint_success(void **state) {
    (void) state;
    reset_test_context();

    uint8_t raw_tx[171] = {0};
    size_t offset = 0;

    // key 0: one input (tx hash + index)
    for (size_t i = 0; i < TX_HASH_LENGTH; i++) {
        raw_tx[offset++] = (uint8_t) (0x20 + i);
    }
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x02;

    // key 1: one output, payload length 85
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x55;
    raw_tx[offset++] = DESTINATION_THIRD_PARTY;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x1D;
    raw_tx[offset++] = 0x61;  // enterprise key address header (mainnet)
    for (size_t i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
        raw_tx[offset++] = (uint8_t) (0x60 + i);
    }
    // ADA amount
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x1E;
    raw_tx[offset++] = 0x84;
    raw_tx[offset++] = 0x80;  // 2_000_000
    raw_tx[offset++] = ARRAY_LEGACY;
    raw_tx[offset++] = 1;  // datum absent
    raw_tx[offset++] = 1;  // ref script absent
    // one asset group
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x01;
    for (size_t i = 0; i < MINTING_POLICY_ID_LENGTH; i++) {
        raw_tx[offset++] = (uint8_t) (0x80 + i);
    }
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x01;  // one token
    raw_tx[offset++] = 0x01;  // asset name len
    raw_tx[offset++] = 0xAA;  // asset name
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x64;  // output token amount = 100

    // key 2: fee
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x03;
    raw_tx[offset++] = 0x0D;
    raw_tx[offset++] = 0x40;  // 200_000

    // key 9: mint (one asset group, one token amount +5)
    for (size_t i = 0; i < MINTING_POLICY_ID_LENGTH; i++) {
        raw_tx[offset++] = (uint8_t) (0x80 + i);
    }
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x01;
    raw_tx[offset++] = 0x01;
    raw_tx[offset++] = 0xAA;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x00;
    raw_tx[offset++] = 0x05;

    assert_int_equal(offset, sizeof(raw_tx));

    G_context.tx_info.tx_params.txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX;
    G_context.tx_info.tx_params.networkId = MAINNET_NETWORK_ID;
    G_context.tx_info.tx_params.protocolMagic = MAINNET_PROTOCOL_MAGIC;
    G_context.tx_info.tx_params.num_inputs = 1;
    G_context.tx_info.tx_params.num_outputs = 1;
    G_context.tx_info.tx_params.includeTtl = false;
    G_context.tx_info.tx_params.num_mint_asset_groups = 1;
    tx_body_ctx()->raw_tx = raw_tx;
    G_context.tx_info.raw_tx_total_length = sizeof(raw_tx);
    tx_body_ctx()->raw_tx_current_length = sizeof(raw_tx);

    bool ok = tx_validate();

    assert_true(ok);
    assert_int_equal(tx_body_ctx()->total_ui_pairs,
                     9);  // output base + output token + fee + mint summary + mint token
}

// ---------------------------------------------------------------------------
// parse_required_signer error paths
// ---------------------------------------------------------------------------

static void test_parse_required_signer_truncated_type(void **state) {
    (void) state;
    // Empty buffer: buffer_read_u8 fails on the type byte.
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    required_signer_t out;
    assert_false(parse_required_signer(&buf, &out));
}

static void test_parse_required_signer_path_truncated(void **state) {
    (void) state;
    // Type byte present (REQUIRED_SIGNER_WITH_PATH=0) but no path data follows.
    uint8_t buf_data[1] = {REQUIRED_SIGNER_WITH_PATH};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    required_signer_t out;
    assert_false(parse_required_signer(&buf, &out));
}

static void test_parse_required_signer_hash_truncated(void **state) {
    (void) state;
    // Type byte present (REQUIRED_SIGNER_WITH_HASH=1) but no hash bytes follow.
    uint8_t buf_data[1] = {REQUIRED_SIGNER_WITH_HASH};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    required_signer_t out;
    assert_false(parse_required_signer(&buf, &out));
}

// ---------------------------------------------------------------------------
// parse_voter_votes_header error paths
// ---------------------------------------------------------------------------

static void test_parse_voter_votes_header_truncated_type(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    ext_voter_t voter;
    uint16_t num_votes;
    assert_false(parse_voter_votes_header(&buf, &voter, &num_votes));
}

static void test_parse_voter_votes_header_unknown_type(void **state) {
    (void) state;
    // 0xFF is not a valid ext_voter_type_t value.
    uint8_t buf_data[1] = {0xFF};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    ext_voter_t voter;
    uint16_t num_votes;
    assert_false(parse_voter_votes_header(&buf, &voter, &num_votes));
}

static void test_parse_voter_votes_header_path_truncated(void **state) {
    (void) state;
    // EXT_VOTER_DREP_KEY_PATH=102 — path data missing.
    uint8_t buf_data[1] = {(uint8_t) EXT_VOTER_DREP_KEY_PATH};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    ext_voter_t voter;
    uint16_t num_votes;
    assert_false(parse_voter_votes_header(&buf, &voter, &num_votes));
}

static void test_parse_voter_votes_header_key_hash_truncated(void **state) {
    (void) state;
    // EXT_VOTER_DREP_KEY_HASH=2 — hash bytes missing.
    uint8_t buf_data[1] = {(uint8_t) EXT_VOTER_DREP_KEY_HASH};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    ext_voter_t voter;
    uint16_t num_votes;
    assert_false(parse_voter_votes_header(&buf, &voter, &num_votes));
}

static void test_parse_voter_votes_header_script_hash_truncated(void **state) {
    (void) state;
    // EXT_VOTER_DREP_SCRIPT_HASH=3 — script hash bytes missing.
    uint8_t buf_data[1] = {(uint8_t) EXT_VOTER_DREP_SCRIPT_HASH};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    ext_voter_t voter;
    uint16_t num_votes;
    assert_false(parse_voter_votes_header(&buf, &voter, &num_votes));
}

static void test_parse_voter_votes_header_num_votes_truncated(void **state) {
    (void) state;
    // EXT_VOTER_STAKE_POOL_KEY_HASH=4 with full hash, but num_votes u16 missing.
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    buf_data[0] = (uint8_t) EXT_VOTER_STAKE_POOL_KEY_HASH;
    // hash bytes left as zero — valid pointer-read (buffer_read_bytes_ptr pointer only)
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    ext_voter_t voter;
    uint16_t num_votes;
    assert_false(parse_voter_votes_header(&buf, &voter, &num_votes));
}

static void test_parse_voter_votes_header_zero_votes(void **state) {
    (void) state;
    // Valid hash voter, but num_votes == 0 must be rejected.
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 2] = {0};
    buf_data[0] = (uint8_t) EXT_VOTER_STAKE_POOL_KEY_HASH;
    // hash: 28 zero bytes (valid buffer pointer)
    buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 0] = 0x00;  // num_votes high byte
    buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 1] = 0x00;  // num_votes low byte  -> 0
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    ext_voter_t voter;
    uint16_t num_votes;
    assert_false(parse_voter_votes_header(&buf, &voter, &num_votes));
}

// ---------------------------------------------------------------------------
// parse_vote error paths
// ---------------------------------------------------------------------------

static void test_parse_vote_truncated_tx_hash(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    vote_item_t item;
    assert_false(parse_vote(&buf, &item));
}

static void test_parse_vote_truncated_gov_action_index(void **state) {
    (void) state;
    uint8_t buf_data[TX_HASH_LENGTH] = {0};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    vote_item_t item;
    assert_false(parse_vote(&buf, &item));
}

static void test_parse_vote_truncated_vote_option(void **state) {
    (void) state;
    uint8_t buf_data[TX_HASH_LENGTH + 4] = {0};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    vote_item_t item;
    assert_false(parse_vote(&buf, &item));
}

static void test_parse_vote_unknown_vote_option(void **state) {
    (void) state;
    uint8_t buf_data[TX_HASH_LENGTH + 4 + 1] = {0};
    buf_data[TX_HASH_LENGTH + 4] = 0xFF;  // invalid vote option
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    vote_item_t item;
    assert_false(parse_vote(&buf, &item));
}

static void test_parse_vote_truncated_anchor(void **state) {
    (void) state;
    // Valid tx hash + gov index + vote option (VOTE_NO=0), but no anchor bytes.
    uint8_t buf_data[TX_HASH_LENGTH + 4 + 1] = {0};
    buf_data[TX_HASH_LENGTH + 4] = (uint8_t) VOTE_NO;
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    vote_item_t item;
    assert_false(parse_vote(&buf, &item));
}

// ---------------------------------------------------------------------------
// parse_withdrawal error paths
// ---------------------------------------------------------------------------

static void test_parse_withdrawal_truncated_amount(void **state) {
    (void) state;
    uint8_t buf_data[4] = {0};  // only 4 bytes, need 8 for u64
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    withdrawal_t out;
    assert_false(parse_withdrawal(&buf, &out));
}

static void test_parse_withdrawal_amount_too_large(void **state) {
    (void) state;
    // LOVELACE_MAX_SUPPLY = 45_000_000_000_000_000 = 0x00A0_AEA1_C0C4_0000
    // Write exactly LOVELACE_MAX_SUPPLY (>= check, so this must fail).
    uint8_t buf_data[8] = {0x00, 0xA0, 0xAE, 0xA1, 0xC0, 0xC4, 0x00, 0x00};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    withdrawal_t out;
    assert_false(parse_withdrawal(&buf, &out));
}

static void test_parse_withdrawal_truncated_credential(void **state) {
    (void) state;
    // Valid amount (1 lovelace), but no credential bytes follow.
    uint8_t buf_data[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    withdrawal_t out;
    assert_false(parse_withdrawal(&buf, &out));
}

// ---------------------------------------------------------------------------
// parse_mint_token error paths
// ---------------------------------------------------------------------------

static void test_parse_mint_token_name_too_long(void **state) {
    (void) state;
    // asset_name_length = MAX_MINT_ASSET_NAME_LENGTH + 1 = 33
    uint8_t buf_data[1] = {MAX_MINT_ASSET_NAME_LENGTH + 1};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    mint_token_t out;
    assert_false(parse_mint_token(&buf, &out));
}

static void test_parse_mint_token_name_truncated(void **state) {
    (void) state;
    // asset_name_length = 5, but only 3 name bytes follow.
    uint8_t buf_data[4] = {5, 0xAA, 0xBB, 0xCC};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    mint_token_t out;
    assert_false(parse_mint_token(&buf, &out));
}

static void test_parse_mint_token_amount_truncated(void **state) {
    (void) state;
    // asset_name_length = 1, name present, but no amount bytes.
    uint8_t buf_data[2] = {1, 0xAA};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    mint_token_t out;
    assert_false(parse_mint_token(&buf, &out));
}

static void test_parse_mint_token_zero_amount(void **state) {
    (void) state;
    // asset_name_length = 1, name byte, amount = 0 (must be rejected).
    uint8_t buf_data[1 + 1 + 8] = {0};
    buf_data[0] = 1;     // name length
    buf_data[1] = 0xAA;  // name byte
    // amount bytes [2..9] remain 0 -> int64 = 0
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    mint_token_t out;
    assert_false(parse_mint_token(&buf, &out));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_tx_fails_on_missing_inputs),
        cmocka_unit_test(test_parse_tx_rejects_oversized_buffer),
        cmocka_unit_test(test_parse_error_mapping_fee),
        cmocka_unit_test(test_parse_error_mapping_buffer_not_fully_consumed),
        cmocka_unit_test(test_process_inputs_field_pass1_success),
        cmocka_unit_test(test_process_inputs_field_parse_error_sends_inputs_swo),
        cmocka_unit_test(test_process_collateral_inputs_field_pass1_success),
        cmocka_unit_test(test_process_reference_inputs_field_parse_error_sends_reference_swo),
        cmocka_unit_test(test_process_required_signers_field_pass1_success),
        cmocka_unit_test(test_process_required_signers_field_parse_error_sends_required_swo),
        cmocka_unit_test(test_mode_allows_rendering_with_validation),
        cmocka_unit_test(test_validate_from_raw_success),
        cmocka_unit_test(test_validate_fails_on_truncated_fee),
        cmocka_unit_test(test_validate_fails_on_truncated_ttl),
        cmocka_unit_test(test_validate_fails_on_truncated_withdrawals),
        cmocka_unit_test(test_validate_from_raw_with_tokens_and_mint_success),
        // parse_required_signer
        cmocka_unit_test(test_parse_required_signer_truncated_type),
        cmocka_unit_test(test_parse_required_signer_path_truncated),
        cmocka_unit_test(test_parse_required_signer_hash_truncated),
        // parse_voter_votes_header
        cmocka_unit_test(test_parse_voter_votes_header_truncated_type),
        cmocka_unit_test(test_parse_voter_votes_header_unknown_type),
        cmocka_unit_test(test_parse_voter_votes_header_path_truncated),
        cmocka_unit_test(test_parse_voter_votes_header_key_hash_truncated),
        cmocka_unit_test(test_parse_voter_votes_header_script_hash_truncated),
        cmocka_unit_test(test_parse_voter_votes_header_num_votes_truncated),
        cmocka_unit_test(test_parse_voter_votes_header_zero_votes),
        // parse_vote
        cmocka_unit_test(test_parse_vote_truncated_tx_hash),
        cmocka_unit_test(test_parse_vote_truncated_gov_action_index),
        cmocka_unit_test(test_parse_vote_truncated_vote_option),
        cmocka_unit_test(test_parse_vote_unknown_vote_option),
        cmocka_unit_test(test_parse_vote_truncated_anchor),
        // parse_withdrawal
        cmocka_unit_test(test_parse_withdrawal_truncated_amount),
        cmocka_unit_test(test_parse_withdrawal_amount_too_large),
        cmocka_unit_test(test_parse_withdrawal_truncated_credential),
        // parse_mint_token
        cmocka_unit_test(test_parse_mint_token_name_too_long),
        cmocka_unit_test(test_parse_mint_token_name_truncated),
        cmocka_unit_test(test_parse_mint_token_amount_truncated),
        cmocka_unit_test(test_parse_mint_token_zero_amount),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
