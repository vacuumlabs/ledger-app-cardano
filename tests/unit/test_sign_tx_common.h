/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <cmocka.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "buffer.h"
#include "handler/sign_tx.h"
#include "handler/sign_tx_aux_data.h"
#include "hexUtils.h"
#include "tx.h"
#include "tx_parse.h"
#include "blake2b.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "securityPolicy.h"
#include "cardano_settings.h"
#include "cardano_constants.h"
#include "test_fixture_types.h"
#include "apdu/dispatcher.h"
#include "ui_display_tx.h"
#include "app_mem_utils.h"
#include "app_context.h"
#include "mock_crypto/crypto_mock_data.h"
#include "nbgl_mock.h"
#include "io_capture.h"
#include "init_apdu.h"
#include "test_read_buffer_helpers.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static inline bool test_mem_init(void) {
    return mem_utils_init(test_heap, sizeof(test_heap));
}
extern bool unit_test_expert_mode_enabled;

static inline bool fixture_blind_signing_enabled(const tx_fixture_t *fixture) {
    LEDGER_ASSERT(fixture != NULL, "NULL fixture");
    return fixture->blind_signing_mode != BLIND_SIGNING_MODE_DISABLED;
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

static inline void run_sign_tx_body_chunked(const uint8_t *raw_tx, size_t raw_tx_len) {
    assert_non_null(raw_tx);
    assert_true(raw_tx_len > 0);

    size_t tx_offset = 0;
    while (tx_offset < raw_tx_len) {
        size_t remaining_bytes = raw_tx_len - tx_offset;
        size_t current_chunk_size =
            (remaining_bytes > MAX_SIGN_TX_CHUNK_SIZE) ? MAX_SIGN_TX_CHUNK_SIZE : remaining_bytes;
        uint8_t p1 = (tx_offset + current_chunk_size < raw_tx_len) ? P1_TX_CHUNK : P1_TX_CONFIRM;

        test_read_buffer_t tx_chunk_buffer =
            make_test_read_buffer(raw_tx + tx_offset, current_chunk_size);
        run_sign_tx_apdu(&tx_chunk_buffer.sdk_buffer, p1);
        assert_read_buffer_unchanged_and_cleanup(&tx_chunk_buffer, raw_tx + tx_offset);
        tx_offset += current_chunk_size;
    }
}

static inline void run_sign_tx_aux_data_apdu(buffer_t *buffer, uint8_t p2) {
    io_capture_reset();
    apdu_response_begin(INS_SIGN_TX);
    handler_sign_tx_aux_data(buffer, p2);
    apdu_response_finalize_after_handler();
}

static inline void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    io_capture_reset();
    nbgl_mock_reset();
}

static inline void run_tx_and_verify(const uint8_t *init_raw,
                                     size_t init_len,
                                     const uint8_t *raw_tx,
                                     size_t raw_tx_len,
                                     bool include_aux_data_hash,
                                     uint8_t aux_data_type,
                                     const uint8_t *aux_data_init_payload,
                                     size_t aux_data_init_payload_len,
                                     const aux_data_payload_t *aux_data_delegations,
                                     size_t aux_data_delegation_count,
                                     const char *cbor_hex,
                                     const char *expected_hash_hex,
                                     uint16_t num_witnesses,
                                     const witness_payload_t *witness_payloads,
                                     size_t witness_payload_count,
                                     bool include_ttl,
                                     bool include_validity_interval_start,
                                     warning_bits_t expected_warning_bits,
                                     const char *fixture_name,
                                     const uint8_t *response_buf,
                                     size_t *response_len,
                                     uint16_t *response_sw) {
    assert_true(init_len > 0);
    run_sign_tx_apdu(&(buffer_t){.ptr = (uint8_t *) init_raw, .size = init_len, .offset = 0},
                     P1_TX_INIT);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
    if (include_aux_data_hash && aux_data_type == AUX_DATA_TYPE_CVOTE_REGISTRATION) {
        assert_int_equal(G_context.state.tx_state, TX_STATE_AUX_DATA);
    } else {
        assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);
    }
    assert_int_equal(G_context.tx_info.num_witnesses, num_witnesses);
    assert_int_equal(G_context.tx_info.tx_params.includeTtl, include_ttl);
    assert_int_equal(G_context.tx_info.tx_params.includeValidityIntervalStart,
                     include_validity_interval_start);

    if (include_aux_data_hash && aux_data_type == AUX_DATA_TYPE_CVOTE_REGISTRATION) {
        assert_non_null(aux_data_init_payload);
        assert_true(aux_data_init_payload_len > 0);
        test_read_buffer_t aux_init_buffer =
            make_test_read_buffer(aux_data_init_payload, aux_data_init_payload_len);
        run_sign_tx_aux_data_apdu(&aux_init_buffer.sdk_buffer, P2_AUX_DATA_INIT);
        assert_read_buffer_unchanged_and_cleanup(&aux_init_buffer, aux_data_init_payload);

        for (size_t i = 0; i < aux_data_delegation_count; i++) {
            const aux_data_payload_t *delegation = &aux_data_delegations[i];
            assert_non_null(delegation->payload);
            assert_true(delegation->payload_len > 0);
            test_read_buffer_t aux_delegation_buffer =
                make_test_read_buffer(delegation->payload, delegation->payload_len);
            run_sign_tx_aux_data_apdu(&aux_delegation_buffer.sdk_buffer, P2_AUX_DATA_DELEGATION);
            assert_read_buffer_unchanged_and_cleanup(&aux_delegation_buffer, delegation->payload);
        }

        assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);
    }

    // Enable streaming auto-complete for TX body review. This must be set after
    // aux data processing (CVote streaming has its own auto-complete lifecycle).
    nbgl_mock_set_streaming_start_auto_complete(true, true);

    run_sign_tx_body_chunked(raw_tx, raw_tx_len);

    // Assert warning bits. Direct struct access because at this point the state may have
    // already transitioned to TX_STATE_APPROVED (via finalize_sign_tx UI callback mock).
    const warning_bits_t actual_warning_bits = G_context.tx_info.body.warning_bits;
    if (actual_warning_bits != expected_warning_bits) {
        print_message(
            "WARNING BITS MISMATCH for fixture \"%s\":\n"
            "  expected: 0x%016llx\n"
            "  actual:   0x%016llx\n",
            fixture_name,
            (unsigned long long) expected_warning_bits,
            (unsigned long long) actual_warning_bits);
    }
    assert_int_equal(actual_warning_bits, expected_warning_bits);

    assert_non_null(cbor_hex);
    assert_true(strlen(cbor_hex) > 0);

    uint8_t expected_hash[TX_HASH_LENGTH];
    size_t expected_hash_len =
        hex_to_bytes(expected_hash_hex, expected_hash, sizeof(expected_hash));
    assert_int_equal(expected_hash_len, TX_HASH_LENGTH);

    uint8_t tx_body_cbor[100 * 1024];
    size_t tx_body_cbor_len = hex_to_bytes(cbor_hex, tx_body_cbor, sizeof(tx_body_cbor));
    assert_true(tx_body_cbor_len > 0);

    uint8_t computed_hash[TX_HASH_LENGTH];
    assert_int_equal(blake2b(computed_hash, sizeof(computed_hash), tx_body_cbor, tx_body_cbor_len),
                     0);
    assert_memory_equal(computed_hash, expected_hash, TX_HASH_LENGTH);

    assert_int_equal(*response_len, TX_HASH_LENGTH);
    assert_memory_equal(response_buf, expected_hash, TX_HASH_LENGTH);
    assert_int_equal(*response_sw, SWO_SUCCESS);

    if (num_witnesses > 0) {
        // Verify all witness APDU payloads from fixtures end-to-end.
        assert_non_null(witness_payloads);
        assert_int_equal(witness_payload_count, num_witnesses);
        assert_int_equal(G_context.state.tx_state, TX_STATE_APPROVED);
        assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
        reset_mock_signature_state();

        for (size_t witness_index = 0; witness_index < witness_payload_count; witness_index++) {
            const witness_payload_t *witness_payload = &witness_payloads[witness_index];
            const bool is_last_fixture_witness = (witness_index == witness_payload_count - 1);
            assert_non_null(witness_payload->payload);
            assert_true(witness_payload->payload_len > 0);

            bip44_path_t witness_path = {0};
            buffer_t witness_policy_buffer = {
                .ptr = (uint8_t *) witness_payload->payload,
                .size = witness_payload->payload_len,
                .offset = 0,
            };
            assert_true(buffer_read_bip44_path(&witness_policy_buffer, &witness_path));
            assert_int_equal(witness_policy_buffer.offset, witness_policy_buffer.size);

            const bool mint_present = (G_context.tx_info.tx_params.num_mint_asset_groups > 0);
            const bip44_path_t *pool_owner_path = NULL;
            if (G_context.tx_info.tx_params.txSigningMode ==
                    SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER &&
                G_context.tx_info.pool_owner_path_present) {
                pool_owner_path = &G_context.tx_info.pool_owner_path;
            }

            warning_bits_t witness_warnings = 0;
            const security_policy_t witness_policy =
                policyForSignTxWitness(G_context.tx_info.tx_params.txSigningMode,
                                       false,
                                       &witness_path,
                                       mint_present,
                                       pool_owner_path,
                                       &witness_warnings);

            const bool witness_requires_confirmation = (witness_policy == POLICY_SHOW);
            const warning_bits_t expected_witness_warning_bits =
                witness_payload->expected_warning_bits;

            if (witness_warnings != expected_witness_warning_bits) {
                print_message(
                    "WITNESS WARNING BITS MISMATCH for fixture \"%s\" witness %zu:\n"
                    "  expected: 0x%016llx\n"
                    "  actual:   0x%016llx\n",
                    fixture_name,
                    witness_index,
                    (unsigned long long) expected_witness_warning_bits,
                    (unsigned long long) witness_warnings);
            }
            assert_int_equal(witness_warnings, expected_witness_warning_bits);

            if (witness_requires_confirmation) {
                const bool witness_final_decisions[] = {true};
                nbgl_mock_set_final_decisions(witness_final_decisions,
                                              ARRAY_LEN(witness_final_decisions));
            }

            test_read_buffer_t witness_buffer =
                make_test_read_buffer(witness_payload->payload, witness_payload->payload_len);
            run_sign_tx_witness_apdu(&witness_buffer.sdk_buffer);
            assert_read_buffer_unchanged_and_cleanup(&witness_buffer, witness_payload->payload);
            if (witness_requires_confirmation) {
                nbgl_mock_assert_all_final_decisions_consumed();
            }

            assert_int_equal(*response_sw, SWO_SUCCESS);
            assert_int_equal(*response_len, ED25519_SIGNATURE_LENGTH);
            assert_int_equal(g_mock_last_signed_message_len, TX_HASH_LENGTH);
            assert_memory_equal(g_mock_last_signed_message, expected_hash, TX_HASH_LENGTH);
            assert_non_null(witness_payload->expected_signature);
            assert_memory_equal(response_buf,
                                witness_payload->expected_signature,
                                ED25519_SIGNATURE_LENGTH);
            if (is_last_fixture_witness) {
                assert_int_equal(G_context.req_type, REQUEST_NONE);
                assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);
            } else {
                assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);
                assert_int_equal(G_context.state.tx_state, TX_STATE_APPROVED);
            }
        }
    } else {
        assert_null(witness_payloads);
        assert_int_equal(witness_payload_count, 0);
        assert_int_equal(G_context.req_type, REQUEST_NONE);
        assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);
    }
}

/**
 * Build init_apdu_params_t from a test fixture and optional pre-decoded aux data hash.
 * Caller is responsible for decoding aux_data_hash_hex and passing the result.
 */
static inline init_apdu_params_t build_init_params_from_fixture(const tx_fixture_t *fixture,
                                                                const uint8_t *aux_data_hash,
                                                                size_t aux_hash_len) {
    bool has_arbitrary_aux =
        fixture->include_aux_data_hash && fixture->aux_data_type == AUX_DATA_TYPE_ARBITRARY_HASH;
    return (init_apdu_params_t){
        .options = fixture->options,
        .networkId = fixture->network_id,
        .protocolMagic = fixture->protocol_magic,
        .signingMode = fixture->signing_mode,
        .numInputs = fixture->num_inputs,
        .numOutputs = fixture->num_outputs,
        .includeTtl = fixture->include_ttl,
        .numCertificates = fixture->num_certificates,
        .numWithdrawals = fixture->num_withdrawals,
        .includeAuxData = fixture->include_aux_data_hash,
        .auxDataType = fixture->aux_data_type,
        .auxDataHash = has_arbitrary_aux ? aux_data_hash : NULL,
        .auxDataHashLen = has_arbitrary_aux ? aux_hash_len : 0,
        .includeScriptDataHash = fixture->include_script_data_hash,
        .includeValidityIntervalStart = fixture->include_validity_interval_start,
        .numMintAssetGroups = fixture->num_mint_asset_groups,
        .numCollateralInputs = fixture->num_collateral_inputs,
        .numRequiredSigners = fixture->num_required_signers,
        .includeNetworkId = fixture->include_network_id,
        .includeCollateralOutput = fixture->include_collateral_output,
        .includeTotalCollateral = fixture->include_total_collateral,
        .numReferenceInputs = fixture->num_reference_inputs,
        .numVoters = fixture->num_voters,
        .includeTreasury = fixture->include_treasury,
        .includeDonation = fixture->include_donation,
        .numWitnesses = fixture->num_witnesses,
        .rawTxTotalLength = (uint16_t) fixture->raw_tx_len,
    };
}

static inline void run_fixture(const tx_fixture_t *fixture) {
    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    uint8_t aux_data_hash[AUX_DATA_HASH_LENGTH] = {0};
    size_t aux_hash_len = 0;
    if (fixture->include_aux_data_hash && fixture->aux_data_type == AUX_DATA_TYPE_ARBITRARY_HASH) {
        assert_non_null(fixture->aux_data_hash_hex);
        aux_hash_len =
            hex_to_bytes(fixture->aux_data_hash_hex, aux_data_hash, sizeof(aux_data_hash));
        assert_int_equal(aux_hash_len, AUX_DATA_HASH_LENGTH);
    }

    init_apdu_params_t params =
        build_init_params_from_fixture(fixture, aux_data_hash, aux_hash_len);
    size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_tx_and_verify(init_raw,
                      init_len,
                      fixture->raw_tx,
                      fixture->raw_tx_len,
                      fixture->include_aux_data_hash,
                      fixture->aux_data_type,
                      fixture->aux_data_init_payload,
                      fixture->aux_data_init_payload_len,
                      fixture->aux_data_delegations,
                      fixture->aux_data_delegation_count,
                      fixture->tx_body_cbor_hex,
                      fixture->expected_hash_hex,
                      fixture->num_witnesses,
                      fixture->witness_payloads,
                      fixture->witness_payload_count,
                      fixture->include_ttl,
                      fixture->include_validity_interval_start,
                      fixture->expected_warning_bits,
                      fixture->name,
                      g_last_response,
                      &g_last_response_len,
                      &g_last_response_swo);
}

static inline void run_fixture_with_expert_mode(const tx_fixture_t *fixture, bool expert_mode) {
    extern bool unit_test_expert_mode_enabled;
    extern bool unit_test_blind_signing_enabled;
    const bool previous_mode = unit_test_expert_mode_enabled;
    const bool previous_blind_signing_enabled = unit_test_blind_signing_enabled;
    unit_test_expert_mode_enabled = expert_mode;
    unit_test_blind_signing_enabled = fixture_blind_signing_enabled(fixture);
    run_fixture(fixture);
    unit_test_expert_mode_enabled = previous_mode;
    unit_test_blind_signing_enabled = previous_blind_signing_enabled;
}

static inline bool fixture_has_cvote_aux_data(const tx_fixture_t *fixture) {
    return fixture->include_aux_data_hash &&
           fixture->aux_data_type == AUX_DATA_TYPE_CVOTE_REGISTRATION;
}

typedef enum {
    REJECT_STAGE_TX = 0,
    REJECT_STAGE_AUX = 1,
} reject_stage_t;

typedef enum {
    ACTUAL_REJECT_STAGE_NONE = 0,
    ACTUAL_REJECT_STAGE_TX = 1,
    ACTUAL_REJECT_STAGE_AUX = 2,
} actual_reject_stage_t;

static inline void run_fixture_reject_with_expert_mode(const tx_fixture_t *fixture,
                                                       bool expert_mode,
                                                       reject_stage_t reject_stage) {
    LEDGER_ASSERT(fixture != NULL, "NULL fixture");
    LEDGER_ASSERT(reject_stage == REJECT_STAGE_TX || reject_stage == REJECT_STAGE_AUX,
                  "Unknown reject stage");
    if (reject_stage == REJECT_STAGE_AUX) {
        LEDGER_ASSERT(fixture_has_cvote_aux_data(fixture),
                      "AUX reject requested for non-CVote fixture");
    }

    extern bool unit_test_expert_mode_enabled;
    extern bool unit_test_blind_signing_enabled;
    const bool previous_mode = unit_test_expert_mode_enabled;
    const bool previous_blind_signing_enabled = unit_test_blind_signing_enabled;
    bool final_decisions_configured = false;
    actual_reject_stage_t actual_reject_stage = ACTUAL_REJECT_STAGE_NONE;
    unit_test_expert_mode_enabled = expert_mode;
    unit_test_blind_signing_enabled = fixture_blind_signing_enabled(fixture);

    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    uint8_t aux_data_hash[AUX_DATA_HASH_LENGTH] = {0};
    size_t aux_hash_len = 0;
    if (fixture->include_aux_data_hash && fixture->aux_data_type == AUX_DATA_TYPE_ARBITRARY_HASH) {
        assert_non_null(fixture->aux_data_hash_hex);
        aux_hash_len =
            hex_to_bytes(fixture->aux_data_hash_hex, aux_data_hash, sizeof(aux_data_hash));
        assert_int_equal(aux_hash_len, AUX_DATA_HASH_LENGTH);
    }

    init_apdu_params_t params =
        build_init_params_from_fixture(fixture, aux_data_hash, aux_hash_len);
    size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);

    if (fixture_has_cvote_aux_data(fixture)) {
        assert_int_equal(G_context.state.tx_state, TX_STATE_AUX_DATA);
        if (reject_stage == REJECT_STAGE_AUX) {
            const bool final_decisions[] = {false};
            nbgl_mock_set_final_decisions(final_decisions, ARRAY_LEN(final_decisions));
            final_decisions_configured = true;
        }

        assert_non_null(fixture->aux_data_init_payload);
        assert_true(fixture->aux_data_init_payload_len > 0);
        test_read_buffer_t aux_init_buffer =
            make_test_read_buffer(fixture->aux_data_init_payload,
                                  fixture->aux_data_init_payload_len);
        run_sign_tx_aux_data_apdu(&aux_init_buffer.sdk_buffer, P2_AUX_DATA_INIT);
        assert_read_buffer_unchanged_and_cleanup(&aux_init_buffer, fixture->aux_data_init_payload);

        if (g_last_response_swo == SWO_CONDITIONS_NOT_SATISFIED) {
            actual_reject_stage = ACTUAL_REJECT_STAGE_AUX;
            goto expected_failure_assertions;
        }
        assert_int_equal(g_last_response_swo, SWO_SUCCESS);

        for (size_t i = 0; i < fixture->aux_data_delegation_count; i++) {
            const aux_data_payload_t *delegation = &fixture->aux_data_delegations[i];
            assert_non_null(delegation->payload);
            assert_true(delegation->payload_len > 0);
            test_read_buffer_t aux_delegation_buffer =
                make_test_read_buffer(delegation->payload, delegation->payload_len);
            run_sign_tx_aux_data_apdu(&aux_delegation_buffer.sdk_buffer, P2_AUX_DATA_DELEGATION);
            assert_read_buffer_unchanged_and_cleanup(&aux_delegation_buffer, delegation->payload);
            if (g_last_response_swo == SWO_CONDITIONS_NOT_SATISFIED) {
                actual_reject_stage = ACTUAL_REJECT_STAGE_AUX;
                goto expected_failure_assertions;
            }
            assert_int_equal(g_last_response_swo, SWO_SUCCESS);
        }

        assert_int_equal(G_context.state.tx_state, TX_STATE_CHUNKS);
    }

    if (reject_stage == REJECT_STAGE_TX) {
        bool final_decisions[2] = {false, false};
        size_t final_decision_count = 1;

        if (fixture->blind_signing_mode == BLIND_SIGNING_MODE_PROMPT_REVIEW_FULL) {
            final_decisions[0] = true;
            final_decisions[1] = false;
            final_decision_count = 2;
        } else if (fixture->blind_signing_mode == BLIND_SIGNING_MODE_PROMPT_REVIEW_HASH) {
            final_decisions[0] = false;
            final_decisions[1] = false;
            final_decision_count = 2;
        }

        nbgl_mock_set_final_decisions(final_decisions, final_decision_count);
        final_decisions_configured = true;
    }

    // Enable streaming auto-complete for TX body review (after aux data processing).
    nbgl_mock_set_streaming_start_auto_complete(true, true);

    run_sign_tx_body_chunked(fixture->raw_tx, fixture->raw_tx_len);
    if (g_last_response_swo == SWO_CONDITIONS_NOT_SATISFIED) {
        actual_reject_stage = ACTUAL_REJECT_STAGE_TX;
    }

expected_failure_assertions:
    if (final_decisions_configured) {
        nbgl_mock_assert_all_final_decisions_consumed();
    }
    assert_int_equal(g_last_response_swo, SWO_CONDITIONS_NOT_SATISFIED);
    assert_int_equal(
        actual_reject_stage,
        reject_stage == REJECT_STAGE_AUX ? ACTUAL_REJECT_STAGE_AUX : ACTUAL_REJECT_STAGE_TX);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);

    unit_test_expert_mode_enabled = previous_mode;
    unit_test_blind_signing_enabled = previous_blind_signing_enabled;
}

static inline void run_fixture_reject_tx_with_expert_mode(const tx_fixture_t *fixture,
                                                          bool expert_mode) {
    run_fixture_reject_with_expert_mode(fixture, expert_mode, REJECT_STAGE_TX);
}

static inline void run_fixture_reject_aux_with_expert_mode(const tx_fixture_t *fixture,
                                                           bool expert_mode) {
    run_fixture_reject_with_expert_mode(fixture, expert_mode, REJECT_STAGE_AUX);
}

/**
 * Run a streaming fixture and reject at the initial "Review transaction" screen
 * (tx_streaming_start_choice called with false). Only valid for streaming fixtures.
 */
static inline void run_fixture_reject_streaming_start_with_expert_mode(const tx_fixture_t *fixture,
                                                                       bool expert_mode) {
    LEDGER_ASSERT(fixture != NULL, "NULL fixture");

    extern bool unit_test_expert_mode_enabled;
    extern bool unit_test_blind_signing_enabled;
    const bool previous_mode = unit_test_expert_mode_enabled;
    const bool previous_blind_signing_enabled = unit_test_blind_signing_enabled;
    unit_test_expert_mode_enabled = expert_mode;
    unit_test_blind_signing_enabled = fixture_blind_signing_enabled(fixture);

    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);

    // Reject at the streaming start screen.
    nbgl_mock_set_streaming_start_auto_complete(true, false);

    run_sign_tx_body_chunked(fixture->raw_tx, fixture->raw_tx_len);

    assert_int_equal(g_last_response_swo, SWO_CONDITIONS_NOT_SATISFIED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);

    unit_test_expert_mode_enabled = previous_mode;
    unit_test_blind_signing_enabled = previous_blind_signing_enabled;
}

/**
 * Run a streaming fixture and reject at the first intermediate streaming continue screen
 * (tx_streaming_continue_choice called with false after the first chunk). Only valid for
 * streaming fixtures with at least two chunks.
 */
static inline void run_fixture_reject_streaming_continue_at_call_with_expert_mode(
    const tx_fixture_t *fixture,
    bool expert_mode,
    size_t continue_call_index) {
    LEDGER_ASSERT(fixture != NULL, "NULL fixture");

    extern bool unit_test_expert_mode_enabled;
    extern bool unit_test_blind_signing_enabled;
    const bool previous_mode = unit_test_expert_mode_enabled;
    const bool previous_blind_signing_enabled = unit_test_blind_signing_enabled;
    unit_test_expert_mode_enabled = expert_mode;
    unit_test_blind_signing_enabled = fixture_blind_signing_enabled(fixture);

    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);

    // Confirm the streaming start, then reject on a chosen streaming continue call.
    nbgl_mock_set_streaming_start_auto_complete(true, true);
    nbgl_mock_set_streaming_continue_reject_at_call(continue_call_index);

    run_sign_tx_body_chunked(fixture->raw_tx, fixture->raw_tx_len);

    assert_int_equal(g_last_response_swo, SWO_CONDITIONS_NOT_SATISFIED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);

    unit_test_expert_mode_enabled = previous_mode;
    unit_test_blind_signing_enabled = previous_blind_signing_enabled;
}

static inline void run_fixture_reject_streaming_continue_with_expert_mode(
    const tx_fixture_t *fixture,
    bool expert_mode) {
    run_fixture_reject_streaming_continue_at_call_with_expert_mode(fixture, expert_mode, 0);
}

static inline void run_fixture_reject_streaming_finish_with_expert_mode(const tx_fixture_t *fixture,
                                                                        bool expert_mode) {
    LEDGER_ASSERT(fixture != NULL, "NULL fixture");

    extern bool unit_test_expert_mode_enabled;
    extern bool unit_test_blind_signing_enabled;
    const bool previous_mode = unit_test_expert_mode_enabled;
    const bool previous_blind_signing_enabled = unit_test_blind_signing_enabled;
    unit_test_expert_mode_enabled = expert_mode;
    unit_test_blind_signing_enabled = fixture_blind_signing_enabled(fixture);

    reset_context();
    assert_true(test_mem_init());

    uint8_t init_raw[512];
    init_apdu_params_t params = build_init_params_from_fixture(fixture, NULL, 0);
    size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_sign_tx_apdu(&(buffer_t){.ptr = init_raw, .size = init_len, .offset = 0}, P1_TX_INIT);
    assert_int_equal(g_last_response_swo, SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_SIGN_TRANSACTION);

    const bool final_decisions[] = {false};
    nbgl_mock_set_final_decisions(final_decisions, ARRAY_LEN(final_decisions));

    // Confirm the streaming start and all intermediate chunks, then reject on the finish screen.
    nbgl_mock_set_streaming_start_auto_complete(true, true);

    run_sign_tx_body_chunked(fixture->raw_tx, fixture->raw_tx_len);
    nbgl_mock_assert_all_final_decisions_consumed();

    assert_int_equal(g_last_response_swo, SWO_CONDITIONS_NOT_SATISFIED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_int_equal(G_context.state.tx_state, TX_STATE_NONE);

    unit_test_expert_mode_enabled = previous_mode;
    unit_test_blind_signing_enabled = previous_blind_signing_enabled;
}

static inline void run_fixture_blind_signing_hash_only_with_expert_mode(const tx_fixture_t *fixture,
                                                                        bool expert_mode) {
    LEDGER_ASSERT(fixture != NULL, "NULL fixture");
    LEDGER_ASSERT(fixture->blind_signing_mode == BLIND_SIGNING_MODE_PROMPT_REVIEW_HASH,
                  "Blind-signing hash-only path requires hash-only prompt fixture");

    extern bool unit_test_expert_mode_enabled;
    extern bool unit_test_blind_signing_enabled;
    const bool previous_mode = unit_test_expert_mode_enabled;
    const bool previous_blind_signing_enabled = unit_test_blind_signing_enabled;
    unit_test_expert_mode_enabled = expert_mode;
    unit_test_blind_signing_enabled = true;

    reset_context();
    assert_true(test_mem_init());

    const bool final_decisions[] = {false, true};
    nbgl_mock_set_final_decisions(final_decisions, ARRAY_LEN(final_decisions));

    uint8_t init_raw[512];
    uint8_t aux_data_hash[AUX_DATA_HASH_LENGTH] = {0};
    size_t aux_hash_len = 0;
    if (fixture->include_aux_data_hash && fixture->aux_data_type == AUX_DATA_TYPE_ARBITRARY_HASH) {
        assert_non_null(fixture->aux_data_hash_hex);
        aux_hash_len =
            hex_to_bytes(fixture->aux_data_hash_hex, aux_data_hash, sizeof(aux_data_hash));
        assert_int_equal(aux_hash_len, AUX_DATA_HASH_LENGTH);
    }

    init_apdu_params_t params =
        build_init_params_from_fixture(fixture, aux_data_hash, aux_hash_len);
    size_t init_len = build_init_apdu(&params, init_raw, sizeof(init_raw));
    assert_true(init_len > 0);

    run_tx_and_verify(init_raw,
                      init_len,
                      fixture->raw_tx,
                      fixture->raw_tx_len,
                      fixture->include_aux_data_hash,
                      fixture->aux_data_type,
                      fixture->aux_data_init_payload,
                      fixture->aux_data_init_payload_len,
                      fixture->aux_data_delegations,
                      fixture->aux_data_delegation_count,
                      fixture->tx_body_cbor_hex,
                      fixture->expected_hash_hex,
                      fixture->num_witnesses,
                      fixture->witness_payloads,
                      fixture->witness_payload_count,
                      fixture->include_ttl,
                      fixture->include_validity_interval_start,
                      fixture->expected_warning_bits,
                      fixture->name,
                      g_last_response,
                      &g_last_response_len,
                      &g_last_response_swo);
    nbgl_mock_assert_all_final_decisions_consumed();

    unit_test_expert_mode_enabled = previous_mode;
    unit_test_blind_signing_enabled = previous_blind_signing_enabled;
}

// Free heap-allocated tx buffers and reset the UI pair count.
// Used in tests that abort a transaction early and need to clean up before the next test.
// Accesses the body slot directly because this may be called in any tx state.
static inline void tx_context_cleanup(void) {
    APP_MEM_FREE_AND_NULL((void **) &G_context.tx_info.body.raw_tx);
    G_context.tx_info.body.total_ui_pairs = 0;
}
