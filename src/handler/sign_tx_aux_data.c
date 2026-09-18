/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "app_context.h"
#include "buffer.h"
#include "cardano_constants.h"
#include "cardano_parsers.h"
#include "cardano_swo.h"
#include "cvote_hash.h"
#include "cvote_parser.h"
#include "globals.h"
#include "io.h"
#include "mem.h"
#include "securityPolicy.h"
#include "cardano_buffer.h"
#include "sign_tx_aux_data.h"
#include "sign_tx_ctx.h"
#include "tx.h"
#include "tx_credential_types.h"
#include "ui_display_cvote_aux_data.h"
#include "utils.h"

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_HANDLERS to trace handler flow details.
 */
#ifdef TRACE_HANDLERS
#define TRACE_MODULE(...) TRACE("[sign_tx_aux_data] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif

// CVote AUX-DATA state machine (handler + UI callback transitions):
// EXPECTING_INIT
//   -> RECEIVING_DELEGATIONS      (non-streaming init with delegations)
//   -> STREAMING_INITIAL_PAGE     (streaming init with delegations)
//   -> ALL_DATA_RECEIVED          (non-streaming init with zero delegations)
// STREAMING_INITIAL_PAGE
//   -> RECEIVING_DELEGATIONS      (after initial page callback)
// RECEIVING_DELEGATIONS
//   -> ALL_DATA_RECEIVED          (after last delegation APDU)
// ALL_DATA_RECEIVED
//   -> NONE                       (after user confirm/reject callback)

static bool ensure_sign_tx_aux_data_request_type(request_type_e required_request_type) {
    if (G_context.req_type != required_request_type) {
        TRACE("AUX_DATA rejected: request type %d (expected %d)",
              G_context.req_type,
              required_request_type);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }
    return true;
}

static bool ensure_sign_tx_aux_data_tx_state(tx_state_e required_tx_state) {
    if (G_context.state.tx_state != required_tx_state) {
        TRACE("AUX_DATA rejected: tx state %d (expected %d)",
              G_context.state.tx_state,
              required_tx_state);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }
    return true;
}

static bool ensure_sign_tx_aux_data_state(cvote_aux_data_state_e required_aux_state) {
    cvote_aux_data_t *aux_data = &tx_aux_data_ctx()->cvote_aux_data;
    if (aux_data->state != required_aux_state) {
        TRACE("AUX_DATA rejected: aux state %d (expected %d)", aux_data->state, required_aux_state);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }
    return true;
}

// Validate CVote aux data against security policies
// Returns false if any policy denies, true if all policies allow
static bool cvote_aux_data_validate(cvote_aux_data_t *aux_data) {
    ASSERT(aux_data != NULL);

    // Assert that CVote warnings are initially empty and TX warnings haven't leaked in
    ASSERT(warning_bits_is_empty(&tx_aux_data_ctx()->cvote_warning_bits));

    // 1. Vote key (only checked in CIP15 or CIP36 with no delegations)
    security_policy_t vote_key_policy = POLICY_DENY;
    if (aux_data->remaining_delegations == 0) {
        warning_bits_t vote_key_warnings = 0;
        vote_key_policy = policyForCVoteRegistrationVoteKey(&aux_data->vote_credential,
                                                            aux_data->format,
                                                            &vote_key_warnings);
        ASSERT(warning_bits_except_mask(
                   vote_key_warnings,
                   warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0);
        // CVote vote-key unusual derivation warning is rendered inline as a dedicated UI pair.
    } else {
        vote_key_policy = POLICY_HIDE;  // Not used with delegations
    }

    switch (vote_key_policy) {
        case POLICY_DENY:
            TRACE("CVote vote key policy denied");
            return false;
        case POLICY_SHOW:
            aux_data->ui_show.vote_key = true;
            break;
        case POLICY_HIDE:
            aux_data->ui_show.vote_key = false;
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            return false;
            // LCOV_EXCL_STOP
    }

    // 2. Staking key
    if (aux_data->staking_credential.type != CVOTE_CREDENTIAL_KEY_PATH) {
        TRACE("CVote staking key must be KEY_PATH, got type %u", aux_data->staking_credential.type);
        return false;
    }

    security_policy_t staking_key_policy =
        policyForCVoteRegistrationStakingKey(&aux_data->staking_credential.keyPath,
                                             &tx_aux_data_ctx()->cvote_warning_bits);

    switch (staking_key_policy) {
        case POLICY_DENY:
            TRACE("CVote staking key policy denied");
            return false;
        case POLICY_SHOW:
            aux_data->ui_show.staking_key = true;
            break;
        // LCOV_EXCL_START
        case POLICY_HIDE:
            // policyForCVoteRegistrationStakingKey currently never returns POLICY_HIDE; if it
            // ever does, set ui_show.staking_key to false here instead of asserting.
            ASSERT(false);
            return false;
        default:
            ASSERT(false);
            return false;
            // LCOV_EXCL_STOP
    }

    // 3. Payment destination
    security_policy_t destination_policy =
        policyForCVoteRegistrationPaymentDestination(&aux_data->destination,
                                                     G_context.tx_info.tx_params.networkId,
                                                     &tx_aux_data_ctx()->cvote_warning_bits);

    switch (destination_policy) {
        case POLICY_DENY:
            TRACE("CVote payment destination policy denied");
            return false;
        case POLICY_SHOW:
            aux_data->ui_show.payment_destination = true;
            break;
        // LCOV_EXCL_START
        case POLICY_HIDE:
            // policyForCVoteRegistrationPaymentDestination currently never returns POLICY_HIDE;
            // if it ever does, set ui_show.payment_destination to false here instead of
            // asserting.
            ASSERT(false);
            return false;
        default:
            ASSERT(false);
            return false;
            // LCOV_EXCL_STOP
    }

    // 4. Nonce
    security_policy_t nonce_policy =
        policyForCVoteRegistrationNonce(&tx_aux_data_ctx()->cvote_warning_bits);

    switch (nonce_policy) {
        case POLICY_SHOW:
            aux_data->ui_show.nonce = true;
            break;
        // LCOV_EXCL_START
        case POLICY_DENY:
            // policyForCVoteRegistrationNonce currently never returns POLICY_DENY; if it ever
            // does, return false here instead of asserting.
            ASSERT(false);
            return false;
        case POLICY_HIDE:
            // policyForCVoteRegistrationNonce currently never returns POLICY_HIDE; if it ever
            // does, set ui_show.nonce to false here instead of asserting.
            ASSERT(false);
            return false;
        default:
            ASSERT(false);
            return false;
            // LCOV_EXCL_STOP
    }

    // 5. Voting purpose (CIP36 only)
    security_policy_t voting_purpose_policy =
        policyForCVoteRegistrationVotingPurpose(aux_data->voting_purpose,
                                                &tx_aux_data_ctx()->cvote_warning_bits);

    switch (voting_purpose_policy) {
        case POLICY_SHOW:
            aux_data->ui_show.voting_purpose = true;
            break;
        case POLICY_HIDE:
            aux_data->ui_show.voting_purpose = false;
            break;
        // LCOV_EXCL_START
        case POLICY_DENY:
            // policyForCVoteRegistrationVotingPurpose currently never returns POLICY_DENY; if it
            // ever does, return false here instead of asserting.
            ASSERT(false);
            return false;
        default:
            ASSERT(false);
            return false;
            // LCOV_EXCL_STOP
    }

    // Aux data hash is no longer displayed in UI (finalized after user confirms)
    // No policy check needed

    return true;
}

static void handler_tx_aux_data_init(buffer_t *cdata) {
    ASSERT(cdata != NULL);
    ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION);
    ASSERT(G_context.state.tx_state == TX_STATE_AUX_DATA);
    cvote_aux_data_t *aux_data = &tx_aux_data_ctx()->cvote_aux_data;

    ASSERT(aux_data->state == CVOTE_AUX_DATA_STATE_EXPECTING_INIT);
    ASSERT(tx_aux_data_ctx()->raw_cvote_init_data == NULL);
    ASSERT(tx_aux_data_ctx()->raw_cvote_init_data_len == 0);

    // Allocate persistent buffer for CVote init data
    const size_t init_payload_len = buffer_data_size(cdata);
    if (init_payload_len == 0) {
        TRACE("CVote AUX_DATA init: empty payload");
        send_swo_and_reset(SWO_CVOTE_AUX_DATA_PARSING_FAIL);
        return;
    }
    ASSERT(init_payload_len <= UINT16_MAX);
    if (!APP_MEM_CALLOC((void **) &tx_aux_data_ctx()->raw_cvote_init_data,
                        (uint16_t) init_payload_len)) {
        // LCOV_EXCL_START
        // Requires allocator failure — not reachable in unit tests.
        TRACE_MODULE("CVote AUX_DATA init: failed to allocate %u byte buffer",
                     (unsigned) init_payload_len);
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
        // LCOV_EXCL_STOP
    }

    const uint8_t *payload_start = buffer_get_cur(cdata);
    ASSERT(payload_start != NULL);
    memcpy(tx_aux_data_ctx()->raw_cvote_init_data, payload_start, init_payload_len);
    tx_aux_data_ctx()->raw_cvote_init_data_len = init_payload_len;

    cvote_parser_status_t status = cvote_parse_aux_data_init(aux_data);
    if (status != CVOTE_PARSER_OK) {
        TRACE("CVote AUX_DATA init parse failed: %d", status);
        send_swo_and_reset(status == CVOTE_PARSER_OUT_OF_MEMORY ? SWO_INSUFFICIENT_MEMORY
                                                                : SWO_CVOTE_AUX_DATA_PARSING_FAIL);
        return;
    }

    // Validate all security policies
    if (!cvote_aux_data_validate(aux_data)) {
        TRACE("CVote AUX_DATA validation failed");
        APP_MEM_FREE_AND_NULL((void **) &tx_aux_data_ctx()->raw_cvote_init_data);
        tx_aux_data_ctx()->raw_cvote_init_data_len = 0;
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    cvote_hash_builder_setup(aux_data);

    // Transition state based on delegation count
    if (aux_data->remaining_delegations > 0) {
        aux_data->state = CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS;
    } else {
        aux_data->state = CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED;
    }

    TRACE_MODULE("CVote AUX_DATA init: format=%u, delegations=%u",
                 aux_data->format,
                 aux_data->remaining_delegations);

    ui_cvote_aux_data_init_vars(aux_data);

    if (aux_data->ui_streaming.on) {
        ASSERT(aux_data->remaining_delegations > 0);
        aux_data->state = CVOTE_AUX_DATA_STATE_STREAMING_INITIAL_PAGE;
        apdu_response_deferred();
        ui_cvote_aux_data_streaming_show_initial_page(aux_data);
        return;
    }

    if (!ui_cvote_aux_data_init_non_streaming(aux_data)) {
        // LCOV_EXCL_START
        // Requires NBGL pair-list allocator failure — not reachable without mock OOM injection.
        TRACE_MODULE("CVote AUX_DATA non-streaming UI init failed");
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
        // LCOV_EXCL_STOP
    }

    // Non-streaming with zero delegations: show final review immediately.
    // State stays TX_STATE_AUX_DATA until user confirms (finalize_sign_tx_aux_data).
    if (aux_data->state == CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED) {
        ASSERT(aux_data->remaining_delegations == 0);
        TRACE_MODULE("CVote AUX_DATA ready for UI confirmation");
        apdu_response_deferred();
        ui_cvote_aux_data_show_non_streaming_final_review(aux_data);
        return;
    }

    apdu_response_send_sw(SWO_SUCCESS);
}

static void handler_tx_aux_data_delegation(buffer_t *cdata) {
    ASSERT(cdata != NULL);
    ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION);
    ASSERT(G_context.state.tx_state == TX_STATE_AUX_DATA);
    cvote_aux_data_t *aux_data = &tx_aux_data_ctx()->cvote_aux_data;

    ASSERT(aux_data->state == CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS);
    ASSERT(aux_data->remaining_delegations > 0);

    TRACE_MODULE("CVote AUX_DATA delegation received, payload_len=%u", cdata->size);
    cvote_credential_t delegation_credential = {0};
    if (!buffer_read_cvote_credential(cdata, &delegation_credential)) {
        TRACE("CVote AUX_DATA delegation: parsing failed");
        send_swo_and_reset(SWO_CVOTE_AUX_DATA_PARSING_FAIL);
        return;
    }

    // Validate delegation credential against security policy BEFORE adding to hash
    // Per CIP-36, delegation vote keys can be device-owned (KEY_PATH) or third-party (KEY)
    // Device-owned paths must be valid CVote key paths (m/1694'/1815'/account'/0/address_index)
    warning_bits_t delegation_warnings = 0;
    security_policy_t delegation_policy = policyForCVoteRegistrationVoteKey(&delegation_credential,
                                                                            aux_data->format,
                                                                            &delegation_warnings);
    ASSERT(warning_bits_except_mask(
               delegation_warnings,
               warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0);
    // CVote vote-key unusual derivation warning is rendered inline as a dedicated UI pair.
    if (delegation_policy == POLICY_DENY) {
        TRACE("CVote AUX_DATA delegation: vote key policy denied");
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    uint32_t weight = 0;
    if (!buffer_read_u32(cdata, &weight, BE)) {
        TRACE("CVote AUX_DATA delegation: missing weight");
        send_swo_and_reset(SWO_CVOTE_AUX_DATA_PARSING_FAIL);
        return;
    }
    if (deny_unconsumed_bytes(cdata, SWO_CVOTE_AUX_DATA_PARSING_FAIL)) {
        TRACE("CVote AUX_DATA delegation APDU not fully consumed");
        return;
    }

    cvote_hash_builder_add_delegation(aux_data, &delegation_credential, weight);

    ASSERT(aux_data->remaining_delegations > 0);
    aux_data->remaining_delegations--;
    const bool is_last_delegation_chunk = (aux_data->remaining_delegations == 0);

    if (aux_data->ui_streaming.on) {
        if (is_last_delegation_chunk) {
            aux_data->state = CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED;
            TRACE_MODULE("CVote AUX_DATA: all delegations received");
            // State stays TX_STATE_AUX_DATA until user confirms (finalize_sign_tx_aux_data).
        }

        // Mark APDU as deferred before invoking UI code.
        // In unit tests, NBGL callbacks execute synchronously and may send SW immediately.
        apdu_response_deferred();
        ui_cvote_aux_data_add_delegation(aux_data, &delegation_credential, weight);

        return;
    } else {
        // Non-streaming mode
        ui_cvote_aux_data_add_delegation(aux_data, &delegation_credential, weight);

        if (aux_data->remaining_delegations == 0) {
            // All delegations received. State stays TX_STATE_AUX_DATA until user confirms.
            aux_data->state = CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED;
            TRACE_MODULE("CVote AUX_DATA ready for UI confirmation");
            apdu_response_deferred();
            ui_cvote_aux_data_show_non_streaming_final_review(aux_data);
            return;
        }

        // More delegations expected, send success
        apdu_response_send_sw(SWO_SUCCESS);
    }
}

void handler_sign_tx_aux_data(buffer_t *cdata, uint8_t p2) {
    ASSERT(cdata != NULL);
#ifdef TRACE_HANDLERS
    TRACE_BUFFER_T(cdata);
#endif

    if (!ensure_sign_tx_aux_data_request_type(REQUEST_SIGN_TRANSACTION)) {
        return;
    }

    if (!ensure_sign_tx_aux_data_tx_state(TX_STATE_AUX_DATA)) {
        return;
    }

    switch (p2) {
        case P2_AUX_DATA_INIT:
            if (!ensure_sign_tx_aux_data_state(CVOTE_AUX_DATA_STATE_EXPECTING_INIT)) {
                return;
            }
            handler_tx_aux_data_init(cdata);
            return;
        case P2_AUX_DATA_DELEGATION:
            if (!ensure_sign_tx_aux_data_state(CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS)) {
                return;
            }
            handler_tx_aux_data_delegation(cdata);
            return;
        default:
            TRACE("Unexpected P2 for AUX_DATA APDU");
            send_swo_and_reset(SWO_INCORRECT_P1_P2);
            return;
    }
}

void finalize_sign_tx_aux_data(void) {
    ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION);
    ASSERT(G_context.state.tx_state == TX_STATE_AUX_DATA);
    ASSERT(tx_aux_data_ctx()->cvote_aux_data.state == CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED);

    cvote_hash_finalize();

    // Capture response fields before freeing aux_data context.
    struct __attribute__((packed)) {
        uint8_t auxDataHash[AUX_DATA_HASH_LENGTH];
        uint8_t registrationSignature[ED25519_SIGNATURE_LENGTH];
    } wireResponse;
    memmove(wireResponse.auxDataHash,
            G_context.tx_info.tx_params.auxDataHash,
            AUX_DATA_HASH_LENGTH);
    memmove(wireResponse.registrationSignature,
            tx_aux_data_ctx()->cvote_aux_data.registration_signature,
            ED25519_SIGNATURE_LENGTH);

    // CVote init buffer is no longer needed once aux-data hash is finalized.
    APP_MEM_FREE_AND_NULL((void **) &tx_aux_data_ctx()->raw_cvote_init_data);
    tx_aux_data_ctx()->raw_cvote_init_data_len = 0;

    // Single point of transition: aux_data slot -> body slot.
    // Clear the body view before reusing the union.
    explicit_bzero(&G_context.tx_info.body, sizeof(G_context.tx_info.body));
    G_context.state.tx_state = TX_STATE_CHUNKS;

    apdu_response_send_data((const uint8_t *) &wireResponse, sizeof(wireResponse), SWO_SUCCESS);
}
