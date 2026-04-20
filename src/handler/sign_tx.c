/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero

#include "app_context.h"
#include "bip44.h"
#include "buffer.h"
#include "cardano_constants.h"
#include "cardano_parsers.h"
#include "cardano_swo.h"
#include "cardano_settings.h"
#include "globals.h"
#include "messageSigning.h"
#include "io.h"
#include "mem.h"
#include "menu.h"
#include "nbgl_use_case.h"
#include "securityPolicy.h"
#include "ui_display_tx.h"
#include "sign_tx.h"
#include "sign_tx_ctx.h"
#include "tx.h"
#include "tx_credential_types.h"
#include "tx_output_types.h"
#include "tx_processing.h"
#include "tx_signing_mode.h"
#include "tx_utils.h"
#include "utils.h"
#include "cardano_buffer.h"

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_HANDLERS to trace handler-level flow.
 */
#ifdef TRACE_HANDLERS
#define TRACE_MODULE(...) TRACE("[sign_tx] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif

#ifdef HAVE_SWAP
#include "swap.h"
#include "swap_error_code_helpers.h"
#include "swap_lib.h"
#endif

static bool ensure_sign_tx_state(tx_state_e required_state) {
    if (G_context.state.tx_state != required_state) {
        TRACE_MODULE("Rejecting sign_tx command in state %d (expected %d)",
                     G_context.state.tx_state,
                     required_state);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }
    return true;
}

static bool ensure_sign_tx_request_type(request_type_e required_request_type) {
    if (G_context.req_type != required_request_type) {
        TRACE_MODULE("Rejecting sign_tx command for req_type %d (expected %d)",
                     G_context.req_type,
                     required_request_type);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }
    return true;
}

/**
 * Read and validate the options bitmask from the TX init APDU.
 * Returns false and sends SW on failure.
 */
static bool read_tx_options(buffer_t *cdata, tx_params_t *tx_params) {
    uint64_t options;
    if (!buffer_read_u64(cdata, &options, BE)) {
        TRACE("TX init: missing options");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return false;
    }
    tx_params->tagCborSets = (bool) (options & TX_OPTIONS_TAG_CBOR_SETS);
    options &= ~TX_OPTIONS_TAG_CBOR_SETS;
    if (options != 0) {
        TRACE("TX init: unsupported options 0x%llx", (unsigned long long) options);
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return false;
    }
    return true;
}

/**
 * Read and validate network ID, protocol magic, and signing mode from the TX init APDU.
 * Returns false and sends SW on failure.
 */
static bool read_tx_network_params(buffer_t *cdata, tx_params_t *tx_params) {
    if (!buffer_read_u8(cdata, &tx_params->networkId) || !isValidNetworkId(tx_params->networkId)) {
        TRACE("TX init: invalid network id %u", tx_params->networkId);
        send_swo_and_reset(SWO_INVALID_NETWORK_ID);
        return false;
    }
    if (!buffer_read_u32(cdata, &tx_params->protocolMagic, BE)) {
        TRACE("TX init: invalid or missing protocol magic");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return false;
    }
    if (tx_params->networkId == MAINNET_NETWORK_ID &&
        tx_params->protocolMagic != MAINNET_PROTOCOL_MAGIC) {
        TRACE("TX init: invalid mainnet protocol magic %u", tx_params->protocolMagic);
        send_swo_and_reset(SWO_INVALID_PROTOCOL_MAGIC);
        return false;
    }
    if (!buffer_read_u8(cdata, (uint8_t *) &tx_params->txSigningMode) ||
        !is_valid_tx_signing_mode(tx_params->txSigningMode)) {
        TRACE("TX init: invalid or missing signing mode");
        send_swo_and_reset(SWO_INVALID_TX_SIGNING_MODE);
        return false;
    }
    return true;
}

/**
 * Read and validate auxiliary data hash parameters (tx body field 7) from the TX init APDU.
 * Sets tx_params->includeAuxDataHash, auxDataType, and auxDataHash.
 * Returns false and sends SW on failure.
 */
static bool read_aux_data_params(buffer_t *cdata, tx_params_t *tx_params) {
    if (!buffer_read_flag_included(cdata, &tx_params->includeAuxDataHash)) {
        TRACE("TX init: invalid aux data hash inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return false;
    }
    if (!tx_params->includeAuxDataHash) {
        tx_params->auxDataType = AUX_DATA_TYPE_ARBITRARY_HASH;
        explicit_bzero(tx_params->auxDataHash, AUX_DATA_HASH_LENGTH);
        return true;
    }
    uint8_t auxDataTypeByte = 0;
    if (!buffer_read_u8(cdata, &auxDataTypeByte)) {
        TRACE("TX init: missing aux data type");
        send_swo_and_reset(SWO_WRONG_TX_INIT_APDU_DATA);
        return false;
    }
    switch (auxDataTypeByte) {
        case AUX_DATA_TYPE_ARBITRARY_HASH:
            tx_params->auxDataType = AUX_DATA_TYPE_ARBITRARY_HASH;
            if (!buffer_read_bytes(cdata, tx_params->auxDataHash, AUX_DATA_HASH_LENGTH)) {
                TRACE("TX init: missing aux data hash bytes");
                send_swo_and_reset(SWO_WRONG_TX_INIT_APDU_DATA);
                return false;
            }
            break;
        case AUX_DATA_TYPE_CVOTE_REGISTRATION:
            tx_params->auxDataType = AUX_DATA_TYPE_CVOTE_REGISTRATION;
            explicit_bzero(tx_params->auxDataHash, AUX_DATA_HASH_LENGTH);
            break;
        default:
            TRACE("TX init: unsupported aux data type %u", auxDataTypeByte);
            send_swo_and_reset(SWO_WRONG_TX_INIT_APDU_DATA);
            return false;
    }
    return true;
}

/**
 * Helper: Initialize transaction from P1_TX_INIT APDU
 * Validates all transaction metadata and checks security policy
 */
static void handle_tx_init_apdu(buffer_t *cdata) {
    ASSERT(cdata != NULL);
    tx_params_t *tx_params = &G_context.tx_info.tx_params;

    if (!read_tx_options(cdata, tx_params)) {
        return;
    }
    if (!read_tx_network_params(cdata, tx_params)) {
        return;
    }

    // Read transaction structure counts (fields 0-1: inputs and outputs, always present)
    if (!buffer_read_u16(cdata, &tx_params->num_inputs, BE) ||
        !buffer_read_u16(cdata, &tx_params->num_outputs, BE)) {
        TRACE("TX init: missing inputs/outputs counts");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 3 (TTL) - optional
    if (!buffer_read_flag_included(cdata, &tx_params->includeTtl)) {
        TRACE("TX init: invalid TTL inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Field 4 (certificates) - optional
    if (!buffer_read_u16(cdata, &tx_params->num_certificates, BE)) {
        TRACE("TX init: missing certificates count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 5 (withdrawals) - optional
    if (!buffer_read_u16(cdata, &tx_params->num_withdrawals, BE)) {
        TRACE("TX init: missing withdrawals count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 7 (auxiliary data hash) - optional
    if (!read_aux_data_params(cdata, tx_params)) {
        return;
    }

    // Field 8 (validity interval start) - optional
    if (!buffer_read_flag_included(cdata, &tx_params->includeValidityIntervalStart)) {
        TRACE("TX init: invalid validity interval start inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Field 9 (mint) - optional
    if (!buffer_read_u16(cdata, &tx_params->num_mint_asset_groups, BE)) {
        TRACE("TX init: missing mint asset group count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 11 (script data hash) - optional
    if (!buffer_read_flag_included(cdata, &tx_params->includeScriptDataHash)) {
        TRACE("TX init: invalid script data hash inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Field 13 (collateral inputs)
    if (!buffer_read_u16(cdata, &tx_params->num_collateral_inputs, BE)) {
        TRACE("TX init: missing collateral inputs count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 14 (required signers)
    if (!buffer_read_u16(cdata, &tx_params->num_required_signers, BE)) {
        TRACE("TX init: missing required signers count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 15 (network ID)
    if (!buffer_read_flag_included(cdata, &tx_params->includeNetworkId)) {
        TRACE("TX init: invalid network id inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Field 16 (collateral output)
    if (!buffer_read_flag_included(cdata, &tx_params->includeCollateralOutput)) {
        TRACE("TX init: invalid collateral output inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Field 17 (total collateral)
    if (!buffer_read_flag_included(cdata, &tx_params->includeTotalCollateral)) {
        TRACE("TX init: invalid total collateral inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Field 18 (reference inputs)
    if (!buffer_read_u16(cdata, &tx_params->num_reference_inputs, BE)) {
        TRACE("TX init: missing reference inputs count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 19 (voting procedures)
    if (!buffer_read_u16(cdata, &tx_params->num_voters, BE)) {
        TRACE("TX init: missing voters count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Field 21 (treasury) - optional
    if (!buffer_read_flag_included(cdata, &tx_params->includeTreasury)) {
        TRACE("TX init: invalid treasury inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Field 22 (donation) - optional
    if (!buffer_read_flag_included(cdata, &tx_params->includeDonation)) {
        TRACE("TX init: invalid donation inclusion flag");
        send_swo_and_reset(SWO_TX_PARSING_FAIL_INCLUSION_FLAG);
        return;
    }

    // Read number of witnesses
    if (!buffer_read_u16(cdata, &G_context.tx_info.num_witnesses, BE)) {
        TRACE("TX init: missing witnesses count");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Read raw transaction buffer size (advertised by client).
    // Direct stage access: tx_state is still TX_STATE_NONE at this point.
    if (!buffer_read_u16(cdata, &G_context.tx_info.raw_tx_total_length, BE)) {
        TRACE("TX init: missing raw_tx_total_length");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Validate raw buffer size is within limits
    if (G_context.tx_info.raw_tx_total_length == 0) {
        TRACE("TX init: raw_tx_total_length cannot be zero");
        send_swo_and_reset(SWO_WRONG_TX_INIT_APDU_DATA);
        return;
    }
    if (G_context.tx_info.raw_tx_total_length > MAX_TX_BUFFER_SIZE) {
        TRACE("TX init: raw_tx_total_length %u exceeds maximum %u",
              G_context.tx_info.raw_tx_total_length,
              MAX_TX_BUFFER_SIZE);
        send_swo_and_reset(SWO_INVALID_TX_LENGTH);
        return;
    }

    if (deny_unconsumed_bytes(cdata, SWO_WRONG_DATA_LENGTH)) {
        TRACE("TX init APDU not fully consumed");
        return;
    }

    TRACE(
        "TX Mode=%d, Network: ID=%d, Magic=%u, Inputs=%u, Outputs=%u, Certificates=%u, "
        "Withdrawals=%u, Mint=%u, includeTTL=%d, includeVIS=%d, Witnesses=%u, RawTotalLength=%u",
        tx_params->txSigningMode,
        tx_params->networkId,
        tx_params->protocolMagic,
        tx_params->num_inputs,
        tx_params->num_outputs,
        tx_params->num_certificates,
        tx_params->num_withdrawals,
        tx_params->num_mint_asset_groups,
        tx_params->includeTtl,
        tx_params->includeValidityIntervalStart,
        G_context.tx_info.num_witnesses,
        G_context.tx_info.raw_tx_total_length);

    // Resolve AUTO signing mode from init-APDU fields before any policy check.
    if (!resolve_auto_tx_signing_mode(tx_params)) {
        TRACE("TX init: AUTO mode cannot be resolved from init APDU fields alone");
        send_swo_and_reset(SWO_AMBIGUOUS_TX_SIGNING_MODE);
        return;
    }
    TRACE("TX mode after AUTO resolution: %d", tx_params->txSigningMode);

    // Check security policy for DENY at init time (before buffering the tx body).
    // Warning bits are intentionally discarded here; they will be re-set in tx_validate
    // so they are available for UI display.
    {
        warning_bits_t dummy_warnings = 0;
        security_policy_t init_policy = policyForSignTxInit(tx_params, &dummy_warnings);
        TRACE("Transaction init security policy: %d", (int) init_policy);
        if (init_policy == POLICY_DENY) {
            TRACE("Security policy DENY - rejecting transaction init");
            send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
            return;
        }
    }

    // Determine if CVote auxiliary data is expected
    bool cvote_aux_data_expected = (tx_params->includeAuxDataHash &&
                                    (tx_params->auxDataType == AUX_DATA_TYPE_CVOTE_REGISTRATION));

    // Show spinner only in standalone mode; in swap mode UI must stay in Exchange app.
#ifdef HAVE_SWAP
    if (!G_called_from_swap)
#endif
    {
        TRACE("Calling nbgl_useCaseSpinner(\"Processing\")");
        nbgl_useCaseSpinner("Processing");
    }

    if (cvote_aux_data_expected) {
        // Transition to AUX_DATA state; set initial aux_data sub-state before accessor is valid.
        G_context.state.tx_state = TX_STATE_AUX_DATA;
        tx_aux_data_ctx()->cvote_aux_data.state = CVOTE_AUX_DATA_STATE_EXPECTING_INIT;
        TRACE("Transaction initialized, waiting for CVote AUX_DATA");
    } else {
        // Transition directly to CHUNKS state - no aux data expected.
        G_context.state.tx_state = TX_STATE_CHUNKS;
        TRACE("Transaction initialized, waiting for data chunks");
    }

    apdu_response_send_sw(SWO_SUCCESS);
}

/**
 * Helper: Accumulate transaction data chunks into buffer.
 * Returns true on success. On failure, sends SW and resets context.
 */
static bool handle_tx_data_chunk(buffer_t *cdata, bool is_final_chunk) {
    ASSERT(cdata != NULL);
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_CHUNKS, "bad state");
    const size_t chunk_size = buffer_data_size(cdata);
    if (is_final_chunk) {
        if (chunk_size == 0 || chunk_size > MAX_SIGN_TX_CHUNK_SIZE) {
            TRACE("Invalid final tx chunk size: chunk=%u, allowed=[1,%u]",
                  (unsigned) chunk_size,
                  (unsigned) MAX_SIGN_TX_CHUNK_SIZE);
            send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
            return false;
        }
    } else {
        if (chunk_size != MAX_SIGN_TX_CHUNK_SIZE) {
            TRACE("Invalid non-final tx chunk size: chunk=%u, expected=%u",
                  (unsigned) chunk_size,
                  (unsigned) MAX_SIGN_TX_CHUNK_SIZE);
            send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
            return false;
        }
    }

    // Allocate buffer on first data chunk (using advertised size from client)
    if (tx_body_ctx()->raw_tx == NULL) {
        uint16_t alloc_size = G_context.tx_info.raw_tx_total_length;
        TRACE("Allocating transaction buffer: %u bytes (advertised by client)", alloc_size);
        if (!APP_MEM_CALLOC((void **) &tx_body_ctx()->raw_tx, alloc_size)) {
            // LCOV_EXCL_START
            // APP_MEM_CALLOC failure requires OOM condition unreachable in unit tests
            TRACE("Failed to allocate %u byte transaction buffer!", alloc_size);
            send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
            return false;
            // LCOV_EXCL_STOP
        }
        TRACE("Transaction buffer allocated: %u bytes at %p", alloc_size, tx_body_ctx()->raw_tx);
    }

    // Check if adding this chunk would exceed advertised buffer size
    if (tx_body_ctx()->raw_tx_current_length + chunk_size > G_context.tx_info.raw_tx_total_length) {
        TRACE("Transaction chunk exceeds advertised size: current=%u, chunk=%u, total=%u",
              (unsigned) tx_body_ctx()->raw_tx_current_length,
              (unsigned) chunk_size,
              (unsigned) G_context.tx_info.raw_tx_total_length);
        send_swo_and_reset(SWO_INVALID_TX_LENGTH);
        return false;
    }

    // Copy chunk data
    bool chunk_copied = buffer_move(cdata,
                                    tx_body_ctx()->raw_tx + tx_body_ctx()->raw_tx_current_length,
                                    chunk_size);
    LEDGER_ASSERT(chunk_copied, "buffer_move failed unexpectedly");
    tx_body_ctx()->raw_tx_current_length += chunk_size;
    TRACE("Copied %u bytes, total: %u",
          (unsigned) chunk_size,
          (unsigned) tx_body_ctx()->raw_tx_current_length);
    return true;
}

void handler_sign_tx(buffer_t *cdata, uint8_t p1) {
    ASSERT(cdata != NULL);
    TRACE_BUFFER_T(cdata);

    switch (p1) {
        case P1_TX_INIT:
            if (!ensure_sign_tx_request_type(REQUEST_NONE)) {
                return;
            }
            ASSERT(G_context.state.tx_state == TX_STATE_NONE);
#ifdef HAVE_SWAP
            if (G_called_from_swap && G_swap_response_ready) {
                // Safety against trying to make the app sign multiple TXs in swap mode
                TRACE("Safety against double signing triggered");
                swap_reject_and_exit(SWAP_EC_ERROR_GENERIC, SWAP_APP_CODE_MULTI_SIGN);
            }
            if (G_called_from_swap) {
                TRACE("Swap mode transaction started");
            }
#endif
            G_context.req_type = REQUEST_SIGN_TRANSACTION;
            // Keep top-level handler structure consistent with other handlers:
            // zero request context immediately after setting req_type.
            explicit_bzero(&G_context.tx_info, sizeof(G_context.tx_info));
            handle_tx_init_apdu(cdata);
            return;

        case P1_TX_CHUNK:
            if (!ensure_sign_tx_request_type(REQUEST_SIGN_TRANSACTION)) {
                return;
            }
            if (!ensure_sign_tx_state(TX_STATE_CHUNKS)) {
                return;
            }

            // More data chunks to follow
            if (!handle_tx_data_chunk(cdata, false)) {
                return;
            }
            apdu_response_send_sw(SWO_SUCCESS);
            return;

        case P1_TX_CONFIRM:
            if (!ensure_sign_tx_request_type(REQUEST_SIGN_TRANSACTION)) {
                return;
            }
            if (!ensure_sign_tx_state(TX_STATE_CHUNKS)) {
                return;
            }

            // Final chunk
            if (!handle_tx_data_chunk(cdata, true)) {
                return;
            }

            // Verify received length matches advertised length
            if (tx_body_ctx()->raw_tx_current_length != G_context.tx_info.raw_tx_total_length) {
                TRACE("TX length mismatch: received=%u, advertised=%u",
                      (unsigned) tx_body_ctx()->raw_tx_current_length,
                      (unsigned) G_context.tx_info.raw_tx_total_length);
                send_swo_and_reset(SWO_INVALID_TX_LENGTH);
                return;
            }

            // Parse and build hash
            LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_CHUNKS, "bad state");
            G_context.state.tx_state = TX_STATE_RECEIVED;

            if (!tx_validate()) {
                return;
            }

            G_context.state.tx_state = TX_STATE_HASHED;

#ifdef HAVE_SWAP
            if (G_called_from_swap) {
                // In swap mode there is no interactive transaction review, so we intentionally
                // skip TX_STATE_UI_REVIEW and transition directly to TX_STATE_APPROVED.
                // Consequently, finalize_sign_tx() is not used in this flow.
                // Free raw_tx while body slot is still valid, before the union is repurposed.
                APP_MEM_FREE_AND_NULL((void **) &tx_body_ctx()->raw_tx);
                G_context.state.tx_state = TX_STATE_APPROVED;
                tx_witness_ctx()->current_witness = 0;
                apdu_response_send_data(G_context.tx_info.tx_hash,
                                        sizeof(G_context.tx_info.tx_hash),
                                        SWO_SUCCESS);
                return;
            }
#endif

            LEDGER_ASSERT(tx_body_ctx()->total_ui_pairs > 0, "Invalid UI plan");

            bool requires_blind_signing_choice =
                is_blind_signing_enabled() &&
                tx_body_ctx()->total_ui_pairs >= LONG_TX_REVIEW_THRESHOLD;

            if (requires_blind_signing_choice) {
                tx_body_ctx()->review_mode = TX_UI_REVIEW_MODE_PENDING_BLIND_SIGNING_CHOICE;
                G_context.state.tx_state = TX_STATE_UI_REVIEW;
            } else {
                if (!tx_render_ui_or_fail(TX_UI_REVIEW_MODE_DETAILS)) {
                    return;
                }
            }

            apdu_response_deferred();
            if (requires_blind_signing_choice) {
                ui_display_blind_signing_choice();
            } else {
                ui_display_transaction();
            }
            return;

        default:
            TRACE("Unexpected P1 for SIGN_TX");
            send_swo_and_reset(SWO_INCORRECT_P1_P2);
            return;
    }
}

void finalize_sign_tx(void) {
    ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION);
    ASSERT(G_context.state.tx_state == TX_STATE_UI_REVIEW);

    // Transition body -> witness slot. Free raw_tx while body slot is still valid,
    // before the union is repurposed. Then initialize witness sub-state.
    APP_MEM_FREE_AND_NULL((void **) &tx_body_ctx()->raw_tx);
    G_context.state.tx_state = TX_STATE_APPROVED;
    tx_witness_ctx()->current_witness = 0;
    apdu_response_send_data(G_context.tx_info.tx_hash,
                            SIZEOF(G_context.tx_info.tx_hash),
                            SWO_SUCCESS);

    if (G_context.tx_info.num_witnesses == 0) {
        // there are no witnesses, we are done with this tx
        reset_app_context();
    }
}

bool is_last_witness_to_process(void) {
    ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION);
    ASSERT(G_context.state.tx_state == TX_STATE_APPROVED);
    LEDGER_ASSERT(G_context.tx_info.num_witnesses > 0, "No witnesses expected");
    LEDGER_ASSERT(tx_witness_ctx()->current_witness < G_context.tx_info.num_witnesses,
                  "Witness index out of range for final-witness check");
    const uint16_t remaining_witnesses =
        G_context.tx_info.num_witnesses - tx_witness_ctx()->current_witness;
    return (remaining_witnesses == 1);
}

void finalize_witness(void) {
    ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION);
    ASSERT(G_context.state.tx_state == TX_STATE_APPROVED);
    LEDGER_ASSERT(G_context.tx_info.num_witnesses > 0, "No witnesses expected");
    LEDGER_ASSERT(tx_witness_ctx()->current_witness < G_context.tx_info.num_witnesses,
                  "Witness index out of range");

    // Witness confirmed - sign transaction hash with the selected witness path
    getWitness(&tx_witness_ctx()->witness_path,
               G_context.tx_info.tx_hash,
               SIZEOF(G_context.tx_info.tx_hash),
               tx_witness_ctx()->witness_signature,
               SIZEOF(tx_witness_ctx()->witness_signature));

    TRACE_BUFFER(tx_witness_ctx()->witness_signature, ED25519_SIGNATURE_LENGTH);

    const bool is_last_witness = is_last_witness_to_process();

    // Witness confirmed - send signature back
#ifdef HAVE_SWAP
    if (G_called_from_swap && is_last_witness) {
        // Must be set before apdu_response_send_data(): the SDK IO send path checks
        // G_swap_response_ready while transmitting the response and calls os_lib_end()
        // immediately to return control to Exchange.
        TRACE("Swap mode: final witness response will return to Exchange");
        G_swap_response_ready = true;
    }
#endif
    apdu_response_send_data(tx_witness_ctx()->witness_signature,
                            ED25519_SIGNATURE_LENGTH,
                            SWO_SUCCESS);

    if (is_last_witness) {
        // All witnesses processed - reset context to prevent further APDUs for this tx
        // apdu_response_send_data() must consume/copy response bytes before returning,
        // so clearing G_context afterwards does not affect the just-sent signature.
        reset_app_context();
    } else {
        tx_witness_ctx()->current_witness++;
    }
}

void handler_sign_tx_witness(buffer_t *cdata) {
    ASSERT(cdata != NULL);
    TRACE_BUFFER_T(cdata);

    // Verify we're in correct state for witness signing
    if (!ensure_sign_tx_request_type(REQUEST_SIGN_TRANSACTION)) {
        return;
    }

    if (G_context.state.tx_state != TX_STATE_APPROVED) {
        TRACE("Bad state for witness signing: expected TX_STATE_APPROVED, got %d",
              G_context.state.tx_state);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return;
    }

    // Check that we haven't exceeded the expected number of witnesses
    if (tx_witness_ctx()->current_witness >= G_context.tx_info.num_witnesses) {
        TRACE("Witness count exceeded: current=%d, expected=%d",
              tx_witness_ctx()->current_witness,
              G_context.tx_info.num_witnesses);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return;
    }

    // Parse witness path from APDU data
    // buffer_read_bip44_path reads the length byte and all path components
    if (!buffer_read_bip44_path(cdata, &tx_witness_ctx()->witness_path)) {
        TRACE("Witness APDU: failed to parse BIP44 path");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }
    if (deny_unconsumed_bytes(cdata, SWO_WRONG_DATA_LENGTH)) {
        TRACE("Witness APDU not fully consumed");
        return;
    }

    TRACE("Witness %d: path length=%d",
          tx_witness_ctx()->current_witness,
          tx_witness_ctx()->witness_path.length);

    // Check security policy for witness signing
    // Determine if mint is present in the transaction
    bool mintPresent = (G_context.tx_info.tx_params.num_mint_asset_groups > 0);

    // Get pool owner path if this is a pool registration
    const bip44_path_t *poolOwnerPath = NULL;
    switch (G_context.tx_info.tx_params.txSigningMode) {
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
            if (G_context.tx_info.pool_owner_path_present) {
                poolOwnerPath =
                    &G_context.tx_info.pool_owner_path;  // cross-stage field, direct access ok
            }
            break;
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            break;
        default:
            break;
    }

    warning_bits_t witness_warnings = 0;
#ifdef HAVE_SWAP
    const bool isSwap = G_called_from_swap;
#else
    const bool isSwap = false;
#endif
    security_policy_t policy = policyForSignTxWitness(G_context.tx_info.tx_params.txSigningMode,
                                                      isSwap,
                                                      &tx_witness_ctx()->witness_path,
                                                      mintPresent,
                                                      poolOwnerPath,
                                                      &witness_warnings);

    TRACE("Witness security policy: %d", (int) policy);

#ifdef HAVE_SWAP
    // Invariant: swap-validated params must only exist in swap invocation context.
    if (swap_transaction_params_initialized() && !G_called_from_swap) {
        ASSERT(false);
    }
#endif

    // Handle DENY policy
    if (policy == POLICY_DENY) {
        TRACE("Security policy DENY - rejecting witness");
#ifdef HAVE_SWAP
        if (G_called_from_swap) {
            swap_reject_and_exit(SWAP_EC_ERROR_GENERIC, SWAP_APP_CODE_DENIED_WITNESS_POLICY);
        }
#endif
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    switch (policy) {
        case POLICY_HIDE: {
            // POLICY_HIDE: witness does not require user confirmation
            // Finalize directly without displaying UI
            const bool is_last_witness = is_last_witness_to_process();
            finalize_witness();

            // Handle UI state: if this was the last witness, return to main menu.
            if (is_last_witness) {
#ifdef HAVE_SWAP
                LEDGER_ASSERT(!G_called_from_swap,
                              "Swap flow must terminate before returning from finalize_witness");
#endif
                // All witnesses processed - return to main menu
                TRACE("All POLICY_HIDE witnesses complete, returning to main menu");
                ui_menu_main();
            }
            return;
        }

        case POLICY_SHOW:
            apdu_response_deferred();
            ui_display_witness(&tx_witness_ctx()->witness_path, policy, witness_warnings);
            return;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            return;
            // LCOV_EXCL_STOP
    }
}
