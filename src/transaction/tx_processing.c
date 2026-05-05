/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "buffer.h"
#include "mem.h"

#include "cardano_constants.h"
#include "cardano_swo.h"
#include "cardano_buffer.h"
#include "app_context.h"
#include "cbor.h"
#include "tx_parse.h"
#include "cardano_parsers.h"
#include "securityPolicy.h"
#include "tx_parse_certificates.h"
#include "tx_parse_outputs.h"
#include "tx_processing.h"
#include "tx_processing_outputs.h"
#include "tx_processing_certificates.h"
#include "tx.h"
#include "utils.h"
#include "assert.h"
#include "tx_constants.h"
#include "tx_output_types.h"
#include "keyDerivation.h"
#include "tx_utils.h"
#include "addressUtilsShelley.h"
#include "globals.h"
#include "cardano_settings.h"
#include "sign_tx_ctx.h"
#include "ui_utils.h"
#include "ui_warnings.h"
#include "ui_constants.h"
#include "ui_formatters.h"
#include "ui_address_fields.h"
#include "tx_ui_render.h"
#include "tx_ui_render_certificates.h"
#include "cardano_tokens.h"
#include "bech32.h"
#include "io.h"

#include <stdio.h>
#include <string.h>

#ifdef HAVE_SWAP
#include "swap.h"
#include "swap_lib.h"
#include "swap_error_code_helpers.h"
#endif

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_TX_PROCESSING to trace this module's processing details.
 */
#ifdef TRACE_TX_PROCESSING
#define TRACE_MODULE(...) TRACE("[tx_process] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif

// ---------------------------------------------------------------------------
// Context helpers
// ---------------------------------------------------------------------------

static void tx_processing_mode_validate(const tx_processing_mode_t *mode)
    __attribute__((nonnull(1)));
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull-compare"
#endif
static void tx_processing_mode_validate(const tx_processing_mode_t *mode) {
    ASSERT(mode != NULL);

    LEDGER_ASSERT(!mode->ui_render || !mode->run_hash_builder,
                  "ui_render implies !run_hash_builder");
    LEDGER_ASSERT(!mode->run_hash_builder || mode->run_validation,
                  "run_hash_builder implies run_validation");
    LEDGER_ASSERT(!mode->ui_count_pairs || mode->run_validation,
                  "ui_count_pairs implies run_validation");
}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

static void tx_processing_state_assert_initialized(const tx_processing_state_t *state) {
    ASSERT(state != NULL && state->tx_params != NULL && state->warning_bits != NULL);
    tx_processing_mode_validate(&state->mode);
}

void tx_processing_setup_state(const tx_processing_mode_t *mode, warning_bits_t *warning_bits) {
    tx_processing_mode_validate(mode);
    ASSERT(warning_bits != NULL);

    tx_processing_state_t *state = &tx_body_ctx()->processing_state;
    explicit_bzero(state, sizeof(*state));

    state->tx_params = &G_context.tx_info.tx_params;
    state->mode = *mode;
    state->warning_bits = warning_bits;

    if (mode->run_hash_builder) {
        txHashBuilder_init(&state->hash_builder, state->tx_params);
    }
}

void tx_handle_parse_error(uint16_t swo) {
    TRACE("tx_handle_parse_error swo=0x%04x", swo);
    send_swo_and_reset(swo);
}

// ---------------------------------------------------------------------------
// Credential/DRep/voter conversion helpers (ext → hash-builder format)
// ---------------------------------------------------------------------------

credential_t credential_for_tx_hash_from_ext_credential(const ext_credential_t *credential) {
    ASSERT(credential != NULL);

    credential_t result = {0};
    switch (credential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            result.type = CREDENTIAL_KEY_HASH;
            keyPathToKeyHash(&credential->keyPath, result.keyHash, SIZEOF(result.keyHash));
            break;
        case EXT_CREDENTIAL_KEY_HASH:
            ASSERT(credential->keyHash != NULL);
            result.type = CREDENTIAL_KEY_HASH;
            memmove(result.keyHash, credential->keyHash, SIZEOF(result.keyHash));
            break;
        case EXT_CREDENTIAL_SCRIPT_HASH:
            ASSERT(credential->scriptHash != NULL);
            result.type = CREDENTIAL_SCRIPT_HASH;
            memmove(result.scriptHash, credential->scriptHash, SIZEOF(result.scriptHash));
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            break;
            // LCOV_EXCL_STOP
    }

    return result;
}

drep_t drep_for_tx_hash_from_ext_drep(const ext_drep_t *ext_drep) {
    ASSERT(ext_drep != NULL);

    drep_t result = {
        .type = (drep_type_t) ext_drep->type,
    };

    switch (ext_drep->type) {
        case EXT_DREP_KEY_PATH:
            result.type = DREP_KEY_HASH;
            keyPathToKeyHash(&ext_drep->keyPath, result.keyHash, SIZEOF(result.keyHash));
            break;
        case EXT_DREP_KEY_HASH:
            ASSERT(ext_drep->keyHash != NULL);
            result.type = DREP_KEY_HASH;
            memmove(result.keyHash, ext_drep->keyHash, SIZEOF(result.keyHash));
            break;
        case EXT_DREP_SCRIPT_HASH:
            ASSERT(ext_drep->scriptHash != NULL);
            result.type = DREP_SCRIPT_HASH;
            memmove(result.scriptHash, ext_drep->scriptHash, SIZEOF(result.scriptHash));
            break;
        case EXT_DREP_ABSTAIN:
            result.type = DREP_ABSTAIN;
            break;
        case EXT_DREP_NO_CONFIDENCE:
            result.type = DREP_NO_CONFIDENCE;
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            break;
            // LCOV_EXCL_STOP
    }

    return result;
}

voter_t voter_for_tx_hash_from_ext_voter(const ext_voter_t *ext_voter) {
    ASSERT(ext_voter != NULL);

    voter_t voter = {0};
    switch (ext_voter->type) {
        case EXT_VOTER_COMMITTEE_HOT_KEY_PATH:
            voter.type = VOTER_COMMITTEE_HOT_KEY_HASH;
            keyPathToKeyHash(&ext_voter->keyPath, voter.keyHash, SIZEOF(voter.keyHash));
            break;
        case EXT_VOTER_DREP_KEY_PATH:
            voter.type = VOTER_DREP_KEY_HASH;
            keyPathToKeyHash(&ext_voter->keyPath, voter.keyHash, SIZEOF(voter.keyHash));
            break;
        case EXT_VOTER_STAKE_POOL_KEY_PATH:
            voter.type = VOTER_STAKE_POOL_KEY_HASH;
            keyPathToKeyHash(&ext_voter->keyPath, voter.keyHash, SIZEOF(voter.keyHash));
            break;
        case EXT_VOTER_COMMITTEE_HOT_KEY_HASH:
            ASSERT(ext_voter->keyHash != NULL);
            voter.type = VOTER_COMMITTEE_HOT_KEY_HASH;
            memmove(voter.keyHash, ext_voter->keyHash, SIZEOF(voter.keyHash));
            break;
        case EXT_VOTER_DREP_KEY_HASH:
            ASSERT(ext_voter->keyHash != NULL);
            voter.type = VOTER_DREP_KEY_HASH;
            memmove(voter.keyHash, ext_voter->keyHash, SIZEOF(voter.keyHash));
            break;
        case EXT_VOTER_STAKE_POOL_KEY_HASH:
            ASSERT(ext_voter->keyHash != NULL);
            voter.type = VOTER_STAKE_POOL_KEY_HASH;
            memmove(voter.keyHash, ext_voter->keyHash, SIZEOF(voter.keyHash));
            break;
        case EXT_VOTER_COMMITTEE_HOT_SCRIPT_HASH:
            ASSERT(ext_voter->scriptHash != NULL);
            voter.type = VOTER_COMMITTEE_HOT_SCRIPT_HASH;
            memmove(voter.scriptHash, ext_voter->scriptHash, SIZEOF(voter.scriptHash));
            break;
        case EXT_VOTER_DREP_SCRIPT_HASH:
            ASSERT(ext_voter->scriptHash != NULL);
            voter.type = VOTER_DREP_SCRIPT_HASH;
            memmove(voter.scriptHash, ext_voter->scriptHash, SIZEOF(voter.scriptHash));
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            break;
            // LCOV_EXCL_STOP
    }

    return voter;
}

// ---------------------------------------------------------------------------

bool tx_process_inputs(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    tx_processing_state_assert_initialized(state);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (mode->run_hash_builder) {
        txHashBuilder_enterInputs(&state->hash_builder);
    }

    for (uint16_t input_index = 0; input_index < tx_params->num_inputs; input_index++) {
        tx_input_t parsed_input = {0};
        if (!parse_input(buf, &parsed_input)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_INPUTS);
            return false;
        }

        if (mode->run_validation) {
            security_policy_t input_policy =
                policyForSignTxInput(tx_params->txSigningMode, &parsed_input, state->warning_bits);

            APPLY_POLICY(input_policy,
                         tx_ui_plan_or_render_input,
                         mode,
                         &parsed_input,
                         input_index);
        }

        if (mode->run_hash_builder) {
            txHashBuilder_addInput(&state->hash_builder, &parsed_input);
        }
    }

    return true;
}

bool tx_process_collateral_inputs(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    tx_processing_state_assert_initialized(state);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (tx_params->num_collateral_inputs == 0) {
        return true;
    }

    if (mode->run_hash_builder) {
        txHashBuilder_enterCollateralInputs(&state->hash_builder);
    }

    for (uint16_t input_index = 0; input_index < tx_params->num_collateral_inputs; input_index++) {
        tx_input_t parsed_input = {0};
        if (!parse_input(buf, &parsed_input)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_COLLATERAL_INPUTS);
            return false;
        }

        if (mode->run_validation) {
            security_policy_t collateral_input_policy =
                policyForSignTxCollateralInput(tx_params->txSigningMode,
                                               tx_params->includeTotalCollateral,
                                               &parsed_input,
                                               state->warning_bits);

            APPLY_POLICY(collateral_input_policy,
                         tx_ui_plan_or_render_collateral_input,
                         mode,
                         &parsed_input,
                         input_index);
        }

        if (mode->run_hash_builder) {
            txHashBuilder_addCollateralInput(&state->hash_builder, &parsed_input);
        }
    }

    return true;
}

bool tx_process_reference_inputs(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    tx_processing_state_assert_initialized(state);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (tx_params->num_reference_inputs == 0) {
        return true;
    }

    if (mode->run_hash_builder) {
        txHashBuilder_enterReferenceInputs(&state->hash_builder);
    }

    for (uint16_t input_index = 0; input_index < tx_params->num_reference_inputs; input_index++) {
        tx_input_t parsed_input = {0};
        if (!parse_input(buf, &parsed_input)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_REFERENCE_INPUTS);
            return false;
        }

        if (mode->run_validation) {
            security_policy_t reference_input_policy =
                policyForSignTxReferenceInput(tx_params->txSigningMode,
                                              &parsed_input,
                                              state->warning_bits);

            APPLY_POLICY(reference_input_policy,
                         tx_ui_plan_or_render_reference_input,
                         mode,
                         &parsed_input,
                         input_index);
        }

        if (mode->run_hash_builder) {
            txHashBuilder_addReferenceInput(&state->hash_builder, &parsed_input);
        }
    }

    return true;
}

static bool tx_process_fee(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    uint64_t parsed_fee = 0;
    if (!buffer_read_u64(buf, &parsed_fee, BE)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_FEE);
        return false;
    }
    if (parsed_fee >= LOVELACE_MAX_SUPPLY) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_FEE);
        return false;
    }

    if (mode->run_validation) {
        security_policy_t fee_policy =
            policyForSignTxFee(tx_params->txSigningMode, parsed_fee, state->warning_bits);
        APPLY_POLICY(fee_policy, tx_ui_plan_or_render_fee, mode, parsed_fee);
    }
#ifdef HAVE_SWAP
    if (mode->run_validation && G_called_from_swap && !swap_check_fee_validity(parsed_fee)) {
        swap_reject_and_exit(SWAP_EC_ERROR_WRONG_FEES, SWAP_APP_CODE_DEFAULT);
    }
#endif

    if (mode->run_hash_builder) {
        txHashBuilder_addFee(&state->hash_builder, parsed_fee);
    }
    return true;
}

static bool tx_process_ttl(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (!tx_params->includeTtl) {
        return true;
    }

    uint64_t parsed_ttl = 0;
    if (!buffer_read_u64(buf, &parsed_ttl, BE)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_TTL);
        return false;
    }

    if (mode->run_validation) {
        security_policy_t ttl_policy = policyForSignTxTtl(parsed_ttl, state->warning_bits);
        APPLY_POLICY(ttl_policy, tx_ui_plan_or_render_ttl, mode, parsed_ttl);
    }

    if (mode->run_hash_builder) {
        txHashBuilder_addTtl(&state->hash_builder, parsed_ttl);
    }

    return true;
}

static bool tx_process_withdrawals(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (tx_params->num_withdrawals == 0) {
        return true;
    }

    TRACE_MODULE("tx_process_withdrawals: num_withdrawals=%u",
                 (unsigned) tx_params->num_withdrawals);

    if (mode->run_hash_builder) {
        txHashBuilder_enterWithdrawals(&state->hash_builder);
    }

    ENFORCE_CANONICAL_ORDERING_START(withdrawal_key_tracker);

    for (uint16_t withdrawal_index = 0; withdrawal_index < tx_params->num_withdrawals;
         withdrawal_index++) {
        withdrawal_t parsed_withdrawal = {0};
        TRACE_MODULE("withdrawal %u/%u: parsing",
                     (unsigned) withdrawal_index + 1,
                     (unsigned) tx_params->num_withdrawals);
        if (!parse_withdrawal(buf, &parsed_withdrawal)) {
            TRACE_MODULE("withdrawal %u/%u: parse_withdrawal FAILED",
                         (unsigned) withdrawal_index + 1,
                         (unsigned) tx_params->num_withdrawals);
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_WITHDRAWALS);
            return false;
        }
        TRACE_MODULE("withdrawal %u/%u: amount=%llu cred_type=%u",
                     (unsigned) withdrawal_index + 1,
                     (unsigned) tx_params->num_withdrawals,
                     (unsigned long long) parsed_withdrawal.amount,
                     (unsigned) parsed_withdrawal.stakeCredential.type);

        if (mode->run_validation) {
            security_policy_t withdrawal_policy =
                policyForSignTxWithdrawal(tx_params->txSigningMode,
                                          &parsed_withdrawal.stakeCredential,
                                          state->warning_bits);
            APPLY_POLICY(withdrawal_policy,
                         tx_ui_plan_or_render_withdrawal,
                         mode,
                         &parsed_withdrawal,
                         tx_params->networkId);
        }

        // Optimization: calculate reward address only when needed (canonical check or hashing)
        if (mode->run_validation || mode->run_hash_builder) {
            uint8_t *reward_address = tx_alloc_temp_buffer_or_fail(REWARD_ACCOUNT_LENGTH);

            size_t reward_address_length = 0;
            switch (parsed_withdrawal.stakeCredential.type) {
                case EXT_CREDENTIAL_KEY_PATH:
                    reward_address_length = constructRewardAddressFromKeyPath(
                        &parsed_withdrawal.stakeCredential.keyPath,
                        tx_params->networkId,
                        reward_address,
                        REWARD_ACCOUNT_LENGTH);
                    break;
                case EXT_CREDENTIAL_KEY_HASH:
                    reward_address_length =
                        constructRewardAddressFromHash(tx_params->networkId,
                                                       REWARD_HASH_SOURCE_KEY,
                                                       parsed_withdrawal.stakeCredential.keyHash,
                                                       ADDRESS_KEY_HASH_LENGTH,
                                                       reward_address,
                                                       REWARD_ACCOUNT_LENGTH);
                    break;
                case EXT_CREDENTIAL_SCRIPT_HASH:
                    reward_address_length =
                        constructRewardAddressFromHash(tx_params->networkId,
                                                       REWARD_HASH_SOURCE_SCRIPT,
                                                       parsed_withdrawal.stakeCredential.scriptHash,
                                                       SCRIPT_HASH_LENGTH,
                                                       reward_address,
                                                       REWARD_ACCOUNT_LENGTH);
                    break;
                // LCOV_EXCL_START
                default:
                    LEDGER_ASSERT(false, "Unknown withdrawal credential type");
                    break;
                    // LCOV_EXCL_STOP
            }
            LEDGER_ASSERT(reward_address_length == REWARD_ACCOUNT_LENGTH,
                          "Invalid reward address length");

            ENFORCE_CANONICAL_ORDERING_CHECK(withdrawal_key_tracker,
                                             reward_address,
                                             reward_address_length,
                                             SWO_TX_PARSING_FAIL_CANONICAL_ORDER);

            if (mode->run_hash_builder) {
                txHashBuilder_addWithdrawal(&state->hash_builder,
                                            reward_address,
                                            reward_address_length,
                                            parsed_withdrawal.amount);
            }

            APP_MEM_FREE_AND_NULL((void **) &reward_address);
        }
    }

    return true;
}

static bool tx_process_aux_data_hash(tx_processing_state_t *state) {
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (!tx_params->includeAuxDataHash) {
        return true;
    }

    if (mode->run_validation) {
        security_policy_t aux_data_policy =
            policyForSignTxAuxData(tx_params->auxDataType, state->warning_bits);
        APPLY_POLICY(aux_data_policy,
                     tx_ui_plan_or_render_aux_data_hash,
                     mode,
                     tx_params->auxDataHash);
    }

    if (mode->run_hash_builder) {
        txHashBuilder_addAuxData(&state->hash_builder,
                                 tx_params->auxDataHash,
                                 AUX_DATA_HASH_LENGTH);
    }

    return true;
}

static bool tx_process_validity_interval_start(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (!tx_params->includeValidityIntervalStart) {
        return true;
    }

    uint64_t validity_interval_start = 0;
    if (!buffer_read_u64(buf, &validity_interval_start, BE)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_VALIDITY_INTERVAL_START);
        return false;
    }

    if (mode->run_validation) {
        security_policy_t validity_interval_start_policy =
            policyForSignTxValidityIntervalStart(state->warning_bits);
        APPLY_POLICY(validity_interval_start_policy,
                     tx_ui_plan_or_render_validity_interval_start,
                     mode,
                     validity_interval_start);
    }

    if (mode->run_hash_builder) {
        txHashBuilder_addValidityIntervalStart(&state->hash_builder, validity_interval_start);
    }

    return true;
}

static bool tx_process_mint_tokens(buffer_t *buf,
                                   tx_processing_state_t *state,
                                   const uint8_t *policy_id,
                                   uint16_t number_of_tokens,
                                   security_policy_t mint_policy) {
    ASSERT(buf != NULL);
    ASSERT(policy_id != NULL);
    const tx_processing_mode_t *mode = &state->mode;

    ENFORCE_CANONICAL_ORDERING_START(asset_name_tracker);
    for (uint16_t token_index = 0; token_index < number_of_tokens; token_index++) {
        mint_token_t parsed_mint_token = {.policyId = policy_id};
        if (!parse_mint_token(buf, &parsed_mint_token)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_MINT);
            return false;
        }

        ENFORCE_CANONICAL_ORDERING_CHECK(asset_name_tracker,
                                         parsed_mint_token.assetName,
                                         parsed_mint_token.assetNameLen,
                                         SWO_TX_PARSING_FAIL_CANONICAL_ORDER);

        if (mode->run_validation) {
            APPLY_POLICY(mint_policy, tx_ui_plan_or_render_mint_token, mode, &parsed_mint_token);
        }

        if (mode->run_hash_builder) {
            txHashBuilder_addMint_token(&state->hash_builder,
                                        parsed_mint_token.assetName,
                                        parsed_mint_token.assetNameLen,
                                        parsed_mint_token.amount);
        }
    }

    return true;
}

static bool tx_process_mint(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (tx_params->num_mint_asset_groups == 0) {
        return true;
    }

    security_policy_t mint_policy = POLICY_DENY;
    if (mode->run_validation) {
        mint_policy = policyForSignTxMintInit(tx_params->txSigningMode, state->warning_bits);
        APPLY_POLICY(mint_policy,
                     tx_ui_plan_or_render_mint_summary,
                     mode,
                     tx_params->num_mint_asset_groups);
    }

    if (mode->run_hash_builder) {
        txHashBuilder_enterMint(&state->hash_builder);
        txHashBuilder_addMint_topLevelData(&state->hash_builder, tx_params->num_mint_asset_groups);
    }

    ENFORCE_CANONICAL_ORDERING_START(policy_id_tracker);
    for (uint16_t asset_group_index = 0; asset_group_index < tx_params->num_mint_asset_groups;
         asset_group_index++) {
        const uint8_t *policy_id = NULL;
        if (!buffer_read_bytes_ptr(buf, &policy_id, MINTING_POLICY_ID_LENGTH)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_MINT);
            return false;
        }
        ENFORCE_CANONICAL_ORDERING_CHECK(policy_id_tracker,
                                         policy_id,
                                         MINTING_POLICY_ID_LENGTH,
                                         SWO_TX_PARSING_FAIL_CANONICAL_ORDER);

        uint16_t number_of_tokens = 0;
        if (!buffer_read_u16(buf, &number_of_tokens, BE)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_MINT);
            return false;
        }
        if (number_of_tokens == 0) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_MINT);
            return false;
        }

        if (mode->run_hash_builder) {
            txHashBuilder_addMint_tokenGroup(&state->hash_builder,
                                             policy_id,
                                             MINTING_POLICY_ID_LENGTH,
                                             number_of_tokens);
        }

        if (!tx_process_mint_tokens(buf, state, policy_id, number_of_tokens, mint_policy)) {
            return false;
        }
    }

    return true;
}

static bool tx_process_script_data_hash(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (!tx_params->includeScriptDataHash) {
        return true;
    }

    const uint8_t *script_data_hash = NULL;
    if (!buffer_read_bytes_ptr(buf, &script_data_hash, SCRIPT_DATA_HASH_LENGTH)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_SCRIPT_DATA_HASH);
        return false;
    }

    if (mode->run_validation) {
        security_policy_t script_data_hash_policy =
            policyForSignTxScriptDataHash(tx_params->txSigningMode, state->warning_bits);
        APPLY_POLICY(script_data_hash_policy,
                     tx_ui_plan_or_render_script_data_hash,
                     mode,
                     script_data_hash);
    }

    if (mode->run_hash_builder) {
        txHashBuilder_addScriptDataHash(&state->hash_builder,
                                        script_data_hash,
                                        SCRIPT_DATA_HASH_LENGTH);
    }

    return true;
}

bool tx_process_required_signers(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    tx_processing_state_assert_initialized(state);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    tx_hash_builder_t *hash_builder = &state->hash_builder;

    if (tx_params->num_required_signers == 0) {
        return true;
    }

    if (mode->run_hash_builder) {
        txHashBuilder_enterRequiredSigners(hash_builder);
    }

    for (uint16_t signer_index = 0; signer_index < tx_params->num_required_signers;
         signer_index++) {
        required_signer_t parsed_required_signer = {0};
        if (!parse_required_signer(buf, &parsed_required_signer)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_REQUIRED_SIGNERS);
            return false;
        }

        if (mode->run_validation) {
            security_policy_t signer_policy =
                policyForSignTxRequiredSigner(tx_params->txSigningMode,
                                              &parsed_required_signer,
                                              state->warning_bits);

            APPLY_POLICY(signer_policy,
                         tx_ui_plan_or_render_required_signer,
                         mode,
                         &parsed_required_signer,
                         signer_index);
        }

        if (mode->run_hash_builder) {
            uint8_t signer_key_hash[ADDRESS_KEY_HASH_LENGTH] = {0};
            switch (parsed_required_signer.type) {
                case REQUIRED_SIGNER_WITH_PATH:
                    keyPathToKeyHash(&parsed_required_signer.keyPath,
                                     signer_key_hash,
                                     SIZEOF(signer_key_hash));
                    break;
                case REQUIRED_SIGNER_WITH_HASH:
                    ASSERT(parsed_required_signer.keyHash != NULL);
                    memmove(signer_key_hash,
                            parsed_required_signer.keyHash,
                            SIZEOF(signer_key_hash));
                    break;
                // LCOV_EXCL_START
                default:
                    LEDGER_ASSERT(false, "Unknown required_signer_type_t");
                    break;
                    // LCOV_EXCL_STOP
            }
            txHashBuilder_addRequiredSigner(hash_builder, signer_key_hash, SIZEOF(signer_key_hash));
        }
    }

    return true;
}

static bool tx_process_network_id(tx_processing_state_t *state) {
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (!tx_params->includeNetworkId) {
        return true;
    }

    if (mode->run_hash_builder) {
        txHashBuilder_addNetworkId(&state->hash_builder, tx_params->networkId);
    }

    return true;
}

static bool tx_process_total_collateral(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (!tx_params->includeTotalCollateral) {
        return true;
    }

    uint64_t total_collateral = 0;
    if (!buffer_read_u64(buf, &total_collateral, BE)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_TOTAL_COLLATERAL);
        return false;
    }
    if (total_collateral >= LOVELACE_MAX_SUPPLY) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_TOTAL_COLLATERAL);
        return false;
    }

    if (mode->run_validation) {
        security_policy_t total_collateral_policy =
            policyForSignTxTotalCollateral(state->warning_bits);
        APPLY_POLICY(total_collateral_policy,
                     tx_ui_plan_or_render_total_collateral,
                     mode,
                     total_collateral);
    }

    if (mode->run_hash_builder) {
        txHashBuilder_addTotalCollateral(&state->hash_builder, total_collateral);
    }

    return true;
}

static bool tx_process_vote(tx_processing_state_t *state,
                            const vote_item_t *parsed_vote,
                            security_policy_t voter_policy) {
    const tx_processing_mode_t *mode = &state->mode;

    if (mode->run_validation) {
        APPLY_POLICY(voter_policy, tx_ui_plan_or_render_vote, mode, parsed_vote);
    }

    if (mode->run_validation && parsed_vote->anchor.isIncluded) {
        security_policy_t anchor_policy =
            policyForSignTxAnchor(&parsed_vote->anchor, state->warning_bits);
        APPLY_POLICY(anchor_policy, tx_ui_plan_or_render_vote_anchor, mode, &parsed_vote->anchor);
    }

    if (mode->run_hash_builder) {
        voting_procedure_t voting_procedure = {
            .vote = parsed_vote->voteOption,
            .anchor = parsed_vote->anchor,
        };
        gov_action_id_t gov_action_id = parsed_vote->govActionId;
        txHashBuilder_addVote(&state->hash_builder, &gov_action_id, &voting_procedure);
    }

    return true;
}

static bool tx_process_votes(buffer_t *buf,
                             tx_processing_state_t *state,
                             uint16_t num_votes,
                             security_policy_t voter_policy) {
    ENFORCE_CANONICAL_ORDERING_START(vote_key_tracker);

    for (uint16_t vote_index = 0; vote_index < num_votes; vote_index++) {
        vote_item_t parsed_vote = {0};
        if (!parse_vote(buf, &parsed_vote)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_VOTING_PROCEDURES);
            return false;
        }

        uint8_t *gov_action_key = tx_alloc_temp_buffer_or_fail(MAX_CBOR_GOV_ACTION_MAP_KEY_SIZE);
        size_t gov_action_key_length =
            txHashBuilder_serializeGovActionKey(&parsed_vote.govActionId,
                                                gov_action_key,
                                                MAX_CBOR_GOV_ACTION_MAP_KEY_SIZE);
        ENFORCE_CANONICAL_ORDERING_CHECK(vote_key_tracker,
                                         gov_action_key,
                                         gov_action_key_length,
                                         SWO_TX_PARSING_FAIL_CANONICAL_ORDER);
        APP_MEM_FREE_AND_NULL((void **) &gov_action_key);

        if (!tx_process_vote(state, &parsed_vote, voter_policy)) {
            return false;  // LCOV_EXCL_LINE - voter policy DENY is handled before votes
        }
    }

    return true;
}

static bool tx_process_voting_procedures(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (tx_params->num_voters == 0) {
        return true;
    }

    TRACE_MODULE("tx_process_voting_procedures: num_voters=%u", (unsigned) tx_params->num_voters);

    if (mode->run_hash_builder) {
        txHashBuilder_enterVotingProcedures(&state->hash_builder);
    }
    ENFORCE_CANONICAL_ORDERING_START(voter_key_tracker);

    for (uint16_t voter_index = 0; voter_index < tx_params->num_voters; voter_index++) {
        ext_voter_t parsed_voter = {0};
        uint16_t num_votes = 0;
        TRACE_MODULE("voter %u/%u: parsing header",
                     (unsigned) voter_index + 1,
                     (unsigned) tx_params->num_voters);
        if (!parse_voter_votes_header(buf, &parsed_voter, &num_votes)) {
            TRACE_MODULE("voter %u/%u: parse_voter_votes_header FAILED",
                         (unsigned) voter_index + 1,
                         (unsigned) tx_params->num_voters);
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_VOTING_PROCEDURES);
            return false;
        }
        TRACE_MODULE("voter %u/%u: type=%u num_votes=%u",
                     (unsigned) voter_index + 1,
                     (unsigned) tx_params->num_voters,
                     (unsigned) parsed_voter.type,
                     (unsigned) num_votes);

        security_policy_t voter_policy = POLICY_DENY;
        if (mode->run_validation) {
            voter_policy = policyForSignTxVotingProcedure(tx_params->txSigningMode,
                                                          &parsed_voter,
                                                          state->warning_bits);
            APPLY_POLICY(voter_policy,
                         tx_ui_plan_or_render_voter,
                         mode,
                         &parsed_voter,
                         voter_index);
        }

        voter_t voter_for_hashbuilder = voter_for_tx_hash_from_ext_voter(&parsed_voter);
        uint8_t *voter_key = tx_alloc_temp_buffer_or_fail(MAX_CBOR_VOTER_MAP_KEY_SIZE);
        size_t voter_key_length = txHashBuilder_serializeVoterKey(&voter_for_hashbuilder,
                                                                  voter_key,
                                                                  MAX_CBOR_VOTER_MAP_KEY_SIZE);
        ENFORCE_CANONICAL_ORDERING_CHECK(voter_key_tracker,
                                         voter_key,
                                         voter_key_length,
                                         SWO_TX_PARSING_FAIL_CANONICAL_ORDER);
        APP_MEM_FREE_AND_NULL((void **) &voter_key);

        if (mode->run_hash_builder) {
            txHashBuilder_addVoter(&state->hash_builder, &voter_for_hashbuilder, num_votes);
        }

        if (!tx_process_votes(buf, state, num_votes, voter_policy)) {
            return false;
        }
    }

    return true;
}

static bool tx_process_treasury(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (!tx_params->includeTreasury) {
        return true;
    }

    uint64_t treasury = 0;
    if (!buffer_read_u64(buf, &treasury, BE)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_TREASURY);
        return false;
    }
    if (treasury >= LOVELACE_MAX_SUPPLY) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_TREASURY);
        return false;
    }

    if (mode->run_validation) {
        security_policy_t treasury_policy =
            policyForSignTxTreasury(tx_params->txSigningMode, treasury, state->warning_bits);
        APPLY_POLICY(treasury_policy, tx_ui_plan_or_render_treasury, mode, treasury);
    }

    if (mode->run_hash_builder) {
        txHashBuilder_addTreasury(&state->hash_builder, treasury);
    }

    return true;
}

static bool tx_process_donation(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (!tx_params->includeDonation) {
        return true;
    }

#ifdef HAVE_SWAP
    if (G_called_from_swap) {  // LCOV_EXCL_LINE - swap init rejects donation before body parsing
        // Donation is not part of the Exchange-reviewed ADA amount; reject to prevent
        // a hidden value transfer the user never confirmed.
        swap_reject_and_exit(SWAP_EC_ERROR_GENERIC, SWAP_APP_CODE_DEFAULT);  // LCOV_EXCL_LINE
    }
#endif

    uint64_t donation = 0;
    if (!buffer_read_u64(buf, &donation, BE)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_DONATION);
        return false;
    }
    if (donation >= LOVELACE_MAX_SUPPLY) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_DONATION);
        return false;
    }

    if (mode->run_validation) {
        security_policy_t donation_policy =
            policyForSignTxDonation(tx_params->txSigningMode, donation, state->warning_bits);
        APPLY_POLICY(donation_policy, tx_ui_plan_or_render_donation, mode, donation);
    }

    if (mode->run_hash_builder) {
        txHashBuilder_addDonation(&state->hash_builder, donation);
    }

    return true;
}

// Returns false only when one of the field processors aborts and already handled
// the error path (parse SWO or security SWO).
static bool tx_process_all_fields(buffer_t *buf, tx_processing_state_t *state) {
    if (!tx_process_inputs(buf, state)) {
        return false;
    }
    if (!tx_process_outputs(buf, state)) {
        return false;
    }
    if (!tx_process_fee(buf, state)) {
        return false;
    }
    if (!tx_process_ttl(buf, state)) {
        return false;
    }
    if (!tx_process_certificates(buf, state)) {
        return false;
    }
    if (!tx_process_withdrawals(buf, state)) {
        return false;
    }
    if (!tx_process_aux_data_hash(state)) {
        return false;  // LCOV_EXCL_LINE - valid aux data policies never deny here
    }
    if (!tx_process_validity_interval_start(buf, state)) {
        return false;
    }
    if (!tx_process_mint(buf, state)) {
        return false;
    }
    if (!tx_process_script_data_hash(buf, state)) {
        return false;
    }
    if (!tx_process_collateral_inputs(buf, state)) {
        return false;
    }
    if (!tx_process_required_signers(buf, state)) {
        return false;
    }
    if (!tx_process_network_id(state)) {
        return false;  // LCOV_EXCL_LINE - network id processing has no failing path
    }
    if (!tx_process_collateral_output(buf, state)) {
        return false;
    }
    if (!tx_process_total_collateral(buf, state)) {
        return false;
    }
    if (!tx_process_reference_inputs(buf, state)) {
        return false;
    }
    if (!tx_process_voting_procedures(buf, state)) {
        return false;
    }
    if (!tx_process_treasury(buf, state)) {
        return false;
    }
    if (!tx_process_donation(buf, state)) {
        return false;
    }
    return true;
}

// Returns false only when body processing aborts due to:
// - parsing/canonical-ordering failure (tx_handle_parse_error already sent SWO), or
// - security policy denial (SWO_SECURITY_CONDITION_NOT_SATISFIED sent).
static bool tx_plan_or_render_ui_for_tx_body(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(state != NULL);

    tx_ui_plan_or_render_network_details(&state->mode, state->tx_params);

    if (!tx_process_all_fields(buf, state)) {
        return false;
    }
    return true;
}

bool tx_validate(void) {
    // Reset warning bits and re-run init policy to set network-level warnings
    // (e.g. WARNING_BIT_NETWORK_UNUSUAL) for UI display. The DENY check was already
    // performed in the init APDU handler; here we only need the side-effect of setting
    // warning bits, so a DENY result is an assertion failure (params haven't changed).
    tx_body_ctx()->warning_bits = 0;
    // Re-run init policy solely to set network-level warning bits (e.g.
    // WARNING_BIT_NETWORK_UNUSUAL). The DENY check was already enforced in the init APDU handler so
    // DENY here is a programming error.
    LEDGER_ASSERT(policyForSignTxInit(&G_context.tx_info.tx_params, &tx_body_ctx()->warning_bits) !=
                      POLICY_DENY,
                  "policyForSignTxInit unexpectedly denied in tx_validate");

    // Phase: Pass-1 setup
    static const tx_processing_mode_t validate_mode = {
        .run_validation = true,
        .run_hash_builder = true,
        .ui_count_pairs = true,
        .ui_render = false,
    };
    tx_processing_setup_state(&validate_mode, &tx_body_ctx()->warning_bits);
    tx_body_ctx()->total_ui_pairs = 0;

    tx_processing_state_t *state = &tx_body_ctx()->processing_state;

    // Phase: Body processing
    ASSERT(tx_body_ctx()->raw_tx != NULL);
    buffer_t buf = {
        .ptr = tx_body_ctx()->raw_tx,
        .size = G_context.tx_info.raw_tx_total_length,
        .offset = 0,
    };
    if (!tx_plan_or_render_ui_for_tx_body(&buf, state)) {
        return false;
    }
    if (deny_unconsumed_bytes(&buf, SWO_TX_PARSING_FAIL_BUFFER_NOT_FULLY_CONSUMED)) {
        return false;
    }

    // Phase: Post-processing (hash finalization + tx-hash UI planning)
    txHashBuilder_finalize(&state->hash_builder, G_context.tx_info.tx_hash, TX_HASH_LENGTH);

    security_policy_t tx_hash_policy =
        policyForSignTxDisplayTxHash(state->tx_params->txSigningMode, &tx_body_ctx()->warning_bits);
    APPLY_POLICY(tx_hash_policy,
                 tx_ui_plan_or_render_tx_hash,
                 &state->mode,
                 G_context.tx_info.tx_hash);

    LEDGER_ASSERT(!warning_bits_has_any_cvote_tx_forbidden(tx_body_ctx()->warning_bits),
                  "CVote warning leaked into transaction warnings");

    LEDGER_ASSERT(tx_body_ctx()->total_ui_pairs > 0, "Invalid UI plan");
    TRACE("tx_validate: total_ui_pairs=%u, first_chunk_capacity=%u",
          tx_body_ctx()->total_ui_pairs,
          MAX_UI_PAIRS);
    return true;
}

// Returns false when rendering aborts due to body parse/policy failure
// (the failing subpath already sent SWO).
bool tx_render_ui_chunk(uint16_t from) {
    ASSERT(tx_body_ctx()->raw_tx != NULL);
    buffer_t buf = {
        .ptr = tx_body_ctx()->raw_tx,
        .size = G_context.tx_info.raw_tx_total_length,
        .offset = 0,
    };

    static const tx_processing_mode_t render_mode = {
        .run_validation = true,
        .run_hash_builder = false,
        .ui_count_pairs = false,
        .ui_render = true,
    };
    // Use a copy of warnings for the render pass so it cannot
    // accidentally change global warning state, and we can assert consistency.
    warning_bits_t render_run_warnings = tx_body_ctx()->warning_bits;
    tx_processing_setup_state(&render_mode, &render_run_warnings);

    // Set the render session: pairs before `from` are skipped, OOM stops the chunk.
    ui_render_session_t session = {0};
    ui_render_session_begin(&session, from);

    tx_processing_state_t *state = &tx_body_ctx()->processing_state;
    if (!tx_plan_or_render_ui_for_tx_body(&buf, state)) {
        ui_render_session_end();
        return false;
    }
    LEDGER_ASSERT(!buffer_can_read(&buf, 1), "Render pass did not consume full tx buffer");

    security_policy_t tx_hash_policy =
        policyForSignTxDisplayTxHash(state->tx_params->txSigningMode, &render_run_warnings);
    switch (tx_hash_policy) {
        // LCOV_EXCL_START
        case POLICY_DENY:
            ui_render_session_end();
            LEDGER_ASSERT(false, "unexpected DENY for tx hash");
            return false;
        // LCOV_EXCL_STOP
        case POLICY_SHOW:
            tx_ui_plan_or_render_tx_hash(&state->mode, G_context.tx_info.tx_hash);
            break;
        case POLICY_HIDE:
            break;
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown policy");
            break;
            // LCOV_EXCL_STOP
    }

    // A single streamed chunk may visit only a subset of policy SHOW paths.
    // It must never introduce warning bits that were not discovered during validation.
    LEDGER_ASSERT(
        (render_run_warnings | tx_body_ctx()->warning_bits) == tx_body_ctx()->warning_bits,
        "Render run introduced unexpected warning bits");

    ui_render_session_end();
    return true;
}

bool tx_render_ui(tx_ui_review_mode_e review_mode) {
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION,
                  "tx_render_ui called in wrong state");
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_HASHED ||
                      G_context.state.tx_state == TX_STATE_UI_REVIEW,
                  "tx_render_ui called in wrong tx state");
    LEDGER_ASSERT(
        review_mode == TX_UI_REVIEW_MODE_DETAILS || review_mode == TX_UI_REVIEW_MODE_HASH_ONLY,
        "tx_render_ui called with unsupported review mode");
    const bool initial_render = (G_context.state.tx_state == TX_STATE_HASHED);
    uint16_t total_pairs = (review_mode == TX_UI_REVIEW_MODE_HASH_ONLY)
                               ? UI_PAIRS_TX_HASH
                               : tx_body_ctx()->total_ui_pairs;

    TRACE("Preparing TX review: total_ui_pairs=%u max_ui_pairs=%u", total_pairs, MAX_UI_PAIRS);
    // Allocate the first slab (full size for non-streaming, capped for streaming).
    uint16_t alloc_count = (total_pairs <= MAX_UI_PAIRS) ? total_pairs : MAX_UI_PAIRS;

    ui_reset_error_status();
    if (!ui_pairs_init(alloc_count)) {
        TRACE("ui_pairs_init failed for %u pairs", alloc_count);  // LCOV_EXCL_LINE
        return false;                                             // LCOV_EXCL_LINE
    }

    if (review_mode == TX_UI_REVIEW_MODE_HASH_ONLY) {
        static const tx_processing_mode_t render_mode = {
            .run_validation = false,
            .run_hash_builder = false,
            .ui_count_pairs = false,
            .ui_render = true,
        };
        ui_render_session_t session = {0};
        ui_render_session_begin(&session, 0);
        tx_ui_plan_or_render_tx_hash(&render_mode, G_context.tx_info.tx_hash);
        ui_render_session_end();
    } else {
        // Try to render the first chunk (from pair 0). A `false` result means
        // parsing/security/invariant failure during render pass, not a chunk-size
        // condition (CHUNK_FULL/OOM are reported via UI status and handled below).
        LEDGER_ASSERT(tx_render_ui_chunk(0),
                      "First chunk render unexpectedly failed after successful validation");
    }

    ui_status_t render_status = ui_get_error_status();
    switch (render_status) {
        case UI_STATUS_SUCCESS:
            // Everything fit in a single chunk --- non-streaming path.
            tx_body_ctx()->streaming_mode = false;
            // Hash-only review always lands here; rendered_ui_pairs is irrelevant when
            // streaming_mode is false and is never consulted by the non-streaming path.
            TRACE("tx ui non-streaming");

            // check for consistency in pair counting
            LEDGER_ASSERT(ui_pairs_get_count() == total_pairs, "UI pair count mismatch");
            break;

        case UI_STATUS_CHUNK_FULL:
            // We reached the limit on maximum number of ui strings,
            // need to use streaming path. First chunk is already rendered.
            tx_body_ctx()->streaming_mode = true;
            tx_body_ctx()->rendered_ui_pairs = ui_pairs_get_count();
            LEDGER_ASSERT(tx_body_ctx()->rendered_ui_pairs > 0,
                          "Chunk-full without any rendered pair");
            ui_reset_error_status();
            TRACE("tx ui streaming");
            break;

        case UI_STATUS_OUT_OF_MEMORY:
            // Low-memory boundary during rendering: if at least one pair was rendered,
            // continue in streaming mode and resume from next_ui_pair_index.
            if (ui_pairs_get_count() == 0) {
                TRACE("OOM during first chunk render with zero rendered pairs");
                return false;
            }
            tx_body_ctx()->streaming_mode = true;
            tx_body_ctx()->rendered_ui_pairs = ui_pairs_get_count();
            ui_reset_error_status();
            TRACE("tx ui streaming");
            break;

        // LCOV_EXCL_START
        case UI_STATUS_UNINITIALIZED:
        default:
            LEDGER_ASSERT(false, "Unexpected UI status after first chunk render");
            return false;
            // LCOV_EXCL_STOP
    }

    // Finalize the pairs count for display (may be less than allocated).
    ASSERT(g_pairsList != NULL);
    g_pairsList->nbPairs = (uint8_t) ui_pairs_get_count();

    ui_status_t warning_status = ui_build_warnings(tx_body_ctx()->warning_bits);
    TRACE("ui_build_warnings returned status=%u", (unsigned) warning_status);
    switch (warning_status) {
        case UI_STATUS_SUCCESS:
            break;
        // LCOV_EXCL_START
        case UI_STATUS_OUT_OF_MEMORY:
            return false;
        case UI_STATUS_UNINITIALIZED:
        default:
            LEDGER_ASSERT(false, "Unexpected UI warning status");
            return false;
            // LCOV_EXCL_STOP
    }

    tx_body_ctx()->review_mode = review_mode;
    if (initial_render) {
        G_context.state.tx_state = TX_STATE_UI_REVIEW;
    }
    return true;
}
