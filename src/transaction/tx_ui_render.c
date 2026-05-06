/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_UI_DISPLAY to trace transaction UI rendering.
 */
#ifdef TRACE_UI_DISPLAY
#define TRACE_MODULE(...) TRACE("[tx_ui_render] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif

#include "assert.h"
#include "bech32.h"
#include "bip44.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "keyDerivation.h"
#include "securityWarnings.h"
#include "securityPolicy.h"
#include "tx_certificate_types.h"
#include "tx_credential_types.h"
#include "tx_ui_pair_counts.h"
#include "tx_ui_render.h"
#include "ui_constants.h"
#include "ui_formatters.h"
#include "ui_utils.h"
#include "cardano_tokens.h"

void tx_ui_plan_or_render_network_details(const tx_processing_mode_t *mode,
                                          const tx_params_t *tx_params) {
    ASSERT(mode != NULL);
    ASSERT(tx_params != NULL);

    if (!shouldShowNetworkDetails(tx_params)) {
        return;
    }

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_NETWORK_DETAILS;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Network ID", "Net ID"),
                       MAX_UINT64_STRING_LENGTH,
                       format_uint64,
                       (uint64_t) tx_params->networkId);
        UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Protocol magic", "Prot magic"),
                       MAX_UINT64_STRING_LENGTH,
                       format_uint64,
                       (uint64_t) tx_params->protocolMagic);
        CHECK_COUNT(UI_PAIRS_NETWORK_DETAILS);
    }
}

void tx_ui_plan_or_render_input(const tx_processing_mode_t *mode,
                                const tx_input_t *parsed_input,
                                uint16_t input_index) {
    ASSERT(mode != NULL);
    ASSERT(parsed_input != NULL);
    TRACE_MODULE("input index=%u count=%d render=%d",
                 (unsigned) input_index,
                 (int) mode->ui_count_pairs,
                 (int) mode->ui_render);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_INPUT;
    } else if (mode->ui_render) {
        START_COUNT();
        if (input_index == 0) {
            ui_pairs_force_new_page();
        }
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Input"),
                       MAX_INPUT_DISPLAY_STRING_LENGTH,
                       format_input_with_index,
                       parsed_input);
        CHECK_COUNT(UI_PAIRS_INPUT);
    }
}

void tx_ui_plan_or_render_collateral_input(const tx_processing_mode_t *mode,
                                           const tx_input_t *parsed_input,
                                           uint16_t input_index) {
    ASSERT(mode != NULL);
    ASSERT(parsed_input != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_COLLATERAL_INPUT;
    } else if (mode->ui_render) {
        START_COUNT();
        if (input_index == 0) {
            ui_pairs_force_new_page();
        }
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Coll input"),
                       MAX_INPUT_DISPLAY_STRING_LENGTH,
                       format_input_with_index,
                       parsed_input);
        CHECK_COUNT(UI_PAIRS_COLLATERAL_INPUT);
    }
}

void tx_ui_plan_or_render_reference_input(const tx_processing_mode_t *mode,
                                          const tx_input_t *parsed_input,
                                          uint16_t input_index) {
    ASSERT(mode != NULL);
    ASSERT(parsed_input != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_REFERENCE_INPUT;
    } else if (mode->ui_render) {
        START_COUNT();
        if (input_index == 0) {
            ui_pairs_force_new_page();
        }
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Ref input"),
                       MAX_INPUT_DISPLAY_STRING_LENGTH,
                       format_input_with_index,
                       parsed_input);
        CHECK_COUNT(UI_PAIRS_REFERENCE_INPUT);
    }
}

void tx_ui_plan_or_render_required_signer(const tx_processing_mode_t *mode,
                                          const required_signer_t *parsed_required_signer,
                                          uint16_t signer_index) {
    ASSERT(mode != NULL);
    ASSERT(parsed_required_signer != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_REQUIRED_SIGNER;
    } else if (mode->ui_render) {
        START_COUNT();
        if (signer_index == 0) {
            ui_pairs_force_new_page();
        }
        switch (parsed_required_signer->type) {
            case REQUIRED_SIGNER_WITH_HASH:
                UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Required signer", "Req signer"),
                               MAX_BECH32_STRING_LENGTH,
                               format_bech32,
                               BECH32_PREFIX_REQUIRED_SIGNER_HASH,
                               parsed_required_signer->keyHash,
                               ADDRESS_KEY_HASH_LENGTH);
                break;
            case REQUIRED_SIGNER_WITH_PATH:
                UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Required signer", "Req signer"),
                               MAX_BIP44_PATH_STRING_LENGTH,
                               format_bip44_path,
                               &parsed_required_signer->keyPath);
                break;
            // LCOV_EXCL_START
            default:
                LEDGER_ASSERT(false, "Unknown required signer type");
                break;
                // LCOV_EXCL_STOP
        }
        CHECK_COUNT(UI_PAIRS_REQUIRED_SIGNER);
    }
}

void tx_ui_plan_or_render_mint_summary(const tx_processing_mode_t *mode,
                                       uint16_t num_mint_asset_groups) {
    ASSERT(mode != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_MINT_SUMMARY;
    } else if (mode->ui_render) {
        START_COUNT();
        ui_pairs_force_new_page();
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Mint"),
                       MAX_MINT_SUMMARY_STRING_LENGTH,
                       format_mint_summary,
                       num_mint_asset_groups);
        CHECK_COUNT(UI_PAIRS_MINT_SUMMARY);
    }
}

void tx_ui_plan_or_render_mint_token(const tx_processing_mode_t *mode,
                                     const mint_token_t *mint_token) {
    ASSERT(mode != NULL);
    ASSERT(mint_token != NULL && mint_token->policyId != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_TOKEN;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Fingerprint"),
                       MAX_TOKEN_FINGERPRINT_STRING_LENGTH,
                       format_asset_fingerprint_bech32,
                       mint_token->policyId,
                       mint_token->assetName,
                       mint_token->assetNameLen);
        UI_ADD_FORMAT4(UI_STATIC_LABEL("Mint amount"),
                       MAX_TOKEN_AMOUNT_STRING_LENGTH,
                       format_token_amount_mint,
                       mint_token->policyId,
                       mint_token->assetName,
                       mint_token->assetNameLen,
                       mint_token->amount);
        CHECK_COUNT(UI_PAIRS_TOKEN);
    }
}

void tx_ui_plan_or_render_fee(const tx_processing_mode_t *mode, uint64_t parsed_fee) {
    ASSERT(mode != NULL);
    TRACE_MODULE("fee count=%d render=%d", (int) mode->ui_count_pairs, (int) mode->ui_render);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_FEE;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Fee"),
                       MAX_ADA_AMOUNT_STRING_LENGTH,
                       format_ada_amount,
                       parsed_fee);
        CHECK_COUNT(UI_PAIRS_FEE);
    }
}

void tx_ui_plan_or_render_ttl(const tx_processing_mode_t *mode, uint64_t parsed_ttl) {
    ASSERT(mode != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_TTL;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT3(UI_STATIC_LABEL("TTL"),
                       MAX_VALIDITY_BOUNDARY_STRING_LENGTH,
                       format_validity_boundary,
                       parsed_ttl,
                       G_context.tx_info.tx_params.networkId,
                       G_context.tx_info.tx_params.protocolMagic);
        CHECK_COUNT(UI_PAIRS_TTL);
    }
}

void tx_ui_plan_or_render_validity_interval_start(const tx_processing_mode_t *mode,
                                                  uint64_t validity_interval_start) {
    ASSERT(mode != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_VALIDITY_INTERVAL_START;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Valid from"),
                       MAX_VALIDITY_BOUNDARY_STRING_LENGTH,
                       format_validity_boundary,
                       validity_interval_start,
                       G_context.tx_info.tx_params.networkId,
                       G_context.tx_info.tx_params.protocolMagic);
        CHECK_COUNT(UI_PAIRS_VALIDITY_INTERVAL_START);
    }
}

void tx_ui_plan_or_render_withdrawal(const tx_processing_mode_t *mode,
                                     const withdrawal_t *parsed_withdrawal,
                                     uint8_t network_id) {
    ASSERT(mode != NULL);
    ASSERT(parsed_withdrawal != NULL);

    const ext_credential_t *credential = &parsed_withdrawal->stakeCredential;

    if (mode->ui_count_pairs) {
        if (credential->type == EXT_CREDENTIAL_KEY_PATH) {
            tx_body_ctx()->total_ui_pairs += UI_PAIRS_WITHDRAWAL_KEY_PATH;
        } else {
            tx_body_ctx()->total_ui_pairs += UI_PAIRS_WITHDRAWAL_OTHER;
        }
    } else if (mode->ui_render) {
        START_COUNT();
        ui_pairs_force_new_page();
        UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Withdrawal amount", "Withdraw amount"),
                       MAX_ADA_AMOUNT_STRING_LENGTH,
                       format_ada_amount,
                       parsed_withdrawal->amount);
        if (credential->type == EXT_CREDENTIAL_KEY_PATH) {
            UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Withdrawal key path", "Withdraw key"),
                           MAX_BIP44_PATH_STRING_LENGTH,
                           format_bip44_path,
                           &credential->keyPath);
        }
        UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Withdraw from", "Withdraw"),
                       MAX_HUMAN_ADDRESS_LENGTH,
                       format_reward_account_from_credential,
                       network_id,
                       credential);
        CHECK_COUNT(credential->type == EXT_CREDENTIAL_KEY_PATH ? UI_PAIRS_WITHDRAWAL_KEY_PATH
                                                                : UI_PAIRS_WITHDRAWAL_OTHER);
    }
}

void tx_ui_plan_or_render_aux_data_hash(const tx_processing_mode_t *mode,
                                        const uint8_t *aux_data_hash) {
    ASSERT(mode != NULL);
    ASSERT(aux_data_hash != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_AUXILIARY_DATA_HASH;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Auxiliary data hash", "Aux data hash"),
                       MAX_TX_HASH_DISPLAY_LENGTH,
                       format_hex_bytes,
                       aux_data_hash,
                       AUX_DATA_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_AUXILIARY_DATA_HASH);
    }
}

void tx_ui_plan_or_render_script_data_hash(const tx_processing_mode_t *mode,
                                           const uint8_t *script_data_hash) {
    ASSERT(mode != NULL);
    ASSERT(script_data_hash != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_SCRIPT_DATA_HASH;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Script data hash", "Script hash"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       BECH32_PREFIX_SCRIPT_DATA_HASH,
                       script_data_hash,
                       SCRIPT_DATA_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_SCRIPT_DATA_HASH);
    }
}

void tx_ui_plan_or_render_total_collateral(const tx_processing_mode_t *mode,
                                           uint64_t total_collateral) {
    ASSERT(mode != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_TOTAL_COLLATERAL;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Total collateral", "Total coll"),
                       MAX_ADA_AMOUNT_STRING_LENGTH,
                       format_ada_amount,
                       total_collateral);
        CHECK_COUNT(UI_PAIRS_TOTAL_COLLATERAL);
    }
}

void tx_ui_plan_or_render_voter(const tx_processing_mode_t *mode,
                                const ext_voter_t *parsed_voter,
                                uint16_t voter_index) {
    ASSERT(mode != NULL);
    ASSERT(parsed_voter != NULL);
    TRACE_MODULE("voter index=%u type=%u count=%d render=%d",
                 (unsigned) voter_index,
                 (unsigned) parsed_voter->type,
                 (int) mode->ui_count_pairs,
                 (int) mode->ui_render);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_VOTER;
    } else if (mode->ui_render) {
        START_COUNT();
        ui_pairs_force_new_page();
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Voter"),
                       MAX_UINT64_STRING_LENGTH,
                       format_index_with_prefix,
                       (uint32_t) voter_index + 1);
        switch (parsed_voter->type) {
            case EXT_VOTER_COMMITTEE_HOT_KEY_PATH:
                UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Committee hot key", "Cmte hot key"),
                               MAX_BIP44_PATH_STRING_LENGTH,
                               format_bip44_path,
                               &parsed_voter->keyPath);
                break;
            case EXT_VOTER_COMMITTEE_HOT_KEY_HASH:
                ASSERT(parsed_voter->keyHash != NULL);
                UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Committee hot key hash", "Cmte hot key"),
                               MAX_BECH32_STRING_LENGTH,
                               format_bech32,
                               BECH32_PREFIX_COMMITTEE_HOT_KEY_HASH,
                               parsed_voter->keyHash,
                               ADDRESS_KEY_HASH_LENGTH);
                break;
            case EXT_VOTER_COMMITTEE_HOT_SCRIPT_HASH:
                ASSERT(parsed_voter->scriptHash != NULL);
                UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Committee hot script hash", "Cmte hot script"),
                               MAX_BECH32_STRING_LENGTH,
                               format_bech32,
                               BECH32_PREFIX_COMMITTEE_HOT_SCRIPT_HASH,
                               parsed_voter->scriptHash,
                               SCRIPT_HASH_LENGTH);
                break;
            case EXT_VOTER_DREP_KEY_PATH:
                UI_ADD_FORMAT1(UI_STATIC_LABEL("DRep key"),
                               MAX_BIP44_PATH_STRING_LENGTH,
                               format_bip44_path,
                               &parsed_voter->keyPath);
                break;
            case EXT_VOTER_DREP_KEY_HASH:
                ASSERT(parsed_voter->keyHash != NULL);
                UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("DRep key hash", "DRep key hash"),
                               MAX_BECH32_STRING_LENGTH,
                               format_bech32,
                               BECH32_PREFIX_DREP_KEY_HASH,
                               parsed_voter->keyHash,
                               ADDRESS_KEY_HASH_LENGTH);
                break;
            case EXT_VOTER_DREP_SCRIPT_HASH:
                ASSERT(parsed_voter->scriptHash != NULL);
                UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("DRep script hash", "DRep script"),
                               MAX_BECH32_STRING_LENGTH,
                               format_bech32,
                               BECH32_PREFIX_DREP_SCRIPT_HASH,
                               parsed_voter->scriptHash,
                               SCRIPT_HASH_LENGTH);
                break;
            case EXT_VOTER_STAKE_POOL_KEY_PATH:
                UI_ADD_FORMAT1(UI_STATIC_LABEL("Stake pool key"),
                               MAX_BIP44_PATH_STRING_LENGTH,
                               format_bip44_path,
                               &parsed_voter->keyPath);
                break;
            case EXT_VOTER_STAKE_POOL_KEY_HASH:
                ASSERT(parsed_voter->keyHash != NULL);
                UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Stake pool key hash", "Pool key hash"),
                               MAX_BECH32_STRING_LENGTH,
                               format_bech32,
                               BECH32_PREFIX_POOL_ID,
                               parsed_voter->keyHash,
                               ADDRESS_KEY_HASH_LENGTH);
                break;
            // LCOV_EXCL_START
            default:
                LEDGER_ASSERT(false, "Unknown voter type");
                break;
                // LCOV_EXCL_STOP
        }
        CHECK_COUNT(UI_PAIRS_VOTER);
    }
}

void tx_ui_plan_or_render_vote(const tx_processing_mode_t *mode, const vote_item_t *parsed_vote) {
    ASSERT(mode != NULL);
    ASSERT(parsed_vote != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_VOTE;
    } else if (mode->ui_render) {
        START_COUNT();
        ui_pairs_force_new_page();
        UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Gov action tx hash", "Action tx hash"),
                       MAX_TX_HASH_DISPLAY_LENGTH,
                       format_hex_bytes,
                       parsed_vote->govActionId.txHash,
                       TX_HASH_LENGTH);
        UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Gov action index", "Action index"),
                       MAX_UINT64_STRING_LENGTH,
                       format_uint64,
                       parsed_vote->govActionId.govActionIndex);
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Vote"),
                       MAX_VOTE_OPTION_LENGTH,
                       format_vote_option,
                       parsed_vote->voteOption);
        CHECK_COUNT(UI_PAIRS_VOTE);
    }
}

void tx_ui_plan_or_render_vote_anchor(const tx_processing_mode_t *mode, const anchor_t *anchor) {
    ASSERT(mode != NULL);
    ASSERT(anchor != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_ANCHOR;
    } else if (mode->ui_render) {
        START_COUNT();
        if (anchor->urlLength == 0) {
            LEDGER_ASSERT(
                warning_bits_has(tx_body_ctx()->warning_bits, WARNING_BIT_EMPTY_ANCHOR_URL),
                "Empty anchor URL warning missing");
            UI_ADD_STATIC(UI_STATIC_LABEL("Anchor URL"), UI_STATIC_LABEL("(empty)"));
        } else {
            UI_ADD_FORMAT2(UI_STATIC_LABEL("Anchor URL"),
                           MAX_ANCHOR_URL_LENGTH,
                           format_url,
                           anchor->url,
                           anchor->urlLength);
        }
        UI_ADD_FORMAT2(UI_STATIC_LABEL("Anchor hash"),
                       MAX_ANCHOR_HASH_STRING_LENGTH,
                       format_hex_bytes,
                       anchor->hash,
                       ANCHOR_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_ANCHOR);
    }
}

void tx_ui_plan_or_render_treasury(const tx_processing_mode_t *mode, uint64_t treasury) {
    ASSERT(mode != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_TREASURY;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Treasury"),
                       MAX_ADA_AMOUNT_STRING_LENGTH,
                       format_ada_amount,
                       treasury);
        CHECK_COUNT(UI_PAIRS_TREASURY);
    }
}

void tx_ui_plan_or_render_donation(const tx_processing_mode_t *mode, uint64_t donation) {
    ASSERT(mode != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_DONATION;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Donation"),
                       MAX_ADA_AMOUNT_STRING_LENGTH,
                       format_ada_amount,
                       donation);
        CHECK_COUNT(UI_PAIRS_DONATION);
    }
}

void tx_ui_plan_or_render_tx_hash(const tx_processing_mode_t *mode, const uint8_t *tx_hash) {
    ASSERT(mode != NULL);
    ASSERT(tx_hash != NULL);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_TX_HASH;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT2(UI_STATIC_LABEL("Tx hash"),
                       MAX_TX_HASH_DISPLAY_LENGTH,
                       format_hex_bytes,
                       tx_hash,
                       TX_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_TX_HASH);
    }
}
