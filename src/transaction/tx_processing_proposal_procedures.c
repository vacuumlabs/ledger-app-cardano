/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "buffer.h"
#include "os.h"

#include "cardano_swo.h"
#include "cardano_parsers.h"
#include "tx_parse_proposal_procedures.h"
#include "tx_processing_proposal_procedures.h"
#include "tx.h"
#include "utils.h"
#include "assert.h"
#include "tx_utils.h"
#include "addressUtilsShelley.h"
#include "securityPolicy.h"
#include "tx_ui_render_proposal_procedures.h"

credential_t credential_for_tx_hash_from_ext_credential(const ext_credential_t *credential);

// --------------------------------------------------------------------------
// Shared helpers
// --------------------------------------------------------------------------

// The hash builder takes the reward account as a plain byte buffer.
static uint8_t *reward_account_to_temp_buffer(const pool_reward_account_t *reward_account,
                                              uint8_t network_id) {
    uint8_t *buffer = tx_alloc_temp_buffer_or_fail(REWARD_ACCOUNT_LENGTH);
    poolRewardAccountToBuffer(reward_account, network_id, buffer);
    return buffer;
}

// Envelope policy and rendering, common to every gov_action variant. Returns false when the
// policy denies, at which point the transaction is already rejected.
static bool apply_proposal_envelope_policy(tx_processing_state_t *state,
                                           const proposal_procedure_t *parsed_proposal,
                                           uint16_t proposal_index) {
    if (!state->mode.run_validation) {
        return true;
    }

    const tx_params_t *tx_params = state->tx_params;
    security_policy_t proposal_policy = policyForSignTxProposalProcedure(tx_params->txSigningMode,
                                                                         tx_params->networkId,
                                                                         parsed_proposal,
                                                                         state->warning_bits);
    APPLY_POLICY(proposal_policy,
                 plan_or_render_proposal_envelope,
                 &state->mode,
                 tx_params->networkId,
                 parsed_proposal,
                 proposal_index);
    return true;
}

// Sets WARNING_BIT_EMPTY_ANCHOR_URL when the anchor URL is empty. The planning pass must run
// this: the render pass asserts the warning is present before it draws an empty URL.
static void note_anchor_url_warning(tx_processing_state_t *state, const anchor_t *anchor) {
    security_policy_t anchor_policy = policyForSignTxAnchor(anchor, state->warning_bits);
    LEDGER_ASSERT(anchor_policy == POLICY_SHOW, "Unexpected anchor policy");
}

// Reads the anchor closing a proposal_procedure. It is mandatory: a missing one is a parse
// error.
static bool read_and_render_proposal_anchor(buffer_t *buf,
                                            tx_processing_state_t *state,
                                            anchor_t *out_anchor) {
    if (!buffer_read_anchor(buf, out_anchor) || !out_anchor->isIncluded) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_PROPOSAL_PROCEDURES);
        return false;
    }
    if (state->mode.run_validation) {
        note_anchor_url_warning(state, out_anchor);
        plan_or_render_proposal_anchor(&state->mode, out_anchor);
    }
    return true;
}

// --------------------------------------------------------------------------
// Action 0: parameter_change_action
// --------------------------------------------------------------------------

// One of the 29 supported protocol_param_update keys; cost_models (key 18) is rejected at
// parse time. `kind` drives parsing, hashing and rendering alike. Ordered by ascending CDDL
// key, which is both the bitmask bit order and the canonical-CBOR map key order for hashing.
typedef struct {
    uint8_t cddlKey;
    param_field_kind_t kind;
    // NULL for the threshold rows, which label each ratio individually.
    const char *label;
} param_field_descriptor_t;

static const param_field_descriptor_t PARAM_FIELD_DESCRIPTORS[] = {
    {0, PARAM_FIELD_COIN, "Min fee A"},
    {1, PARAM_FIELD_COIN, "Min fee B"},
    {2, PARAM_FIELD_UINT, "Max block body size"},
    {3, PARAM_FIELD_UINT, "Max tx size"},
    {4, PARAM_FIELD_UINT, "Max block header size"},
    {5, PARAM_FIELD_COIN, "Key deposit"},
    {6, PARAM_FIELD_COIN, "Pool deposit"},
    {7, PARAM_FIELD_UINT, "Max epoch"},
    {8, PARAM_FIELD_UINT, "Pool count"},
    {9, PARAM_FIELD_RATIO, "Pledge influence"},
    {10, PARAM_FIELD_RATIO, "Expansion rate"},
    {11, PARAM_FIELD_RATIO, "Treasury growth"},
    {16, PARAM_FIELD_COIN, "Min pool cost"},
    {17, PARAM_FIELD_COIN, "Ada/UTxO byte"},
    {19, PARAM_FIELD_EX_UNIT_PRICES, "Execution costs"},
    {20, PARAM_FIELD_EX_UNITS, "Max tx units"},
    {21, PARAM_FIELD_EX_UNITS, "Max block units"},
    {22, PARAM_FIELD_UINT, "Max value size"},
    {23, PARAM_FIELD_UINT, "Collateral %"},
    {24, PARAM_FIELD_UINT, "Max coll. inputs"},
    {25, PARAM_FIELD_POOL_VOTING_THRESHOLDS, NULL},
    {26, PARAM_FIELD_DREP_VOTING_THRESHOLDS, NULL},
    {27, PARAM_FIELD_UINT, "Min cmte size"},
    {28, PARAM_FIELD_UINT, "Cmte term limit"},
    {29, PARAM_FIELD_UINT, "Action validity period"},
    {30, PARAM_FIELD_COIN, "Action deposit"},
    {31, PARAM_FIELD_COIN, "DRep deposit"},
    {32, PARAM_FIELD_UINT, "DRep inactivity"},
    {33, PARAM_FIELD_RATIO, "Ref script fee/byte"},
};
#define NUM_PARAM_FIELD_DESCRIPTORS ARRAY_LEN(PARAM_FIELD_DESCRIPTORS)

// A set bit and a descriptor are the same thing: parsing rejects any bit outside the mask.
STATIC_ASSERT(__builtin_popcountll(SUPPORTED_PROTOCOL_PARAM_KEYS_MASK) ==
                  NUM_PARAM_FIELD_DESCRIPTORS,
              "Supported key mask and descriptor table must agree");

// Each present protocol-param field is parsed, displayed and hashed one at a time; the set is
// never held in memory.
static bool process_parameter_change_proposal(buffer_t *buf,
                                              tx_processing_state_t *state,
                                              const proposal_procedure_t *parsed_proposal,
                                              uint16_t proposal_index) {
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;
    const parameter_change_data_t *parameter_change = &parsed_proposal->govAction.parameterChange;

    if (!apply_proposal_envelope_policy(state, parsed_proposal, proposal_index)) {
        return false;
    }
    if (mode->run_validation) {
        plan_or_render_prev_gov_action_id(mode, &parameter_change->prevActionId);
    }

    uint16_t num_present_fields = 0;
    for (size_t i = 0; i < NUM_PARAM_FIELD_DESCRIPTORS; i++) {
        const param_field_descriptor_t *descriptor =
            (const param_field_descriptor_t *) PIC(&PARAM_FIELD_DESCRIPTORS[i]);
        if ((parameter_change->presentFieldsBitmask & (1ULL << descriptor->cddlKey)) != 0) {
            num_present_fields++;
        }
    }

    if (mode->run_hash_builder) {
        uint8_t *reward_account_buffer =
            reward_account_to_temp_buffer(&parsed_proposal->rewardAccount, tx_params->networkId);
        txHashBuilder_parameterChange_enter(&state->hash_builder,
                                            parsed_proposal->deposit,
                                            reward_account_buffer,
                                            REWARD_ACCOUNT_LENGTH,
                                            &parameter_change->prevActionId,
                                            num_present_fields);
        tx_free_temp_buffer((void **) &reward_account_buffer);
    }

    parsed_param_field_t *field =
        (parsed_param_field_t *) tx_alloc_temp_buffer_or_fail(sizeof(parsed_param_field_t));

    for (size_t i = 0; i < NUM_PARAM_FIELD_DESCRIPTORS; i++) {
        const param_field_descriptor_t *descriptor =
            (const param_field_descriptor_t *) PIC(&PARAM_FIELD_DESCRIPTORS[i]);
        if ((parameter_change->presentFieldsBitmask & (1ULL << descriptor->cddlKey)) == 0) {
            continue;
        }

        if (!parse_param_field(buf, descriptor->kind, field)) {
            tx_free_temp_buffer((void **) &field);
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_PROPOSAL_PROCEDURES);
            return false;
        }

        if (mode->run_validation) {
            // NULL for the threshold rows, which label each ratio individually.
            const char *label =
                descriptor->label != NULL ? (const char *) PIC(descriptor->label) : NULL;
            plan_or_render_param_field(mode, field, label);
        }
        if (mode->run_hash_builder) {
            txHashBuilder_parameterChange_addField(&state->hash_builder,
                                                   descriptor->cddlKey,
                                                   field);
        }
    }
    tx_free_temp_buffer((void **) &field);

    if (mode->run_validation && parameter_change->hasGuardrailsScriptHash) {
        plan_or_render_guardrails_script_hash(mode, parameter_change->guardrailsScriptHash);
    }

    anchor_t anchor = {0};
    if (!read_and_render_proposal_anchor(buf, state, &anchor)) {
        return false;
    }

    if (mode->run_hash_builder) {
        txHashBuilder_parameterChange_finish(&state->hash_builder,
                                             parameter_change->hasGuardrailsScriptHash,
                                             parameter_change->guardrailsScriptHash,
                                             &anchor);
    }

    return true;
}

// --------------------------------------------------------------------------
// Action 2: treasury_withdrawals_action
// --------------------------------------------------------------------------

// Each withdrawal entry is parsed, displayed and hashed one at a time; the map is never held
// in memory.
static bool process_treasury_withdrawals_proposal(buffer_t *buf,
                                                  tx_processing_state_t *state,
                                                  const proposal_procedure_t *parsed_proposal,
                                                  uint16_t proposal_index) {
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;
    const treasury_withdrawals_data_t *treasury_withdrawals =
        &parsed_proposal->govAction.treasuryWithdrawals;

    if (!apply_proposal_envelope_policy(state, parsed_proposal, proposal_index)) {
        return false;
    }

    if (mode->run_hash_builder) {
        uint8_t *reward_account_buffer =
            reward_account_to_temp_buffer(&parsed_proposal->rewardAccount, tx_params->networkId);
        txHashBuilder_treasuryWithdrawals_enter(&state->hash_builder,
                                                parsed_proposal->deposit,
                                                reward_account_buffer,
                                                REWARD_ACCOUNT_LENGTH,
                                                treasury_withdrawals->numWithdrawals);
        tx_free_temp_buffer((void **) &reward_account_buffer);
    }

    // Withdrawal recipients
    if (treasury_withdrawals->numWithdrawals > 0) {
        for (uint16_t i = 0; i < treasury_withdrawals->numWithdrawals; i++) {
            treasury_withdrawal_entry_t entry = {0};
            if (!parse_treasury_withdrawal_entry(buf, &entry)) {
                tx_handle_parse_error(SWO_TX_PARSING_FAIL_PROPOSAL_PROCEDURES);
                return false;
            }

            if (mode->run_validation) {
                security_policy_t withdrawal_policy =
                    policyForSignTxProposalProcedureRewardAccount(tx_params->txSigningMode,
                                                                  tx_params->networkId,
                                                                  &entry.rewardAccount,
                                                                  state->warning_bits);
                APPLY_POLICY(withdrawal_policy,
                             plan_or_render_treasury_withdrawal,
                             mode,
                             tx_params->networkId,
                             &entry);
            }

            if (mode->run_hash_builder) {
                uint8_t *withdrawal_reward_account_buffer =
                    reward_account_to_temp_buffer(&entry.rewardAccount, tx_params->networkId);
                txHashBuilder_treasuryWithdrawals_addWithdrawal(&state->hash_builder,
                                                                withdrawal_reward_account_buffer,
                                                                REWARD_ACCOUNT_LENGTH,
                                                                entry.coin);
                tx_free_temp_buffer((void **) &withdrawal_reward_account_buffer);
            }
        }
    } else if (mode->run_validation) {
        plan_or_render_no_treasury_withdrawals(mode);
    }

    if (mode->run_validation && treasury_withdrawals->hasGuardrailsScriptHash) {
        plan_or_render_guardrails_script_hash(mode, treasury_withdrawals->guardrailsScriptHash);
    }

    anchor_t anchor = {0};
    if (!read_and_render_proposal_anchor(buf, state, &anchor)) {
        return false;
    }

    if (mode->run_hash_builder) {
        txHashBuilder_treasuryWithdrawals_finish(&state->hash_builder,
                                                 treasury_withdrawals->hasGuardrailsScriptHash,
                                                 treasury_withdrawals->guardrailsScriptHash,
                                                 &anchor);
    }

    return true;
}

// --------------------------------------------------------------------------
// Action 4: update_committee
// --------------------------------------------------------------------------

static bool process_update_committee_proposal(buffer_t *buf,
                                              tx_processing_state_t *state,
                                              const proposal_procedure_t *parsed_proposal,
                                              uint16_t proposal_index) {
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;
    const update_committee_data_t *update_committee = &parsed_proposal->govAction.updateCommittee;

    if (!apply_proposal_envelope_policy(state, parsed_proposal, proposal_index)) {
        return false;
    }
    if (mode->run_validation) {
        plan_or_render_prev_gov_action_id(mode, &update_committee->prevActionId);
    }

    if (mode->run_hash_builder) {
        uint8_t *reward_account_buffer =
            reward_account_to_temp_buffer(&parsed_proposal->rewardAccount, tx_params->networkId);
        txHashBuilder_updateCommittee_enter(&state->hash_builder,
                                            parsed_proposal->deposit,
                                            reward_account_buffer,
                                            REWARD_ACCOUNT_LENGTH,
                                            &update_committee->prevActionId,
                                            update_committee->numMembersToRemove);
        tx_free_temp_buffer((void **) &reward_account_buffer);
    }

    // Removed committee members
    if (update_committee->numMembersToRemove > 0) {
        for (uint16_t i = 0; i < update_committee->numMembersToRemove; i++) {
            ext_credential_t removed_credential = {0};
            if (!buffer_read_credential(buf, &removed_credential)) {
                tx_handle_parse_error(SWO_TX_PARSING_FAIL_PROPOSAL_PROCEDURES);
                return false;
            }

            if (mode->run_validation) {
                security_policy_t credential_policy =
                    policyForSignTxProposalProcedureCommitteeCredential(&removed_credential,
                                                                        state->warning_bits);
                APPLY_POLICY(credential_policy,
                             plan_or_render_committee_member_removal,
                             mode,
                             &removed_credential);
            }

            if (mode->run_hash_builder) {
                credential_t credential_for_hash =
                    credential_for_tx_hash_from_ext_credential(&removed_credential);
                txHashBuilder_updateCommittee_addRemoval(&state->hash_builder,
                                                         &credential_for_hash);
            }
        }
    } else if (mode->run_validation) {
        plan_or_render_committee_no_removals(mode);
    }

    if (mode->run_hash_builder) {
        txHashBuilder_updateCommittee_enterAdditions(&state->hash_builder,
                                                     update_committee->numMembersToAdd);
    }

    // Added committee members. Canonical ordering is deliberately not enforced: mainnet
    // transactions have been observed with these entries not sorted by encoded credential key,
    // and the network does not require it, so rejecting them would reject valid transactions.
    if (update_committee->numMembersToAdd > 0) {
        for (uint16_t i = 0; i < update_committee->numMembersToAdd; i++) {
            committee_member_addition_t addition = {0};
            if (!parse_committee_member_addition(buf, &addition)) {
                tx_handle_parse_error(SWO_TX_PARSING_FAIL_PROPOSAL_PROCEDURES);
                return false;
            }

            credential_t credential_for_hash =
                credential_for_tx_hash_from_ext_credential(&addition.credential);

            if (mode->run_validation) {
                security_policy_t credential_policy =
                    policyForSignTxProposalProcedureCommitteeCredential(&addition.credential,
                                                                        state->warning_bits);
                APPLY_POLICY(credential_policy,
                             plan_or_render_committee_member_addition,
                             mode,
                             &addition);
            }

            if (mode->run_hash_builder) {
                txHashBuilder_updateCommittee_addAddition(&state->hash_builder,
                                                          &credential_for_hash,
                                                          addition.expirationEpoch);
            }
        }
    } else if (mode->run_validation) {
        plan_or_render_committee_no_additions(mode);
    }

    if (mode->run_validation) {
        plan_or_render_committee_threshold(mode,
                                           update_committee->thresholdNumerator,
                                           update_committee->thresholdDenominator);
    }

    anchor_t anchor = {0};
    if (!read_and_render_proposal_anchor(buf, state, &anchor)) {
        return false;
    }

    if (mode->run_hash_builder) {
        txHashBuilder_updateCommittee_finish(&state->hash_builder,
                                             update_committee->thresholdNumerator,
                                             update_committee->thresholdDenominator,
                                             &anchor);
    }

    return true;
}

// --------------------------------------------------------------------------
// Entry point
// --------------------------------------------------------------------------

bool tx_process_proposal_procedures(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    ASSERT(state != NULL && state->tx_params != NULL && state->warning_bits != NULL);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (tx_params->num_proposal_procedures == 0) {
        return true;
    }

    proposal_procedure_t *parsed_proposal =
        (proposal_procedure_t *) tx_alloc_temp_buffer_or_fail(sizeof(proposal_procedure_t));

    if (mode->run_hash_builder) {
        txHashBuilder_enterProposalProcedures(&state->hash_builder);
    }

    for (uint16_t proposal_index = 0; proposal_index < tx_params->num_proposal_procedures;
         proposal_index++) {
        explicit_bzero(parsed_proposal, sizeof(proposal_procedure_t));

        if (!parse_proposal_procedure(buf, parsed_proposal)) {
            tx_free_temp_buffer((void **) &parsed_proposal);
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_PROPOSAL_PROCEDURES);
            return false;
        }

        // parse_proposal_procedure() has read every field, except for the actions with a
        // variable number of entries: for those it stops at the fixed header, leaving the
        // entries and the trailing anchor unread, and each parses its own remainder in its
        // own case. The rest are complete; the two calls after the switch render and hash them.
        switch (parsed_proposal->govAction.type) {
            case GOV_ACTION_PARAMETER_CHANGE:
                if (!process_parameter_change_proposal(buf,
                                                       state,
                                                       parsed_proposal,
                                                       proposal_index)) {
                    return false;
                }
                continue;
            case GOV_ACTION_TREASURY_WITHDRAWALS:
                if (!process_treasury_withdrawals_proposal(buf,
                                                           state,
                                                           parsed_proposal,
                                                           proposal_index)) {
                    return false;
                }
                continue;
            case GOV_ACTION_UPDATE_COMMITTEE:
                if (!process_update_committee_proposal(buf,
                                                       state,
                                                       parsed_proposal,
                                                       proposal_index)) {
                    return false;
                }
                continue;
            // Nothing pending: rendered and hashed by the two calls after the switch.
            case GOV_ACTION_INFO:
            case GOV_ACTION_NO_CONFIDENCE:
            case GOV_ACTION_HARD_FORK_INITIATION:
            case GOV_ACTION_NEW_CONSTITUTION:
                break;
        }

        if (mode->run_validation) {
            note_anchor_url_warning(state, &parsed_proposal->anchor);
            if (parsed_proposal->govAction.type == GOV_ACTION_NEW_CONSTITUTION) {
                note_anchor_url_warning(
                    state,
                    &parsed_proposal->govAction.newConstitution.constitutionAnchor);
            }
            security_policy_t proposal_policy =
                policyForSignTxProposalProcedure(tx_params->txSigningMode,
                                                 tx_params->networkId,
                                                 parsed_proposal,
                                                 state->warning_bits);
            APPLY_POLICY(proposal_policy,
                         tx_ui_plan_or_render_proposal_procedure,
                         mode,
                         tx_params->networkId,
                         parsed_proposal,
                         proposal_index);
        }

        if (mode->run_hash_builder) {
            uint8_t *reward_account_buffer =
                reward_account_to_temp_buffer(&parsed_proposal->rewardAccount,
                                              tx_params->networkId);
            txHashBuilder_addProposalProcedure(&state->hash_builder,
                                               parsed_proposal->deposit,
                                               reward_account_buffer,
                                               REWARD_ACCOUNT_LENGTH,
                                               &parsed_proposal->govAction,
                                               &parsed_proposal->anchor);
            tx_free_temp_buffer((void **) &reward_account_buffer);
        }
    }

    tx_free_temp_buffer((void **) &parsed_proposal);
    return true;
}
