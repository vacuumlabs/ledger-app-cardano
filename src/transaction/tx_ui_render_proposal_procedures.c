/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>

#include "os.h"

#include "assert.h"
#include "bech32.h"
#include "cardano_constants.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "tx_credential_types.h"
#include "tx_proposal_procedure_types.h"
#include "tx_ui_pair_counts.h"
#include "tx_ui_render_proposal_procedures.h"
#include "tx_ui_render_shared.h"
#include "ui_constants.h"
#include "ui_formatters.h"
#include "ui_utils.h"
#include "utils.h"

// ---------------------------------------------------------------------------
// Envelope render helpers (pure renderers, no policy awareness)
// ---------------------------------------------------------------------------

static void render_proposal_header(uint16_t proposal_index) {
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Proposal"),
                   MAX_UINT64_STRING_LENGTH,
                   format_index_with_prefix,
                   (uint32_t) proposal_index + 1);
}

static void render_deposit(uint64_t deposit) {
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Deposit"),
                   MAX_ADA_AMOUNT_STRING_LENGTH,
                   format_ada_amount,
                   deposit);
}

void plan_or_render_proposal_envelope(const tx_processing_mode_t *mode,
                                      uint8_t network_id,
                                      const proposal_procedure_t *proposal,
                                      uint16_t proposal_index) {
    UI_PLAN_OR_RENDER(mode, UI_PAIRS_PROPOSAL_ENVELOPE);
    START_COUNT();
    ui_pairs_force_new_page();
    render_proposal_header(proposal_index);
    render_deposit(proposal->deposit);
    UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Reward address", "Reward addr"),
                   MAX_HUMAN_ADDRESS_LENGTH,
                   format_pool_reward_account,
                   network_id,
                   &proposal->rewardAccount);
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Gov action"),
                   MAX_GOV_ACTION_TYPE_LENGTH,
                   format_gov_action_type,
                   proposal->govAction.type);
    CHECK_COUNT(UI_PAIRS_PROPOSAL_ENVELOPE);
}

// Shared by every variant carrying an optional prior gov action id. Takes the optional
// wrapper rather than the id itself so each caller avoids its own isIncluded branch.
void plan_or_render_prev_gov_action_id(const tx_processing_mode_t *mode,
                                       const opt_gov_action_id_t *opt_prev_gov_action_id) {
    if (!opt_prev_gov_action_id->isIncluded) {
        return;
    }
    const gov_action_id_t *prev_gov_action_id = &opt_prev_gov_action_id->govActionId;

    UI_PLAN_OR_RENDER(mode, UI_PAIRS_PROPOSAL_PREV_GOV_ACTION_ID);
    START_COUNT();
    UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Prior gov action tx hash", "Prior tx hash"),
                   MAX_TX_HASH_DISPLAY_LENGTH,
                   format_hex_bytes,
                   prev_gov_action_id->txHash,
                   TX_HASH_LENGTH);
    UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Prior gov action index", "Prior index"),
                   MAX_UINT64_STRING_LENGTH,
                   format_uint64,
                   prev_gov_action_id->govActionIndex);
    CHECK_COUNT(UI_PAIRS_PROPOSAL_PREV_GOV_ACTION_ID);
}

static void plan_or_render_protocol_version(const tx_processing_mode_t *mode,
                                            const protocol_version_t *version) {
    UI_PLAN_OR_RENDER(mode, UI_PAIRS_PROPOSAL_PROTOCOL_VERSION);
    START_COUNT();
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Protocol version"),
                   MAX_PROTOCOL_VERSION_STRING_LENGTH,
                   format_protocol_version,
                   *version);
    CHECK_COUNT(UI_PAIRS_PROPOSAL_PROTOCOL_VERSION);
}

// Shared by new_constitution and treasury_withdrawals_action -- only called when the
// optional guardrails script hash is actually included.
void plan_or_render_guardrails_script_hash(const tx_processing_mode_t *mode,
                                           const uint8_t *guardrails_script_hash) {
    UI_PLAN_OR_RENDER(mode, UI_PAIRS_PROPOSAL_GUARDRAILS_SCRIPT_HASH);
    START_COUNT();
    UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Guardrails script hash", "Guardrails script"),
                   MAX_BECH32_STRING_LENGTH,
                   format_bech32,
                   BECH32_PREFIX_SCRIPT_HASH,
                   guardrails_script_hash,
                   SCRIPT_HASH_LENGTH);
    CHECK_COUNT(UI_PAIRS_PROPOSAL_GUARDRAILS_SCRIPT_HASH);
}

void plan_or_render_treasury_withdrawal(const tx_processing_mode_t *mode,
                                        uint8_t network_id,
                                        const treasury_withdrawal_entry_t *withdrawal) {
    ASSERT(withdrawal != NULL);
    UI_PLAN_OR_RENDER(mode, UI_PAIRS_PROPOSAL_TREASURY_WITHDRAWAL);
    START_COUNT();
    UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Withdrawal reward address", "Withdraw addr"),
                   MAX_HUMAN_ADDRESS_LENGTH,
                   format_pool_reward_account,
                   network_id,
                   &withdrawal->rewardAccount);
    UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Withdrawal amount", "Withdraw amount"),
                   MAX_ADA_AMOUNT_STRING_LENGTH,
                   format_ada_amount,
                   withdrawal->coin);
    CHECK_COUNT(UI_PAIRS_PROPOSAL_TREASURY_WITHDRAWAL);
}

void plan_or_render_no_treasury_withdrawals(const tx_processing_mode_t *mode) {
    plan_or_render_none_label(mode, UI_STATIC_LABEL("Treasury withdrawals"));
}

// The proposal's own anchor. It is mandatory, so isIncluded is always true by the time
// parsing has succeeded.
void plan_or_render_proposal_anchor(const tx_processing_mode_t *mode, const anchor_t *anchor) {
    plan_or_render_labeled_anchor(mode,
                                  anchor,
                                  UI_STATIC_LABEL("Anchor URL"),
                                  UI_STATIC_LABEL("Anchor hash"));
}

// new_constitution carries two anchors: the constitution's and the proposal's own. Distinct
// labels keep the two screens apart.
static void plan_or_render_constitution_anchor(const tx_processing_mode_t *mode,
                                               const anchor_t *anchor) {
    plan_or_render_labeled_anchor(
        mode,
        anchor,
        UI_LABEL_BY_SCREEN("Constitution anchor URL", "Constitution URL"),
        UI_LABEL_BY_SCREEN("Constitution anchor hash", "Constitution hash"));
}

// Sub-labels for the 5 pool_voting_thresholds and 10 drep_voting_thresholds ratios, taken from
// the CDDL field comments. Each key appears at most once per protocol_param_update, so these
// labels are fixed.
static const char *const POOL_VOTING_THRESHOLD_LABELS[5] = {
    "Pool: no confidence",
    "Pool: committee normal",
    "Pool: committee no conf.",
    "Pool: hard fork",
    "Pool: security param",
};
static const char *const DREP_VOTING_THRESHOLD_LABELS[10] = {
    "DRep: no confidence",
    "DRep: committee normal",
    "DRep: committee no conf.",
    "DRep: update constitution",
    "DRep: hard fork",
    "DRep: PP network group",
    "DRep: PP economic group",
    "DRep: PP technical group",
    "DRep: PP governance group",
    "DRep: treasury withdrawal",
};

static uint16_t param_field_pair_count(param_field_kind_t kind) {
    switch (kind) {
        case PARAM_FIELD_COIN:
        case PARAM_FIELD_UINT:
        case PARAM_FIELD_RATIO:
        case PARAM_FIELD_EX_UNITS:  // memory+steps are combined into a single displayed pair
            return UI_PAIRS_PARAM_CHANGE_SIMPLE_FIELD;
        case PARAM_FIELD_EX_UNIT_PRICES:
            return UI_PAIRS_PARAM_CHANGE_EX_UNIT_PRICES;
        case PARAM_FIELD_POOL_VOTING_THRESHOLDS:
            return UI_PAIRS_PARAM_CHANGE_POOL_VOTING_THRESHOLDS;
        case PARAM_FIELD_DREP_VOTING_THRESHOLDS:
            return UI_PAIRS_PARAM_CHANGE_DREP_VOTING_THRESHOLDS;
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown param field kind");
            return 0;
            // LCOV_EXCL_STOP
    }
}

static void render_param_ratio(const char *label, const param_ratio_t *ratio) {
    UI_ADD_FORMAT2(label,
                   MAX_PROFIT_MARGIN_STRING_LENGTH,
                   format_pool_margin,
                   ratio->numerator,
                   ratio->denominator);
}

// Renders N ratios against a fixed label array. The pool and DRep threshold fields differ only
// in which array and count they pass.
static void render_ratio_array(const char *const *labels,
                               const param_ratio_t *ratios,
                               size_t count) {
    // The label arrays live in flash, so each stored pointer is a link-time address that has
    // to go through PIC() before it can be dereferenced.
    const char *const *relocated_labels = (const char *const *) PIC(labels);
    for (size_t i = 0; i < count; i++) {
        render_param_ratio((const char *) PIC(relocated_labels[i]), &ratios[i]);
    }
}

// One protocol_param_update field, generic across every supported key's shape. `label` comes
// from the caller's per-key descriptor table; unused (NULL) for *_VOTING_THRESHOLDS, which
// use their own fixed per-ratio sub-labels instead.
void plan_or_render_param_field(const tx_processing_mode_t *mode,
                                const parsed_param_field_t *field,
                                const char *label) {
    const uint16_t pair_count = param_field_pair_count(field->kind);

    UI_PLAN_OR_RENDER(mode, pair_count);

    START_COUNT();
    switch (field->kind) {
        case PARAM_FIELD_COIN:
            UI_ADD_FORMAT1(label, MAX_ADA_AMOUNT_STRING_LENGTH, format_ada_amount, field->scalar);
            break;
        case PARAM_FIELD_UINT:
            UI_ADD_FORMAT1(label, MAX_UINT64_STRING_LENGTH, format_uint64, field->scalar);
            break;
        case PARAM_FIELD_RATIO:
            render_param_ratio(label, &field->ratio);
            break;
        case PARAM_FIELD_EX_UNIT_PRICES:
            render_param_ratio(UI_STATIC_LABEL("Mem price"), &field->ratios[0]);
            render_param_ratio(UI_STATIC_LABEL("Step price"), &field->ratios[1]);
            break;
        case PARAM_FIELD_EX_UNITS:
            UI_ADD_FORMAT2(label,
                           MAX_EX_UNITS_STRING_LENGTH,
                           format_ex_units,
                           field->exUnits.memory,
                           field->exUnits.steps);
            break;
        case PARAM_FIELD_POOL_VOTING_THRESHOLDS:
            render_ratio_array(POOL_VOTING_THRESHOLD_LABELS,
                               field->ratios,
                               ARRAY_LEN(POOL_VOTING_THRESHOLD_LABELS));
            break;
        case PARAM_FIELD_DREP_VOTING_THRESHOLDS:
            render_ratio_array(DREP_VOTING_THRESHOLD_LABELS,
                               field->ratios,
                               ARRAY_LEN(DREP_VOTING_THRESHOLD_LABELS));
            break;
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown param field kind");
            break;
            // LCOV_EXCL_STOP
    }
    CHECK_COUNT(pair_count);
}

void tx_ui_plan_or_render_proposal_procedure(const tx_processing_mode_t *mode,
                                             uint8_t network_id,
                                             const proposal_procedure_t *proposal,
                                             uint16_t proposal_index) {
    ASSERT(mode != NULL);
    ASSERT(proposal != NULL);

    plan_or_render_proposal_envelope(mode, network_id, proposal, proposal_index);

    switch (proposal->govAction.type) {
        case GOV_ACTION_INFO:
            // No variant-specific payload.
            break;
        case GOV_ACTION_NO_CONFIDENCE:
            plan_or_render_prev_gov_action_id(mode, &proposal->govAction.noConfidence);
            break;
        case GOV_ACTION_HARD_FORK_INITIATION:
            plan_or_render_prev_gov_action_id(mode,
                                              &proposal->govAction.hardForkInitiation.prevActionId);
            plan_or_render_protocol_version(
                mode,
                &proposal->govAction.hardForkInitiation.protocolVersion);
            break;
        case GOV_ACTION_NEW_CONSTITUTION:
            plan_or_render_prev_gov_action_id(mode,
                                              &proposal->govAction.newConstitution.prevActionId);
            plan_or_render_constitution_anchor(
                mode,
                &proposal->govAction.newConstitution.constitutionAnchor);
            if (proposal->govAction.newConstitution.hasGuardrailsScriptHash) {
                plan_or_render_guardrails_script_hash(
                    mode,
                    proposal->govAction.newConstitution.guardrailsScriptHash);
            }
            break;
        // LCOV_EXCL_START
        case GOV_ACTION_TREASURY_WITHDRAWALS:
        case GOV_ACTION_UPDATE_COMMITTEE:
        case GOV_ACTION_PARAMETER_CHANGE:
            // These three are rendered by their own processing functions, which stream their
            // entries.
            LEDGER_ASSERT(false, "Streamed gov action in generic renderer");
            break;
        default:
            LEDGER_ASSERT(false, "Unknown gov action type reached UI rendering");
            break;
            // LCOV_EXCL_STOP
    }

    plan_or_render_proposal_anchor(mode, &proposal->anchor);
}

// ---------------------------------------------------------------------------
// update_committee render helpers (pure renderers, no policy awareness).
// Removed and added members are streamed one at a time and never held in
// proposal_procedure_t, so each one is rendered as it is parsed.
// ---------------------------------------------------------------------------

// Renders a committee member credential with the given labels, plus an expiration epoch when
// one is given (NULL for a removal).
static void plan_or_render_committee_member(const tx_processing_mode_t *mode,
                                            const ext_credential_t *credential,
                                            const char *key_path_label,
                                            const char *key_hash_label,
                                            const char *script_hash_label,
                                            const uint64_t *expiration_epoch) {
    const uint16_t pair_count = expiration_epoch != NULL
                                    ? UI_PAIRS_PROPOSAL_COMMITTEE_MEMBER_ADDITION
                                    : UI_PAIRS_PROPOSAL_COMMITTEE_MEMBER_REMOVAL;

    UI_PLAN_OR_RENDER(mode, pair_count);
    START_COUNT();
    render_credential(credential,
                      key_path_label,
                      key_hash_label,
                      BECH32_PREFIX_COMMITTEE_COLD_KEY_HASH,
                      script_hash_label,
                      BECH32_PREFIX_COMMITTEE_COLD_SCRIPT_HASH);
    if (expiration_epoch != NULL) {
        UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Committee member expiration epoch", "Expiration epoch"),
                       MAX_UINT64_STRING_LENGTH,
                       format_uint64,
                       *expiration_epoch);
    }
    CHECK_COUNT(pair_count);
}

void plan_or_render_committee_member_removal(const tx_processing_mode_t *mode,
                                             const ext_credential_t *credential) {
    ASSERT(credential != NULL);
    plan_or_render_committee_member(
        mode,
        credential,
        UI_LABEL_BY_SCREEN("Remove committee cold key", "Remove cmte key"),
        UI_LABEL_BY_SCREEN("Remove committee cold key hash", "Remove cmte key"),
        UI_LABEL_BY_SCREEN("Remove committee cold script hash", "Remove cmte scr"),
        NULL);
}

void plan_or_render_committee_member_addition(const tx_processing_mode_t *mode,
                                              const committee_member_addition_t *addition) {
    ASSERT(addition != NULL);
    plan_or_render_committee_member(
        mode,
        &addition->credential,
        UI_LABEL_BY_SCREEN("Add committee cold key", "Add cmte key"),
        UI_LABEL_BY_SCREEN("Add committee cold key hash", "Add cmte key"),
        UI_LABEL_BY_SCREEN("Add committee cold script hash", "Add cmte scr"),
        &addition->expirationEpoch);
}

void plan_or_render_committee_no_removals(const tx_processing_mode_t *mode) {
    plan_or_render_none_label(mode, UI_STATIC_LABEL("Committee members removed"));
}

void plan_or_render_committee_no_additions(const tx_processing_mode_t *mode) {
    plan_or_render_none_label(mode, UI_STATIC_LABEL("Committee members added"));
}

void plan_or_render_committee_threshold(const tx_processing_mode_t *mode,
                                        uint64_t numerator,
                                        uint64_t denominator) {
    UI_PLAN_OR_RENDER(mode, UI_PAIRS_PROPOSAL_COMMITTEE_THRESHOLD);
    START_COUNT();
    UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Committee threshold", "Cmte threshold"),
                   MAX_PROFIT_MARGIN_STRING_LENGTH,
                   format_pool_margin,
                   numerator,
                   denominator);
    CHECK_COUNT(UI_PAIRS_PROPOSAL_COMMITTEE_THRESHOLD);
}
