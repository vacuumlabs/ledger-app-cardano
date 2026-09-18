/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "tx_certificate_types.h"  // For anchor_t, gov_action_id_t
#include "tx_address_types.h"      // For pool_reward_account_t
#include "tx_credential_types.h"   // For ext_credential_t

typedef enum {
    GOV_ACTION_PARAMETER_CHANGE = 0,
    GOV_ACTION_HARD_FORK_INITIATION = 1,
    GOV_ACTION_TREASURY_WITHDRAWALS = 2,
    GOV_ACTION_NO_CONFIDENCE = 3,
    GOV_ACTION_UPDATE_COMMITTEE = 4,
    GOV_ACTION_NEW_CONSTITUTION = 5,
    GOV_ACTION_INFO = 6,
} gov_action_type_t;

// ---------------------------------------------------------------------------
// Shared by several actions
// ---------------------------------------------------------------------------

// gov_action_id / nil. Every action except treasury_withdrawals and info_action
// references a prior action id this way.
typedef struct {
    bool isIncluded;
    gov_action_id_t govActionId;
} opt_gov_action_id_t;

// ---------------------------------------------------------------------------
// Action 0: parameter_change_action
// ---------------------------------------------------------------------------

// The protocol_param_update keys the app can parse, display and hash: 0-11, 16, 17 and 19-33.
// Key 18 (cost_models) is left out because it is not reviewable on a small screen. No other
// key is defined, so a bitmask carrying any bit outside this set fails parsing.
#define SUPPORTED_PROTOCOL_PARAM_KEYS_MASK 0x00000003FFFB0FFFULL

typedef struct {
    uint64_t numerator;
    uint64_t denominator;
} param_ratio_t;

// drep_voting_thresholds is the largest compound field.
#define PARAM_FIELD_MAX_RATIOS 10

typedef enum {
    PARAM_FIELD_COIN,                    // plain lovelace amount
    PARAM_FIELD_UINT,                    // plain unsigned count
    PARAM_FIELD_RATIO,                   // single unit_interval / nonnegative_interval
    PARAM_FIELD_EX_UNIT_PRICES,          // [mem_price, step_price]: 2 ratios
    PARAM_FIELD_EX_UNITS,                // [memory, steps]: 2 plain counts
    PARAM_FIELD_POOL_VOTING_THRESHOLDS,  // 5 ratios
    PARAM_FIELD_DREP_VOTING_THRESHOLDS,  // 10 ratios
} param_field_kind_t;

// A single protocol_param_update value, generic across every supported key's wire shape. Kept
// as one tagged union so parsing, hashing and UI can loop over a shared per-key descriptor
// table.
typedef struct {
    param_field_kind_t kind;
    union {
        uint64_t scalar;  // COIN / UINT
        param_ratio_t ratio;
        struct {
            uint64_t memory;
            uint64_t steps;
        } exUnits;
        // EX_UNIT_PRICES uses ratios[0..1]; *_VOTING_THRESHOLDS use ratios[0..4]/[0..9].
        param_ratio_t ratios[PARAM_FIELD_MAX_RATIOS];
    };
} parsed_param_field_t;

// Number of param_ratio_t entries a field of this kind carries (0 for COIN/UINT/EX_UNITS, which
// have no ratio sub-values). Shared by parsing, hashing, and UI rendering so each needs only one
// generic "loop over N ratios" case.
static inline uint8_t param_field_ratio_count(param_field_kind_t kind) {
    switch (kind) {
        case PARAM_FIELD_RATIO:
            return 1;
        case PARAM_FIELD_EX_UNIT_PRICES:
            return 2;
        case PARAM_FIELD_POOL_VOTING_THRESHOLDS:
            return 5;
        case PARAM_FIELD_DREP_VOTING_THRESHOLDS:
            return PARAM_FIELD_MAX_RATIOS;
        default:
            return 0;
    }
}

typedef struct {
    opt_gov_action_id_t prevActionId;
    // Bit N set means protocol_param_update key N is present on the wire.
    // Parsing rejects any bit outside SUPPORTED_PROTOCOL_PARAM_KEYS_MASK.
    uint64_t presentFieldsBitmask;
    bool hasGuardrailsScriptHash;
    uint8_t guardrailsScriptHash[SCRIPT_HASH_LENGTH];
} parameter_change_data_t;

// ---------------------------------------------------------------------------
// Action 1: hard_fork_initiation_action
// ---------------------------------------------------------------------------

// major_protocol_version is bounded to 0..12; enforced in the parser.
typedef struct {
    uint32_t major;
    uint32_t minor;
} protocol_version_t;

typedef struct {
    opt_gov_action_id_t prevActionId;
    protocol_version_t protocolVersion;
} hard_fork_initiation_data_t;

// ---------------------------------------------------------------------------
// Action 2: treasury_withdrawals_action
// ---------------------------------------------------------------------------

// Withdrawal recipients are counted here and parsed one at a time as
// treasury_withdrawal_entry_t, never held in memory as a list.
typedef struct {
    bool hasGuardrailsScriptHash;
    uint8_t guardrailsScriptHash[SCRIPT_HASH_LENGTH];
    uint16_t numWithdrawals;
} treasury_withdrawals_data_t;

typedef struct {
    pool_reward_account_t rewardAccount;
    uint64_t coin;
} treasury_withdrawal_entry_t;

// ---------------------------------------------------------------------------
// Action 3: no_confidence
// Carries only the prior gov action id, so it reuses opt_gov_action_id_t and
// defines no type of its own.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Action 4: update_committee
// ---------------------------------------------------------------------------

// Removed and added committee members are counted here and parsed one at a
// time (ext_credential_t for a removal, committee_member_addition_t for an
// addition), never held in memory as a list.
typedef struct {
    opt_gov_action_id_t prevActionId;
    uint16_t numMembersToRemove;
    uint16_t numMembersToAdd;
    uint64_t thresholdNumerator;
    uint64_t thresholdDenominator;
} update_committee_data_t;

typedef struct {
    ext_credential_t credential;
    uint64_t expirationEpoch;
} committee_member_addition_t;

// ---------------------------------------------------------------------------
// Action 5: new_constitution
// ---------------------------------------------------------------------------

// This action changes the constitution and/or the guardrails script;
// constitutionAnchor is required either way, since a constitution is always
// anchored to a document even when only the guardrails script changes. It is
// separate from proposal_procedure_t.anchor, which documents the rationale
// for the proposal itself.
typedef struct {
    opt_gov_action_id_t prevActionId;
    anchor_t constitutionAnchor;
    bool hasGuardrailsScriptHash;
    uint8_t guardrailsScriptHash[SCRIPT_HASH_LENGTH];
} new_constitution_data_t;

// ---------------------------------------------------------------------------
// Action 6: info_action
// Has no payload, so it defines no type and has no member in gov_action_t.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Proposal envelope
// ---------------------------------------------------------------------------

typedef struct {
    gov_action_type_t type;
    union {
        parameter_change_data_t parameterChange;
        hard_fork_initiation_data_t hardForkInitiation;
        treasury_withdrawals_data_t treasuryWithdrawals;
        opt_gov_action_id_t noConfidence;
        update_committee_data_t updateCommittee;
        new_constitution_data_t newConstitution;
    };
} gov_action_t;

typedef struct {
    uint64_t deposit;
    pool_reward_account_t rewardAccount;
    gov_action_t govAction;
    anchor_t anchor;
} proposal_procedure_t;
