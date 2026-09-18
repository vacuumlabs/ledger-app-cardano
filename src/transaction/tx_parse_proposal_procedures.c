/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "buffer.h"

#include "cardano_swo.h"
#include "cardano_constants.h"
#include "cardano_parsers.h"
#include "tx_parse_proposal_procedures.h"
#include "tx.h"
#include "utils.h"
#include "assert.h"

#include <string.h>

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_TX_PARSE to trace this module's parsing details.
 */
#ifdef TRACE_TX_PARSE
#define TRACE_MODULE(...) TRACE("[tx_parse_proposal_procs] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif

// major_protocol_version is bounded to 0..12.
#define PROTOCOL_MAJOR_VERSION_MAX 12

// Bounds the committee threshold denominator so the ratio stays within the range
// format_pool_margin() can safely render.
#define COMMITTEE_THRESHOLD_DENOMINATOR_MAX MARGIN_DENOMINATOR_MAX

static bool parse_opt_gov_action_id(buffer_t *buf, opt_gov_action_id_t *out_opt_gov_action_id) {
    ASSERT(buf != NULL);
    ASSERT(out_opt_gov_action_id != NULL);

    explicit_bzero(out_opt_gov_action_id, sizeof(*out_opt_gov_action_id));

    if (!buffer_read_flag_included(buf, &out_opt_gov_action_id->isIncluded)) {
        return false;
    }
    if (!out_opt_gov_action_id->isIncluded) {
        return true;
    }

    if (!buffer_read_bytes_ptr(buf, &out_opt_gov_action_id->govActionId.txHash, TX_HASH_LENGTH)) {
        return false;
    }
    ASSERT(out_opt_gov_action_id->govActionId.txHash != NULL);

    ASSERT_TYPE(out_opt_gov_action_id->govActionId.govActionIndex, uint32_t);
    if (!buffer_read_u32(buf, &out_opt_gov_action_id->govActionId.govActionIndex, BE)) {
        return false;
    }

    return true;
}

// Reads a flag byte followed by an optional fixed-size script hash, the shape shared by
// treasury_withdrawals_action's and new_constitution's guardrails script hash field.
static bool parse_opt_guardrails_script_hash(buffer_t *buf,
                                             bool *out_has_guardrails_script_hash,
                                             uint8_t *out_guardrails_script_hash) {
    ASSERT(buf != NULL);
    ASSERT(out_has_guardrails_script_hash != NULL);
    ASSERT(out_guardrails_script_hash != NULL);

    if (!buffer_read_flag_included(buf, out_has_guardrails_script_hash)) {
        return false;
    }
    if (*out_has_guardrails_script_hash) {
        if (!buffer_read_bytes(buf, out_guardrails_script_hash, SCRIPT_HASH_LENGTH)) {
            return false;
        }
    }
    return true;
}

static bool parse_no_confidence(buffer_t *buf, gov_action_t *out_gov_action) {
    return parse_opt_gov_action_id(buf, &out_gov_action->noConfidence);
}

static bool parse_hard_fork_initiation(buffer_t *buf, gov_action_t *out_gov_action) {
    hard_fork_initiation_data_t *data = &out_gov_action->hardForkInitiation;

    if (!parse_opt_gov_action_id(buf, &data->prevActionId)) {
        return false;
    }

    uint8_t major = 0;
    if (!buffer_read_u8(buf, &major)) {
        return false;
    }
    if (major > PROTOCOL_MAJOR_VERSION_MAX) {
        return false;
    }
    data->protocolVersion.major = major;

    ASSERT_TYPE(data->protocolVersion.minor, uint32_t);
    if (!buffer_read_u32(buf, &data->protocolVersion.minor, BE)) {
        return false;
    }

    return true;
}

// Parses the whole new_constitution payload in one shot: it has no variable-length list,
// so nothing is left for the caller to stream.
static bool parse_new_constitution(buffer_t *buf, gov_action_t *out_gov_action) {
    new_constitution_data_t *data = &out_gov_action->newConstitution;

    if (!parse_opt_gov_action_id(buf, &data->prevActionId)) {
        return false;
    }

    if (!buffer_read_anchor(buf, &data->constitutionAnchor)) {
        return false;
    }
    if (!data->constitutionAnchor.isIncluded) {
        // The constitution anchor is mandatory: a constitution always documents its own
        // rationale, even when only the guardrails script is being changed.
        return false;
    }

    if (!parse_opt_guardrails_script_hash(buf,
                                          &data->hasGuardrailsScriptHash,
                                          data->guardrailsScriptHash)) {
        return false;
    }

    return true;
}

// Parses only the treasury_withdrawals_action fixed header (guardrails script hash and
// withdrawal count). The withdrawal entries themselves are streamed one at a time by the
// caller via parse_treasury_withdrawal_entry(), and the caller reads the mandatory anchor
// itself once the entries are done -- both happen after this function returns.
static bool parse_treasury_withdrawals_header(buffer_t *buf, gov_action_t *out_gov_action) {
    treasury_withdrawals_data_t *data = &out_gov_action->treasuryWithdrawals;

    if (!parse_opt_guardrails_script_hash(buf,
                                          &data->hasGuardrailsScriptHash,
                                          data->guardrailsScriptHash)) {
        return false;
    }

    if (!buffer_read_u16(buf, &data->numWithdrawals, BE)) {
        return false;
    }
    TRACE_MODULE("numWithdrawals=%u hasGuardrailsScriptHash=%u",
                 (unsigned) data->numWithdrawals,
                 (unsigned) data->hasGuardrailsScriptHash);

    return true;
}

// Parses only the update_committee fixed header (prior gov action id, member counts, and
// committee threshold). The member entries themselves are streamed one at a time by the
// caller, and the caller reads the mandatory anchor itself once the entries are done --
// both happen after this function returns.
static bool parse_update_committee_header(buffer_t *buf, gov_action_t *out_gov_action) {
    update_committee_data_t *data = &out_gov_action->updateCommittee;

    if (!parse_opt_gov_action_id(buf, &data->prevActionId)) {
        return false;
    }

    if (!buffer_read_u16(buf, &data->numMembersToRemove, BE)) {
        return false;
    }
    if (!buffer_read_u16(buf, &data->numMembersToAdd, BE)) {
        return false;
    }

    ASSERT_TYPE(data->thresholdNumerator, uint64_t);
    if (!buffer_read_u64(buf, &data->thresholdNumerator, BE)) {
        return false;
    }
    ASSERT_TYPE(data->thresholdDenominator, uint64_t);
    if (!buffer_read_u64(buf, &data->thresholdDenominator, BE)) {
        return false;
    }
    if (data->thresholdDenominator == 0 ||
        data->thresholdDenominator > COMMITTEE_THRESHOLD_DENOMINATOR_MAX ||
        data->thresholdNumerator > COMMITTEE_THRESHOLD_DENOMINATOR_MAX ||
        data->thresholdNumerator > data->thresholdDenominator) {
        return false;
    }
    TRACE_MODULE("numMembersToRemove=%u numMembersToAdd=%u",
                 (unsigned) data->numMembersToRemove,
                 (unsigned) data->numMembersToAdd);

    return true;
}

static bool parse_param_ratio(buffer_t *buf, param_ratio_t *out_ratio) {
    ASSERT_TYPE(out_ratio->numerator, uint64_t);
    if (!buffer_read_u64(buf, &out_ratio->numerator, BE)) {
        return false;
    }
    ASSERT_TYPE(out_ratio->denominator, uint64_t);
    if (!buffer_read_u64(buf, &out_ratio->denominator, BE)) {
        return false;
    }
    if (out_ratio->denominator == 0) {
        return false;
    }
    // Every ratio is rendered via format_pool_margin() (reused generically, not just for pool
    // margins), which asserts numerator <= UINT64_MAX / 10000. nonnegative_interval fields
    // have no CDDL upper bound, so an out-of-range numerator is rejected here before that
    // assert can fire on wire data.
    return out_ratio->numerator <= UINT64_MAX / 10000;
}

// Reads one protocol_param_update value in the wire shape implied by `kind`; the shape (how
// many u64s, plain vs. ratio) is fully determined by `kind`.
bool parse_param_field(buffer_t *buf, param_field_kind_t kind, parsed_param_field_t *out_field) {
    explicit_bzero(out_field, sizeof(*out_field));
    out_field->kind = kind;

    switch (kind) {
        // COIN carries the same extra range check as every other lovelace amount parsed
        // elsewhere in this app; UINT has no such bound.
        case PARAM_FIELD_COIN:
        case PARAM_FIELD_UINT:
            if (!buffer_read_u64(buf, &out_field->scalar, BE)) {
                return false;
            }
            return kind != PARAM_FIELD_COIN || out_field->scalar < LOVELACE_MAX_SUPPLY;
        case PARAM_FIELD_EX_UNITS:
            return buffer_read_u64(buf, &out_field->exUnits.memory, BE) &&
                   buffer_read_u64(buf, &out_field->exUnits.steps, BE);
        // RATIO/EX_UNIT_PRICES/*_VOTING_THRESHOLDS are all just N consecutive ratios on the
        // wire (N = 1/2/5/10); out_field->ratio (used by RATIO) is the union's alias for
        // ratios[0], so this single loop covers all four kinds.
        case PARAM_FIELD_RATIO:
        case PARAM_FIELD_EX_UNIT_PRICES:
        case PARAM_FIELD_POOL_VOTING_THRESHOLDS:
        case PARAM_FIELD_DREP_VOTING_THRESHOLDS: {
            uint8_t count = param_field_ratio_count(kind);
            for (uint8_t i = 0; i < count; i++) {
                if (!parse_param_ratio(buf, &out_field->ratios[i])) {
                    return false;
                }
            }
            return true;
        }
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown param field kind");
            return false;
            // LCOV_EXCL_STOP
    }
}

// Parses the parameter_change_action fixed header: prior gov action id, the bitmask of which
// of the 29 supported protocol_param_update keys are present, then the optional guardrails
// script hash. The field values themselves are streamed one at a time by the caller, which
// reads the mandatory anchor itself once they are done.
static bool parse_parameter_change_header(buffer_t *buf, gov_action_t *out_gov_action) {
    parameter_change_data_t *data = &out_gov_action->parameterChange;

    if (!parse_opt_gov_action_id(buf, &data->prevActionId)) {
        return false;
    }

    ASSERT_TYPE(data->presentFieldsBitmask, uint64_t);
    if (!buffer_read_u64(buf, &data->presentFieldsBitmask, BE)) {
        return false;
    }
    if ((data->presentFieldsBitmask & ~SUPPORTED_PROTOCOL_PARAM_KEYS_MASK) != 0) {
        return false;
    }

    if (!parse_opt_guardrails_script_hash(buf,
                                          &data->hasGuardrailsScriptHash,
                                          data->guardrailsScriptHash)) {
        return false;
    }

    TRACE_MODULE("presentFieldsBitmask=0x%llx", (unsigned long long) data->presentFieldsBitmask);
    return true;
}

static bool parse_gov_action(buffer_t *buf, gov_action_t *out_gov_action) {
    ASSERT(buf != NULL);
    ASSERT(out_gov_action != NULL);

    uint8_t gov_action_type_wire = 0;
    if (!buffer_read_u8(buf, &gov_action_type_wire)) {
        return false;
    }
    TRACE_MODULE("gov_action_type_wire=%u", gov_action_type_wire);

    out_gov_action->type = (gov_action_type_t) gov_action_type_wire;
    switch (out_gov_action->type) {
        case GOV_ACTION_INFO:
            return true;
        case GOV_ACTION_NO_CONFIDENCE:
            return parse_no_confidence(buf, out_gov_action);
        case GOV_ACTION_HARD_FORK_INITIATION:
            return parse_hard_fork_initiation(buf, out_gov_action);
        case GOV_ACTION_NEW_CONSTITUTION:
            return parse_new_constitution(buf, out_gov_action);
        case GOV_ACTION_TREASURY_WITHDRAWALS:
            return parse_treasury_withdrawals_header(buf, out_gov_action);
        case GOV_ACTION_UPDATE_COMMITTEE:
            return parse_update_committee_header(buf, out_gov_action);
        case GOV_ACTION_PARAMETER_CHANGE:
            return parse_parameter_change_header(buf, out_gov_action);
        default:
            return false;
    }
}

bool parse_proposal_procedure(buffer_t *buf, proposal_procedure_t *out_proposal) {
    ASSERT(buf != NULL);
    ASSERT(out_proposal != NULL);

    explicit_bzero(out_proposal, sizeof(*out_proposal));

    ASSERT_TYPE(out_proposal->deposit, uint64_t);
    if (!buffer_read_u64(buf, &out_proposal->deposit, BE)) {
        return false;
    }
    if (out_proposal->deposit >= LOVELACE_MAX_SUPPLY) {
        return false;
    }

    if (!buffer_read_pool_reward_account(buf, &out_proposal->rewardAccount)) {
        return false;
    }

    if (!parse_gov_action(buf, &out_proposal->govAction)) {
        return false;
    }

    // An action whose payload holds a variable number of entries stops here: the entry count
    // is parsed, but the entries themselves, and the mandatory anchor that follows them, are
    // read by the caller one entry at a time.
    if (out_proposal->govAction.type == GOV_ACTION_TREASURY_WITHDRAWALS ||
        out_proposal->govAction.type == GOV_ACTION_UPDATE_COMMITTEE ||
        out_proposal->govAction.type == GOV_ACTION_PARAMETER_CHANGE) {
        return true;
    }

    if (!buffer_read_anchor(buf, &out_proposal->anchor)) {
        return false;
    }
    if (!out_proposal->anchor.isIncluded) {
        return false;  // Anchor is mandatory
    }

    return true;
}

bool parse_treasury_withdrawal_entry(buffer_t *buf, treasury_withdrawal_entry_t *out_entry) {
    ASSERT(buf != NULL);
    ASSERT(out_entry != NULL);

    explicit_bzero(out_entry, sizeof(*out_entry));

    if (!buffer_read_pool_reward_account(buf, &out_entry->rewardAccount)) {
        return false;
    }

    ASSERT_TYPE(out_entry->coin, uint64_t);
    if (!buffer_read_u64(buf, &out_entry->coin, BE)) {
        return false;
    }
    if (out_entry->coin >= LOVELACE_MAX_SUPPLY) {
        return false;
    }

    return true;
}

bool parse_committee_member_addition(buffer_t *buf, committee_member_addition_t *out_addition) {
    ASSERT(buf != NULL);
    ASSERT(out_addition != NULL);

    explicit_bzero(out_addition, sizeof(*out_addition));

    if (!buffer_read_credential(buf, &out_addition->credential)) {
        return false;
    }

    ASSERT_TYPE(out_addition->expirationEpoch, uint64_t);
    if (!buffer_read_u64(buf, &out_addition->expirationEpoch, BE)) {
        return false;
    }

    return true;
}
