/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "buffer.h"
#include "tx.h"
#include "tx_proposal_procedure_types.h"

/**
 * Parse one proposal_procedure entry (envelope + gov_action payload)
 *
 * Format:
 * - deposit (8 bytes): deposit amount in lovelace
 * - reward_account (variable): type byte (EXT_CREDENTIAL_KEY_HASH or EXT_CREDENTIAL_KEY_PATH)
 *   followed by a 29-byte reward account hash or a BIP44 path
 * - gov_action (variable): type byte (gov_action_type_t) followed by the variant payload
 *   - INFO: none
 *   - NO_CONFIDENCE: prior gov action id
 *   - HARD_FORK_INITIATION: prior gov action id + 1 byte major (<= 12) + 4 bytes minor
 *   - NEW_CONSTITUTION: prior gov action id + constitution anchor + optional guardrails hash
 *   - TREASURY_WITHDRAWALS: optional guardrails hash + withdrawal count
 *   - UPDATE_COMMITTEE: prior gov action id + remove count + add count + threshold ratio
 *   - PARAMETER_CHANGE: prior gov action id + bitmask of the 29 supported
 *     protocol_param_update keys (key 18, cost_models, is rejected) + optional guardrails hash
 * - anchor (variable): URL + hash;
 *
 * TREASURY_WITHDRAWALS, UPDATE_COMMITTEE and PARAMETER_CHANGE get only their fixed header
 * parsed here: the caller streams their entries and reads the anchor itself, so this function
 * returns before the anchor for those three.
 *
 * @param[in]  buf          Buffer with serialized proposal_procedure
 * @param[out] out_proposal Parsed proposal_procedure data
 *
 * @return true on success, false on failure
 */
bool parse_proposal_procedure(buffer_t *buf, proposal_procedure_t *out_proposal);

/**
 * Parse one treasury withdrawal recipient entry.
 *
 * Format:
 * - reward_account (variable): type byte (EXT_CREDENTIAL_KEY_HASH or EXT_CREDENTIAL_KEY_PATH)
 *   followed by a 29-byte reward account hash or a BIP44 path
 * - coin (8 bytes): withdrawal amount in lovelace
 *
 * Called once per withdrawal by tx_process_proposal_procedures, after
 * parse_proposal_procedure() has already read the withdrawal count.
 *
 * @param[in]  buf         Buffer with serialized treasury withdrawal entry
 * @param[out] out_entry   Parsed entry data
 *
 * @return true on success, false on failure
 */
bool parse_treasury_withdrawal_entry(buffer_t *buf, treasury_withdrawal_entry_t *out_entry);

/**
 * Parse one update_committee addition entry: a committee member and its term.
 *
 * Format:
 * - credential (variable): committee cold credential (type byte + data)
 * - expiration_epoch (8 bytes): epoch at which the member's term ends
 *
 * Called once per addition by tx_process_proposal_procedures, after
 * parse_proposal_procedure() has already read the addition count.
 *
 * @param[in]  buf           Buffer with serialized addition entry
 * @param[out] out_addition  Parsed entry data
 *
 * @return true on success, false on failure
 */
bool parse_committee_member_addition(buffer_t *buf, committee_member_addition_t *out_addition);

/**
 * Parse one present protocol_param_update field value, in the wire shape implied by `kind`.
 *
 * Called once per present field (per the bitmask read by parse_parameter_change_header(),
 * internal to this file) by tx_process_proposal_procedures, in ascending CDDL-key order.
 *
 * @param[in]  buf        Buffer with the serialized field value
 * @param[in]  kind        Wire/CBOR shape to parse (see param_field_kind_t)
 * @param[out] out_field   Parsed field value
 *
 * @return true on success, false on failure
 */
bool parse_param_field(buffer_t *buf, param_field_kind_t kind, parsed_param_field_t *out_field);
