/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>

#include "tx_credential_types.h"
#include "tx_parse.h"
#include "tx_proposal_procedure_types.h"

/**
 * Handle UI planning and rendering for a single proposal_procedure.
 *
 * Covers the shared envelope (deposit, reward account, gov action type, mandatory anchor)
 * and the currently-supported variant payloads (info_action, no_confidence,
 * hard_fork_initiation_action, new_constitution). update_committee, treasury_withdrawals_action,
 * and parameter_change_action are excluded: their entries (removed/added committee members,
 * withdrawal entries, present protocol-param fields) are never held in proposal_procedure_t,
 * so each has its own processing function that streams them.
 *
 * On the planning pass (mode->ui_count_pairs), adds the appropriate pair count
 * to G_context.tx_info.planned_ui_pairs.
 * On the rendering pass (mode->ui_render), renders all UI pairs for the proposal.
 */
void tx_ui_plan_or_render_proposal_procedure(const tx_processing_mode_t *mode,
                                             uint8_t network_id,
                                             const proposal_procedure_t *proposal,
                                             uint16_t proposal_index);

// ---------------------------------------------------------------------------
// Shared envelope/anchor helpers (no policy awareness).
// update_committee's removed and added members are streamed one at a time and never held
// in proposal_procedure_t, so the generic renderer cannot draw them.
// ---------------------------------------------------------------------------
void plan_or_render_proposal_envelope(const tx_processing_mode_t *mode,
                                      uint8_t network_id,
                                      const proposal_procedure_t *proposal,
                                      uint16_t proposal_index);
// Renders the prior gov action id when present; a no-op when it isn't, so callers need no
// isIncluded branch of their own.
void plan_or_render_prev_gov_action_id(const tx_processing_mode_t *mode,
                                       const opt_gov_action_id_t *opt_prev_gov_action_id);
void plan_or_render_proposal_anchor(const tx_processing_mode_t *mode, const anchor_t *anchor);

// Shared by new_constitution and treasury_withdrawals_action -- only called when the
// optional guardrails script hash is actually included.
void plan_or_render_guardrails_script_hash(const tx_processing_mode_t *mode,
                                           const uint8_t *guardrails_script_hash);

void plan_or_render_treasury_withdrawal(const tx_processing_mode_t *mode,
                                        uint8_t network_id,
                                        const treasury_withdrawal_entry_t *withdrawal);
void plan_or_render_no_treasury_withdrawals(const tx_processing_mode_t *mode);

void plan_or_render_committee_member_removal(const tx_processing_mode_t *mode,
                                             const ext_credential_t *credential);
void plan_or_render_committee_member_addition(const tx_processing_mode_t *mode,
                                              const committee_member_addition_t *addition);
void plan_or_render_committee_no_removals(const tx_processing_mode_t *mode);
void plan_or_render_committee_no_additions(const tx_processing_mode_t *mode);
void plan_or_render_committee_threshold(const tx_processing_mode_t *mode,
                                        uint64_t numerator,
                                        uint64_t denominator);

// One protocol_param_update field (parameter_change_action). `label` comes from the caller's
// per-key descriptor table; unused (NULL) for *_VOTING_THRESHOLDS, which use their own fixed
// per-ratio sub-labels instead. Present fields are streamed one at a time and never held in
// proposal_procedure_t, so each one is rendered as it is parsed.
void plan_or_render_param_field(const tx_processing_mode_t *mode,
                                const parsed_param_field_t *field,
                                const char *label);
