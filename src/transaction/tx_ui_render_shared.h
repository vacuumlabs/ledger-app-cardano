/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "tx_certificate_types.h"
#include "tx_credential_types.h"
#include "tx_parse.h"
#include "sign_tx_ctx.h"

/**
 * UI render helpers used by more than one tx_ui_render_* domain.
 */

/**
 * Collapses the count-vs-render branch that every plan_or_render_* function repeats:
 *
 *   UI_PLAN_OR_RENDER(mode, UI_PAIRS_X);
 *   START_COUNT();
 *   ... UI_ADD_* ...
 *   CHECK_COUNT(UI_PAIRS_X);
 *
 * WARNING: on the planning pass this records pair_count and then causes an immediate
 * `return` in the *calling function*, as it does when neither pass is active. Callers do
 * not check a return value.
 */
#define UI_PLAN_OR_RENDER(mode, pair_count) \
    do {                                    \
        if ((mode)->ui_count_pairs) {       \
            ui_plan_pairs((pair_count));    \
            return;                         \
        }                                   \
        if (!(mode)->ui_render) {           \
            return;                         \
        }                                   \
    } while (0)

// Adds pair_count to the planned total. Out of line so the address of the counter is
// materialized once instead of at every UI_PLAN_OR_RENDER site.
void ui_plan_pairs(uint16_t pair_count);

// Renders one ext_credential_t as a key path, a key hash or a script hash. The labels and
// bech32 prefixes are parameters, so one switch serves any kind of credential.
void render_credential(const ext_credential_t *credential,
                       const char *key_path_label,
                       const char *key_hash_label,
                       const char *key_hash_prefix,
                       const char *script_hash_label,
                       const char *script_hash_prefix);

// Renders an anchor as its URL and hash, or "(empty)" when the URL is blank. The labels are
// parameters so that two anchors on the same review can be told apart.
void plan_or_render_labeled_anchor(const tx_processing_mode_t *mode,
                                   const anchor_t *anchor,
                                   const char *url_label,
                                   const char *hash_label);

// Renders a single "<label>: (none)" pair for an empty collection.
void plan_or_render_none_label(const tx_processing_mode_t *mode, const char *label);
