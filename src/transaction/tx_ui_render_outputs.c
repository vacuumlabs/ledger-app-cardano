/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>
#include <string.h>

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_UI_DISPLAY to trace output UI rendering.
 */
#ifdef TRACE_UI_DISPLAY
#define TRACE_MODULE(...) TRACE("[tx_ui_render_outputs] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif

#include "assert.h"
#include "bech32.h"
#include "cardano_tokens.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "ui_address_fields.h"
#include "tx_ui_pair_counts.h"
#include "tx_ui_render_outputs.h"
#include "tx_ui_render_shared.h"
#include "tx_utils.h"
#include "ui_constants.h"
#include "ui_formatters.h"
#include "ui_utils.h"

void tx_ui_plan_or_render_output(const tx_processing_mode_t *mode,
                                 uint16_t output_index,
                                 const tx_output_description_t *output_desc) {
    ASSERT(mode != NULL);
    ASSERT(output_desc != NULL);
    TRACE_MODULE("output index=%u destination_type=%u count=%d render=%d",
                 (unsigned) output_index,
                 (unsigned) output_desc->destination.type,
                 (int) mode->ui_count_pairs,
                 (int) mode->ui_render);

    uint16_t pair_count = UI_PAIRS_OUTPUT_BASE;
    if (output_desc->destination.type == DESTINATION_DEVICE_OWNED) {
        pair_count += UI_PAIRS_OUTPUT_DEVICE_OWNED;
    }
    UI_PLAN_OR_RENDER(mode, pair_count);
    START_COUNT();
    ui_pairs_force_new_page();
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Output"),
                   MAX_UINT64_STRING_LENGTH,
                   format_index_with_prefix,
                   (uint32_t) output_index + 1);
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Address"),
                   MAX_HUMAN_ADDRESS_LENGTH,
                   format_tx_output_destination_human_readable,
                   &output_desc->destination);
    if (output_desc->destination.type == DESTINATION_DEVICE_OWNED) {
        addPaymentInfoUIPairs(&output_desc->destination.params);
        addStakingInfoUIPairs(&output_desc->destination.params);
    }
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Amount"),
                   MAX_ADA_AMOUNT_STRING_LENGTH,
                   format_ada_amount,
                   output_desc->amount);
    uint32_t expected_base = UI_PAIRS_OUTPUT_BASE;
    if (output_desc->destination.type == DESTINATION_DEVICE_OWNED) {
        expected_base += UI_PAIRS_OUTPUT_DEVICE_OWNED;
    }
    CHECK_COUNT(expected_base);
}

void tx_ui_plan_or_render_collateral_output_address(const tx_processing_mode_t *mode,
                                                    const tx_output_description_t *output_desc) {
    ASSERT(mode != NULL);
    ASSERT(output_desc != NULL);

    uint16_t pair_count = UI_PAIRS_COLLATERAL_OUTPUT_ADDRESS;
    if (output_desc->destination.type == DESTINATION_DEVICE_OWNED) {
        pair_count += UI_PAIRS_COLLATERAL_OUTPUT_DEVICE_OWNED;
    }
    UI_PLAN_OR_RENDER(mode, pair_count);
    START_COUNT();
    UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Collateral address", "Coll address"),
                   MAX_HUMAN_ADDRESS_LENGTH,
                   format_tx_output_destination_human_readable,
                   &output_desc->destination);
    if (output_desc->destination.type == DESTINATION_DEVICE_OWNED) {
        addPaymentInfoUIPairs(&output_desc->destination.params);
        addStakingInfoUIPairs(&output_desc->destination.params);
    }
    uint32_t expected_collateral = UI_PAIRS_COLLATERAL_OUTPUT_ADDRESS;
    if (output_desc->destination.type == DESTINATION_DEVICE_OWNED) {
        expected_collateral += UI_PAIRS_COLLATERAL_OUTPUT_DEVICE_OWNED;
    }
    CHECK_COUNT(expected_collateral);
}

void tx_ui_plan_or_render_collateral_output_amount(const tx_processing_mode_t *mode,
                                                   const tx_output_description_t *output_desc) {
    ASSERT(mode != NULL);
    ASSERT(output_desc != NULL);

    UI_PLAN_OR_RENDER(mode, UI_PAIRS_COLLATERAL_OUTPUT_AMOUNT);
    START_COUNT();
    UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Collateral amount", "Coll amount"),
                   MAX_ADA_AMOUNT_STRING_LENGTH,
                   format_ada_amount,
                   output_desc->amount);
    CHECK_COUNT(UI_PAIRS_COLLATERAL_OUTPUT_AMOUNT);
}

void tx_ui_plan_or_render_output_token(const tx_processing_mode_t *mode,
                                       const uint8_t *policy_id,
                                       const output_token_t *token) {
    ASSERT(mode != NULL);
    ASSERT(policy_id != NULL);
    ASSERT(token != NULL);

    // Pair count added in the caller (total_token_count known there)
    UI_PLAN_OR_RENDER(mode, 0);
    START_COUNT();
    UI_ADD_FORMAT3(UI_STATIC_LABEL("Fingerprint"),
                   MAX_TOKEN_FINGERPRINT_STRING_LENGTH,
                   format_asset_fingerprint_bech32,
                   policy_id,
                   token->assetName,
                   token->assetNameLen);
    UI_ADD_FORMAT4(UI_STATIC_LABEL("Token amount"),
                   MAX_TOKEN_AMOUNT_STRING_LENGTH,
                   format_token_amount_output,
                   policy_id,
                   token->assetName,
                   token->assetNameLen,
                   token->amount);
    CHECK_COUNT(UI_PAIRS_TOKEN);
}

void tx_ui_plan_or_render_output_datum(const tx_processing_mode_t *mode,
                                       const output_datum_t *datum) {
    ASSERT(mode != NULL);
    ASSERT(datum != NULL);
    TRACE_MODULE("datum type=%u count=%d render=%d",
                 (unsigned) datum->type,
                 (int) mode->ui_count_pairs,
                 (int) mode->ui_render);

    UI_PLAN_OR_RENDER(mode, UI_PAIRS_OUTPUT_DATUM);
    START_COUNT();
    if (datum->type == DATUM_HASH) {
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Datum hash"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       BECH32_PREFIX_DATUM_HASH,
                       datum->hash,
                       OUTPUT_DATUM_HASH_LENGTH);
    } else {
        UI_ADD_FORMAT2(UI_STATIC_LABEL("Datum"),
                       MAX_INLINE_DATUM_STRING_LENGTH,
                       format_incomplete_hex_with_length,
                       datum->inline_datum.buffer,
                       datum->inline_datum.length);
    }
    CHECK_COUNT(UI_PAIRS_OUTPUT_DATUM);
}

void tx_ui_plan_or_render_output_ref_script(const tx_processing_mode_t *mode,
                                            const ref_script_t *ref_script) {
    ASSERT(mode != NULL);
    ASSERT(ref_script != NULL);

    UI_PLAN_OR_RENDER(mode, UI_PAIRS_OUTPUT_REF_SCRIPT);
    START_COUNT();
    UI_ADD_FORMAT2(UI_STATIC_LABEL("Script"),
                   MAX_REFERENCE_SCRIPT_STRING_LENGTH,
                   format_incomplete_hex_with_length,
                   ref_script->data,
                   ref_script->size);
    CHECK_COUNT(UI_PAIRS_OUTPUT_REF_SCRIPT);
}
