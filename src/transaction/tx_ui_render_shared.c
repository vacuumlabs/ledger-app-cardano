/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>

#include "assert.h"
#include "cardano_constants.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "tx_credential_types.h"
#include "tx_ui_pair_counts.h"
#include "tx_ui_render_shared.h"
#include "ui_constants.h"
#include "ui_formatters.h"
#include "ui_utils.h"

void ui_plan_pairs(uint16_t pair_count) {
    tx_body_ctx()->total_ui_pairs += pair_count;
}

void render_credential(const ext_credential_t *credential,
                       const char *key_path_label,
                       const char *key_hash_label,
                       const char *key_hash_prefix,
                       const char *script_hash_label,
                       const char *script_hash_prefix) {
    ASSERT(credential != NULL);

    switch (credential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            UI_ADD_FORMAT1(key_path_label,
                           MAX_BIP44_PATH_STRING_LENGTH,
                           format_bip44_path,
                           &credential->keyPath);
            break;
        case EXT_CREDENTIAL_KEY_HASH:
            ASSERT(credential->keyHash != NULL);
            UI_ADD_FORMAT3(key_hash_label,
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           key_hash_prefix,
                           credential->keyHash,
                           ADDRESS_KEY_HASH_LENGTH);
            break;
        case EXT_CREDENTIAL_SCRIPT_HASH:
            ASSERT(credential->scriptHash != NULL);
            UI_ADD_FORMAT3(script_hash_label,
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           script_hash_prefix,
                           credential->scriptHash,
                           SCRIPT_HASH_LENGTH);
            break;
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown credential type");
            // LCOV_EXCL_STOP
    }
}

void plan_or_render_labeled_anchor(const tx_processing_mode_t *mode,
                                   const anchor_t *anchor,
                                   const char *url_label,
                                   const char *hash_label) {
    ASSERT(mode != NULL);
    ASSERT(anchor != NULL && anchor->isIncluded);

    UI_PLAN_OR_RENDER(mode, UI_PAIRS_ANCHOR);
    START_COUNT();
    if (anchor->urlLength == 0) {
        LEDGER_ASSERT(warning_bits_has(tx_body_ctx()->warning_bits, WARNING_BIT_EMPTY_ANCHOR_URL),
                      "Empty anchor URL warning missing");
        UI_ADD_STATIC(url_label, UI_STATIC_LABEL("(empty)"));
    } else {
        UI_ADD_FORMAT2(url_label,
                       MAX_ANCHOR_URL_LENGTH,
                       format_url,
                       anchor->url,
                       anchor->urlLength);
    }
    UI_ADD_FORMAT2(hash_label,
                   MAX_ANCHOR_HASH_STRING_LENGTH,
                   format_hex_bytes,
                   anchor->hash,
                   ANCHOR_HASH_LENGTH);
    CHECK_COUNT(UI_PAIRS_ANCHOR);
}

void plan_or_render_none_label(const tx_processing_mode_t *mode, const char *label) {
    UI_PLAN_OR_RENDER(mode, UI_PAIRS_NONE_INDICATOR);
    START_COUNT();
    UI_ADD_STATIC(label, UI_STATIC_LABEL("(none)"));
    CHECK_COUNT(UI_PAIRS_NONE_INDICATOR);
}
