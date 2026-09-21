/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>  // bool
#include <string.h>   // memset

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "bip44.h"
#include "format.h"

#include "ui_icons.h"
#include "ui_constants.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "utils.h"
#include "app_context.h"
#include "cardano_swo.h"
#include "securityPolicy.h"
#include "menu.h"
#include "mem.h"
#include "ui_utils.h"
#include "sign_tx.h"

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_UI_DISPLAY to trace UI flow details.
 */
#ifdef TRACE_UI_DISPLAY
#define TRACE_MODULE(...) TRACE("[ui_witness] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif

static void witness_review_choice(bool confirm) {
    // CLEANUP
    // No dynamically allocated UI buffers to release in this flow.

    // FINALIZE
    if (!confirm) {
        TRACE_MODULE("User rejected");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
        return;
    }

    TRACE_MODULE("User confirmed");
    nbgl_useCaseSpinner("Processing");
    const bool is_last_witness = is_last_witness_to_process();
    finalize_witness();

    // SHOW STATUS
    if (is_last_witness) {
        // All witnesses processed - show final success status
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    }
}

void ui_display_witness(const bip44_path_t *witnessPath,
                        security_policy_t securityPolicy,
                        warning_bits_t warnings) {
    TRACE_MODULE("=== ui_display_witness START ===");
    TRACE_MODULE("securityPolicy: %d", securityPolicy);

    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION,
                  "ui_display_witness called with wrong request type: %d",
                  G_context.req_type);
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_APPROVED,
                  "ui_display_witness called in wrong tx state: %d",
                  G_context.state.tx_state);
    LEDGER_ASSERT(warning_bits_except_mask(
                      warnings,
                      warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0,
                  "Unexpected warning bits: 0x%08x",
                  (unsigned int) warnings);

    bool isUnusual = warning_bits_has(warnings, WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH);

    LEDGER_ASSERT(securityPolicy == POLICY_SHOW, "Unexpected security policy");

    TRACE_MODULE("isUnusual: %d", isUnusual);

    // Format the witness path into static buffer. Capture the context pointer once so the
    // sizeof() operand below contains no function call (cpp/sizeof-side-effect false positive).
    typeof(tx_witness_ctx()) witness_ctx = tx_witness_ctx();
    bool formatted = format_bip44_path(witnessPath,
                                       witness_ctx->witness_path_str,
                                       sizeof(witness_ctx->witness_path_str));
    LEDGER_ASSERT(formatted, "Unable to format witness path");
    LEDGER_ASSERT(strlen(witness_ctx->witness_path_str) <= MAX_BIP44_PATH_STRING_LENGTH,
                  "Witness path ui string buffer too short");

    if (isUnusual) {
        // A mild warning about unusual path
        // No immediate threat, just to be aware that the witness key is unusual
        nbgl_useCaseChoice(&WARNING_ICON,
                           "Sign with UNUSUAL key",
                           witness_ctx->witness_path_str,
                           "Confirm",
                           "Reject",
                           witness_review_choice);
    } else {
        // Normal path display
        nbgl_useCaseChoice(&ICON_APP_CARDANO,
                           "Witness",
                           witness_ctx->witness_path_str,
                           "Confirm",
                           "Reject",
                           witness_review_choice);
    }

    return;
}
