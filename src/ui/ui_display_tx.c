/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>  // bool

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "utils.h"

#include "ui_icons.h"
#include "globals.h"
#include "cardano_swo.h"
#include "menu.h"
#include "app_context.h"
#include "cardano_settings.h"
#include "sign_tx_ctx.h"
#include "tx_processing.h"
#include "ui_utils.h"
#include "ui_warnings.h"
#include "ui_display_tx.h"
#include "sign_tx.h"

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_UI_DISPLAY to trace UI flow details.
 */
#ifdef TRACE_UI_DISPLAY
#define TRACE_MODULE(...) TRACE("[ui_display_tx] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif

static const char BLIND_SIGNING_CHOICE_TITLE[] = "Blind signing";
static const char BLIND_SIGNING_CHOICE_DESCRIPTION[] = "Transaction is long. Show details?";
static const char BLIND_SIGNING_CHOICE_CONFIRM[] = "Show details";
static const char BLIND_SIGNING_CHOICE_REJECT[] = "View hash only";

void tx_review_cleanup(void) {
    ui_all_cleanup();
}

bool tx_render_ui_or_fail(tx_ui_review_mode_e review_mode) {
    if (tx_render_ui(review_mode)) {
        return true;
    }

    // LCOV_EXCL_START
    tx_review_cleanup();
    TRACE_MODULE("TX UI render failed");
    send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
    return false;
    // LCOV_EXCL_STOP
}

static void tx_review_choice(bool confirm) {
    // CLEANUP
    tx_review_cleanup();

    // FINALIZE
    if (!confirm) {
        TRACE_MODULE("User rejected");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
        return;
    }

    TRACE_MODULE("User confirmed");
    const bool has_witnesses = (G_context.tx_info.num_witnesses > 0);
    if (has_witnesses) {
        // we will wait for a witness APDU
        // the spinner is not needed for finalize_sign_tx on its own, it is fast
        nbgl_useCaseSpinner("Processing");
    }
    finalize_sign_tx();

    // SHOW STATUS
    if (!has_witnesses) {
        // we are totally finished
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    }
}

static void tx_blind_signing_choice(bool confirm) {
    tx_ui_review_mode_e review_mode =
        confirm ? TX_UI_REVIEW_MODE_DETAILS : TX_UI_REVIEW_MODE_HASH_ONLY;
    if (!tx_render_ui_or_fail(review_mode)) {
        return;  // LCOV_EXCL_LINE
    }
    ui_display_transaction();
}

void ui_display_blind_signing_choice(void) {
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION,
                  "ui_display_blind_signing_choice called with wrong request type: %d",
                  G_context.req_type);
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_UI_REVIEW,
                  "ui_display_blind_signing_choice called in wrong tx state: %d",
                  G_context.state.tx_state);
    LEDGER_ASSERT(is_blind_signing_enabled(),
                  "Blind-signing choice shown when blind signing is off");
    LEDGER_ASSERT(tx_body_ctx()->review_mode == TX_UI_REVIEW_MODE_PENDING_BLIND_SIGNING_CHOICE,
                  "Blind-signing choice shown without pending choice");

    nbgl_useCaseChoice(&ICON_APP_WARNING,
                       BLIND_SIGNING_CHOICE_TITLE,
                       BLIND_SIGNING_CHOICE_DESCRIPTION,
                       BLIND_SIGNING_CHOICE_CONFIRM,
                       BLIND_SIGNING_CHOICE_REJECT,
                       tx_blind_signing_choice);
}

static bool is_recoverable_streaming_chunk_boundary(ui_status_t render_status,
                                                    uint16_t rendered_count) {
    switch (render_status) {
        case UI_STATUS_CHUNK_FULL:
            return true;
        // LCOV_EXCL_START
        case UI_STATUS_OUT_OF_MEMORY:
            return rendered_count > 0;
        default:
            return false;
            // LCOV_EXCL_STOP
    }
}

static void tx_streaming_continue_choice(bool confirm) {
    if (!confirm) {
        tx_review_cleanup();
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
        return;
    }

    // Free the pairs rendered for the previous chunk.
    ui_free_pairs();

    uint16_t next_from = tx_body_ctx()->rendered_ui_pairs;
    uint16_t total = tx_body_ctx()->total_ui_pairs;

    if (next_from >= total) {
        // All chunks done — finish screen.
        nbgl_useCaseReviewStreamingFinish("Sign transaction", tx_review_choice);
        return;
    }

    // Render the next chunk.
    ui_reset_error_status();
    if (!ui_pairs_init(MAX_UI_PAIRS)) {
        tx_review_cleanup();                          // LCOV_EXCL_LINE
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);  // LCOV_EXCL_LINE
        return;                                       // LCOV_EXCL_LINE
    }

    LEDGER_ASSERT(tx_render_ui_chunk(next_from),
                  "Streaming tx_render_ui_chunk failed after successful validation");

    uint16_t rendered_count = ui_pairs_get_count();
    ui_status_t render_status = ui_get_error_status();
    switch (render_status) {
        case UI_STATUS_SUCCESS:
            // Last chunk: remaining pairs fit in this slab.
            break;
        case UI_STATUS_CHUNK_FULL:
        case UI_STATUS_OUT_OF_MEMORY:
            if (is_recoverable_streaming_chunk_boundary(render_status, rendered_count)) {
                // Intermediate boundary: clear status for the next chunk render.
                ui_reset_error_status();
                break;
            }
            tx_review_cleanup();                          // LCOV_EXCL_LINE
            send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);  // LCOV_EXCL_LINE
            return;                                       // LCOV_EXCL_LINE
        // LCOV_EXCL_START
        case UI_STATUS_UNINITIALIZED:
        default:
            LEDGER_ASSERT(false, "Unexpected UI status after streaming chunk render");
            return;
            // LCOV_EXCL_STOP
    }

    // Update next_ui_pair_index for the next chunk.
    if (rendered_count == 0) {
        // If nothing rendered, the single pair exceeds memory. This should
        // never happen in practice because individual UI strings are bounded and small, but without
        // this guard the next_ui_pair_index would not advance and the app would loop forever on
        // this chunk.
        tx_review_cleanup();                          // LCOV_EXCL_LINE
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);  // LCOV_EXCL_LINE
        return;                                       // LCOV_EXCL_LINE
    }
    tx_body_ctx()->rendered_ui_pairs = next_from + rendered_count;

    // Finalize the pairs count for display.
    ASSERT(g_pairsList != NULL);
    g_pairsList->nbPairs = (uint8_t) rendered_count;

    TRACE_MODULE("Streaming chunk: from=%u rendered=%u next_ui_pair_index=%u total=%u",
                 next_from,
                 rendered_count,
                 tx_body_ctx()->rendered_ui_pairs,
                 total);

    nbgl_useCaseReviewStreamingContinue(g_pairsList, tx_streaming_continue_choice);
}

static void tx_streaming_start_choice(bool confirm) {
    if (!confirm) {
        tx_review_cleanup();
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
        return;
    }
    // Serve the already-rendered first chunk.
    nbgl_useCaseReviewStreamingContinue(g_pairsList, tx_streaming_continue_choice);
}

void ui_display_transaction(void) {
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION,
                  "ui_display_transaction called with wrong request type: %d",
                  G_context.req_type);
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_UI_REVIEW,
                  "ui_display_transaction called in wrong tx state: %d",
                  G_context.state.tx_state);
    LEDGER_ASSERT(tx_body_ctx()->review_mode == TX_UI_REVIEW_MODE_DETAILS ||
                      tx_body_ctx()->review_mode == TX_UI_REVIEW_MODE_HASH_ONLY,
                  "ui_display_transaction called without prepared review mode: %d",
                  tx_body_ctx()->review_mode);

    const char *review_subtitle = NULL;
    const char *review_title = "Review transaction";
    switch (G_context.tx_info.tx_params.txSigningMode) {
        case SIGN_TX_SIGNINGMODE_PLUTUS:
            review_subtitle = "Plutus execution";
            break;
        case SIGN_TX_SIGNINGMODE_MULTISIG:
            review_subtitle = "Multisig transaction";
            break;
        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            review_subtitle = "Unrestricted signing";
            break;
        default:
            break;
    }

    const nbgl_warning_t *warningPtr = ui_get_warnings();

    if (tx_body_ctx()->review_mode == TX_UI_REVIEW_MODE_HASH_ONLY) {
        review_subtitle = "Blind signing";
    }

    if (!tx_body_ctx()->streaming_mode) {
        // Non-streaming: identical to before.
        nbgl_useCaseAdvancedReview(TYPE_TRANSACTION,
                                   g_pairsList,
                                   &ICON_APP_CARDANO,
                                   review_title,
                                   review_subtitle,
                                   "Sign transaction",
                                   NULL,
                                   warningPtr,
                                   tx_review_choice);
    } else {
        // Streaming: first chunk already rendered.
        nbgl_useCaseAdvancedReviewStreamingStart(TYPE_TRANSACTION,
                                                 &ICON_APP_CARDANO,
                                                 review_title,
                                                 review_subtitle,
                                                 warningPtr,
                                                 tx_streaming_start_choice);
    }
}
