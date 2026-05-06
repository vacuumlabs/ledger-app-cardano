/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>

#include "nbgl_use_case.h"

#include "ui_icons.h"
#include "cardano_constants.h"
#include "globals.h"
#include "cardano_swo.h"
#include "menu.h"
#include "securityPolicy.h"
#include "app_context.h"
#include "derive_address.h"
#include "ui_utils.h"
#include "ui_warnings.h"
#include "ui_display_address_derivation.h"
#include "ui_address_fields.h"

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_UI_DISPLAY to trace UI flow details.
 */
#ifdef TRACE_UI_DISPLAY
#define TRACE_MODULE(...) TRACE("[ui_derive_addr] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif
// Called when long press button is touched or when reject footer is touched
static void derive_address_review_choice(bool confirm) {
    TRACE_MODULE("confirmed = %d", confirm);
    LEDGER_ASSERT(G_context.req_type == REQUEST_DERIVE_ADDRESS,
                  "derive_address_review_choice called without REQUEST_DERIVE_ADDRESS");
    LEDGER_ASSERT(G_context.state.derive_address_state == DERIVE_ADDRESS_STATE_PREPARED,
                  "derive_address_review_choice called in wrong state: %d",
                  G_context.state.derive_address_state);

    // CLEANUP
    ui_all_cleanup();

    // FINALIZE
    if (!confirm) {
        TRACE_MODULE("User rejected");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);
        return;
    }

    TRACE_MODULE("User confirmed");
    // does not need a spinner
    finalize_derive_address();

    // SHOW STATUS
    nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);
}

// Address derivation UI pair counts
#define DERIVE_ADDRESS_PAIRS_REWARD_ONLY       1  // Staking info only
#define DERIVE_ADDRESS_PAIRS_PAYMENT_AND_STAKE 2  // Payment + Staking info
#define DERIVE_ADDRESS_PAIRS_WARNING           1  // Warning banner

static void format_address_fields(const address_params_t *params, warning_bits_t warnings) {
    ui_render_session_t session = {0};
    ui_render_scope_begin(&session);
    LEDGER_ASSERT(warning_bits_except_mask(
                      warnings,
                      warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0,
                  "Unexpected warning bits: 0x%08x",
                  (unsigned int) warnings);
    const bool hasUnusualPathWarning =
        warning_bits_has(warnings, WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH);

    switch (params->type) {
        // Reward addresses: staking info only
        case REWARD_KEY:
        case REWARD_SCRIPT: {
            const int expectedPairs = DERIVE_ADDRESS_PAIRS_REWARD_ONLY +
                                      (hasUnusualPathWarning ? DERIVE_ADDRESS_PAIRS_WARNING : 0);

            if (!ui_pairs_init(expectedPairs)) {
                ui_render_scope_end();                               // LCOV_EXCL_LINE
                LEDGER_ASSERT(false, "Failed to initialize pairs");  // LCOV_EXCL_LINE
                return;                                              // LCOV_EXCL_LINE
            }

            START_COUNT();

            if (hasUnusualPathWarning) {
                TRACE_MODULE("Adding warning banner");
                UI_ADD_STATIC(UI_STATIC_LABEL("Warning:"),
                              UI_STATIC_LABEL("Unusual request, be careful"));
            }

            addStakingInfoUIPairs(params);
            CHECK_COUNT(expectedPairs);
            break;
        }

        // Base addresses: payment + staking info
        case BASE_PAYMENT_KEY_STAKE_KEY:
        case BASE_PAYMENT_KEY_STAKE_SCRIPT:
        case BASE_PAYMENT_SCRIPT_STAKE_KEY:
        case BASE_PAYMENT_SCRIPT_STAKE_SCRIPT:
        // Enterprise addresses: payment info + no staking
        case ENTERPRISE_KEY:
        case ENTERPRISE_SCRIPT:
        // Pointer addresses: payment info + blockchain pointer
        case POINTER_KEY:
        case POINTER_SCRIPT:
        // Byron addresses: payment info + legacy (no staking)
        case BYRON: {
            const int expectedPairs = DERIVE_ADDRESS_PAIRS_PAYMENT_AND_STAKE +
                                      (hasUnusualPathWarning ? DERIVE_ADDRESS_PAIRS_WARNING : 0);

            if (!ui_pairs_init(expectedPairs)) {
                ui_render_scope_end();                               // LCOV_EXCL_LINE
                LEDGER_ASSERT(false, "Failed to initialize pairs");  // LCOV_EXCL_LINE
                return;                                              // LCOV_EXCL_LINE
            }

            START_COUNT();

            if (hasUnusualPathWarning) {
                TRACE_MODULE("Adding warning banner");
                UI_ADD_STATIC(UI_STATIC_LABEL("Warning:"),
                              UI_STATIC_LABEL("Unusual request, be careful"));
            }

            addPaymentInfoUIPairs(params);
            addStakingInfoUIPairs(params);
            CHECK_COUNT(expectedPairs);
            break;
        }

        // LCOV_EXCL_START
        default:
            ui_render_scope_end();
            LEDGER_ASSERT(false, "Unsupported address type: %d", params->type);
            return;
            // LCOV_EXCL_STOP
    }
    ui_status_t status = ui_render_scope_end();
    LEDGER_ASSERT(status == UI_STATUS_SUCCESS, "Unexpected UI status: %d", status);
}

static void ui_displayAddressReview(const char *title,
                                    const char *subtitle,
                                    nbgl_choiceCallback_t callback,
                                    warning_bits_t warnings) {
    derive_address_ctx_t *ctx = &G_context.derive_address_info;
    format_address_fields(&ctx->address_params, warnings);

    LEDGER_ASSERT(ctx->address.length <= MAX_HUMAN_ADDRESS_LENGTH, "Address length too large");

    bool formattingSucceeded = format_address_human_readable(ctx->address.buffer,
                                                             ctx->address.length,
                                                             ctx->humanAddress,
                                                             SIZEOF(ctx->humanAddress));
    LEDGER_ASSERT(formattingSucceeded, "Failed to format derived address");
    TRACE_MODULE("Derived human-readable address (bech32/base58): %s", ctx->humanAddress);
    nbgl_useCaseAddressReview(ctx->humanAddress,
                              g_pairsList,
                              &ICON_APP_CARDANO,
                              title,
                              subtitle,
                              callback);
}

void ui_deriveAddress_handleReturn(security_policy_t policy, warning_bits_t warnings) {
    // Validate state before proceeding (address must be prepared before UI display)
    LEDGER_ASSERT(G_context.req_type == REQUEST_DERIVE_ADDRESS,
                  "ui_deriveAddress_handleReturn called with wrong request type: %d",
                  G_context.req_type);
    LEDGER_ASSERT(G_context.state.derive_address_state == DERIVE_ADDRESS_STATE_PREPARED,
                  "ui_deriveAddress_handleReturn called in wrong state: %d",
                  G_context.state.derive_address_state);

    switch (policy) {
        case POLICY_SHOW:
            ui_displayAddressReview(
                warning_bits_has(warnings, WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)
                    ? "Export UNUSUAL address"
                    : "Export address",
                NULL,
                derive_address_review_choice,
                warnings);
            break;
        case POLICY_HIDE: {
            // Silently approve and return address without UI
            finalize_derive_address();
            break;
        }
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Invalid policy in ui_deriveAddress_handleReturn: %d", policy);
            break;
            // LCOV_EXCL_STOP
    }
}

void ui_deriveAddress_handleDisplay(security_policy_t policy, warning_bits_t warnings) {
    // Validate state before proceeding (address must be prepared before UI display)
    LEDGER_ASSERT(G_context.req_type == REQUEST_DERIVE_ADDRESS,
                  "ui_deriveAddress_handleDisplay called with wrong request type: %d",
                  G_context.req_type);
    LEDGER_ASSERT(G_context.state.derive_address_state == DERIVE_ADDRESS_STATE_PREPARED,
                  "ui_deriveAddress_handleDisplay called in wrong state: %d",
                  G_context.state.derive_address_state);

    switch (policy) {
        case POLICY_SHOW:
            ui_displayAddressReview("Verify Cardano address",
                                    NULL,
                                    derive_address_review_choice,
                                    warnings);
            break;
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Invalid policy in ui_deriveAddress_handleDisplay: %d", policy);
            break;
            // LCOV_EXCL_STOP
    }
}
