/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Centralized NBGL mock implementations for unit tests.
 *
 * All NBGL use-case functions auto-confirm by calling their choice/quit
 * callbacks synchronously. This lets unit tests exercise the real app UI
 * code (formatting, state validation, cleanup) without pulling in the
 * actual NBGL rendering stack.
 */

#include "nbgl_use_case.h"
#include "nbgl_mock.h"
#include "ledger_assert.h"
#include "menu.h"
#include "globals.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NBGL_MOCK_MAX_FINAL_DECISIONS 16
#define NBGL_MOCK_TEXT_BUFFER_SIZE    256

static warning_bits_t g_captured_warning_bits = 0;
static bool g_final_decisions_storage[NBGL_MOCK_MAX_FINAL_DECISIONS];
static size_t g_final_decision_count = 0;
static size_t g_final_decision_index = 0;
static bool g_final_decisions_strict = false;
static nbgl_operationType_t g_last_streaming_operation_type = TYPE_TRANSACTION;
static bool g_streaming_start_auto_complete = false;
static bool g_streaming_start_confirm = true;
static bool g_streaming_continue_reject_enabled = false;
static size_t g_streaming_continue_reject_at_call = 0;
static size_t g_streaming_continue_call_count = 0;
static char g_last_choice_message[NBGL_MOCK_TEXT_BUFFER_SIZE];
static char g_last_status_message[NBGL_MOCK_TEXT_BUFFER_SIZE];
static bool g_last_status_success = false;

static void nbgl_mock_store_text(char *destination, const char *source) {
    memset(destination, 0, NBGL_MOCK_TEXT_BUFFER_SIZE);
    if (source == NULL) {
        return;
    }
    strncpy(destination, source, NBGL_MOCK_TEXT_BUFFER_SIZE - 1);
}

void nbgl_mock_reset(void) {
    g_final_decision_count = 0;
    g_final_decision_index = 0;
    g_final_decisions_strict = false;
    g_last_streaming_operation_type = TYPE_TRANSACTION;
    g_streaming_start_auto_complete = false;
    g_streaming_start_confirm = true;
    g_streaming_continue_reject_enabled = false;
    g_streaming_continue_reject_at_call = 0;
    g_streaming_continue_call_count = 0;
    memset(g_last_choice_message, 0, sizeof(g_last_choice_message));
    memset(g_last_status_message, 0, sizeof(g_last_status_message));
    g_last_status_success = false;
    g_captured_warning_bits = 0;
}

void nbgl_mock_set_final_decisions(const bool *decisions, size_t decision_count) {
    if (decisions == NULL || decision_count == 0) {
        g_final_decision_count = 0;
        g_final_decision_index = 0;
        g_final_decisions_strict = false;
        return;
    }

    LEDGER_ASSERT(decision_count <= NBGL_MOCK_MAX_FINAL_DECISIONS, "Too many final decisions");

    for (size_t i = 0; i < decision_count; i++) {
        g_final_decisions_storage[i] = decisions[i];
    }

    g_final_decision_count = decision_count;
    g_final_decision_index = 0;
    g_final_decisions_strict = true;
}

void nbgl_mock_assert_all_final_decisions_consumed(void) {
    if (g_final_decisions_strict && g_final_decision_index != g_final_decision_count) {
        fprintf(stderr,
                "nbgl_mock: only consumed %zu/%zu configured final decisions\n",
                g_final_decision_index,
                g_final_decision_count);
        abort();
    }
}

void nbgl_mock_set_streaming_start_auto_complete(bool enabled, bool confirm) {
    g_streaming_start_auto_complete = enabled;
    g_streaming_start_confirm = confirm;
}

void nbgl_mock_set_streaming_continue_reject_at_call(size_t call_index) {
    g_streaming_continue_reject_enabled = true;
    g_streaming_continue_reject_at_call = call_index;
    g_streaming_continue_call_count = 0;
}

static bool nbgl_mock_next_final_decision(void) {
    if (g_final_decision_index < g_final_decision_count) {
        return g_final_decisions_storage[g_final_decision_index++];
    }
    if (g_final_decisions_strict) {
        fprintf(stderr,
                "nbgl_mock: missing final decision for prompt %zu (configured %zu)\n",
                g_final_decision_index,
                g_final_decision_count);
        abort();
    }
    return true;
}

static bool nbgl_mock_final_decision_for_operation(nbgl_operationType_t operation_type) {
    (void) operation_type;
    return nbgl_mock_next_final_decision();
}

// ======================================================================
// No-op functions
// ======================================================================

void nbgl_useCaseSpinner(const char *text) {
    (void) text;
}

void nbgl_useCaseHomeAndSettings(const char *appName,
                                 const nbgl_icon_details_t *appIcon,
                                 const char *tagline,
                                 const uint8_t initSettingPage,
                                 const nbgl_genericContents_t *settingContents,
                                 const nbgl_contentInfoList_t *infosList,
                                 const nbgl_homeAction_t *action,
                                 nbgl_callback_t quitCallback) {
    (void) appName;
    (void) appIcon;
    (void) tagline;
    (void) initSettingPage;
    (void) settingContents;
    (void) infosList;
    (void) action;
    (void) quitCallback;
}

// ======================================================================
// Status functions (call quit callback)
// ======================================================================

void nbgl_useCaseStatus(const char *message, bool isSuccess, nbgl_callback_t quitCallback) {
    nbgl_mock_store_text(g_last_status_message, message);
    g_last_status_success = isSuccess;
    if (quitCallback != NULL) {
        quitCallback();
    }
}

void nbgl_useCaseReviewStatus(nbgl_reviewStatusType_t reviewStatusType,
                              nbgl_callback_t quitCallback) {
    (void) reviewStatusType;
    if (quitCallback != NULL) {
        quitCallback();
    }
}

// ======================================================================
// Review/choice functions (auto-confirm with true)
// ======================================================================

void nbgl_useCaseAdvancedReview(nbgl_operationType_t operationType,
                                const nbgl_contentTagValueList_t *tagValueList,
                                const nbgl_icon_details_t *icon,
                                const char *reviewTitle,
                                const char *reviewSubTitle,
                                const char *finishTitle,
                                const nbgl_tipBox_t *tipBox,
                                const nbgl_warning_t *warning,
                                nbgl_choiceCallback_t choiceCallback) {
    (void) operationType;
    (void) tagValueList;
    (void) icon;
    (void) reviewTitle;
    (void) reviewSubTitle;
    (void) finishTitle;
    (void) tipBox;
    (void) warning;
    g_captured_warning_bits = G_context.tx_info.body.warning_bits;
    if (choiceCallback != NULL) {
        choiceCallback(nbgl_mock_final_decision_for_operation(operationType));
    }
}

void nbgl_useCaseChoice(const nbgl_icon_details_t *icon,
                        const char *message,
                        const char *subMessage,
                        const char *confirmText,
                        const char *rejectString,
                        nbgl_choiceCallback_t callback) {
    (void) icon;
    nbgl_mock_store_text(g_last_choice_message, message);
    (void) subMessage;
    (void) confirmText;
    (void) rejectString;
    if (callback != NULL) {
        callback(nbgl_mock_next_final_decision());
    }
}

void nbgl_useCaseAddressReview(const char *address,
                               const nbgl_contentTagValueList_t *additionalTagValueList,
                               const nbgl_icon_details_t *icon,
                               const char *reviewTitle,
                               const char *reviewSubTitle,
                               nbgl_choiceCallback_t choiceCallback) {
    (void) address;
    (void) additionalTagValueList;
    (void) icon;
    (void) reviewTitle;
    (void) reviewSubTitle;
    if (choiceCallback != NULL) {
        choiceCallback(nbgl_mock_next_final_decision());
    }
}

// ======================================================================
// Streaming review functions (auto-confirm with true)
// ======================================================================

void nbgl_useCaseReviewStreamingStart(nbgl_operationType_t operationType,
                                      const nbgl_icon_details_t *icon,
                                      const char *reviewTitle,
                                      const char *reviewSubTitle,
                                      nbgl_choiceCallback_t choiceCallback) {
    g_last_streaming_operation_type = operationType;
    (void) operationType;
    (void) icon;
    (void) reviewTitle;
    (void) reviewSubTitle;
    if (g_streaming_start_auto_complete && choiceCallback != NULL) {
        choiceCallback(g_streaming_start_confirm);
    }
}

void nbgl_useCaseAdvancedReviewStreamingStart(nbgl_operationType_t operationType,
                                              const nbgl_icon_details_t *icon,
                                              const char *reviewTitle,
                                              const char *reviewSubTitle,
                                              const nbgl_warning_t *warning,
                                              nbgl_choiceCallback_t choiceCallback) {
    g_last_streaming_operation_type = operationType;
    (void) operationType;
    (void) icon;
    (void) reviewTitle;
    (void) reviewSubTitle;
    (void) warning;
    g_captured_warning_bits = G_context.tx_info.body.warning_bits;
    if (g_streaming_start_auto_complete && choiceCallback != NULL) {
        choiceCallback(g_streaming_start_confirm);
    }
}

void nbgl_useCaseReviewStreamingContinue(const nbgl_contentTagValueList_t *tagValueList,
                                         nbgl_choiceCallback_t choiceCallback) {
    (void) tagValueList;
    if (choiceCallback != NULL) {
        bool confirm = true;
        if (g_streaming_continue_reject_enabled &&
            g_streaming_continue_call_count == g_streaming_continue_reject_at_call) {
            confirm = false;
        }
        g_streaming_continue_call_count++;
        choiceCallback(confirm);
    }
}

void nbgl_useCaseReviewStreamingFinish(const char *finishTitle,
                                       nbgl_choiceCallback_t choiceCallback) {
    (void) finishTitle;
    if (choiceCallback != NULL) {
        choiceCallback(nbgl_mock_final_decision_for_operation(g_last_streaming_operation_type));
    }
}

// ======================================================================
// UI menu stub (replaces per-test duplicates)
// ======================================================================

void ui_menu_main(void) {
    // no-op in unit tests
}

const char *nbgl_mock_last_choice_message(void) {
    return g_last_choice_message;
}

const char *nbgl_mock_last_status_message(void) {
    return g_last_status_message;
}

bool nbgl_mock_last_status_success(void) {
    return g_last_status_success;
}

warning_bits_t nbgl_mock_captured_warning_bits(void) {
    return g_captured_warning_bits;
}
