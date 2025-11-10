/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdbool.h>  // bool
#include <string.h>   // memset

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "addressUtils/bip44.h"

#include "display.h"
#include "constants.h"
#include "globals.h"
#include "sw.h"
#include "opcert_types.h"
#include "menu.h"
#include "securityPolicy.h"
#include "nbgl_screens.h"
#include "sign_opcert.h"
#include "mem.h"

// Dynamic display structures
static nbgl_contentTagValue_t *g_pairs = NULL;
static nbgl_contentTagValueList_t *g_pairsList = NULL;

// Centered info for the main warning screen.
static const nbgl_contentCenter_t warningInfo = {
  .icon          = &WARNING_ICON,
  .title         = "Suspicious derivation path",
  .description   = "Pool cold key path seems unusual"
};

// Details page shown when the user taps the top-right icon.
static const nbgl_warningDetails_t warningDetails = {
  .title                   = "Suspicious derivation path",
  .type                    = CENTERED_INFO_WARNING,
  .centeredInfo.icon       = &WARNING_ICON,
  .centeredInfo.title      = "Suspicious derivation path",
  .centeredInfo.description= "Pool cold key path seems unusual"
};

static nbgl_warning_t warning = {0};

/**
 * Cleanup dynamically allocated opcert display structures
 */
static void opcert_display_cleanup(void) {
    if (g_pairs != NULL) {
        // Free individual strings in pairs
        for (size_t i = 0; i < 5; i++) {
            if (g_pairs[i].item != NULL) {
                app_mem_free((void*)g_pairs[i].item);
            }
            if (g_pairs[i].value != NULL) {
                app_mem_free((void*)g_pairs[i].value);
            }
        }
        app_mem_free(g_pairs);
        g_pairs = NULL;
    }
    if (g_pairsList != NULL) {
        app_mem_free(g_pairsList);
        g_pairsList = NULL;
    }
}

// called when long press button on 3rd page is long-touched or when reject footer is touched
static void review_choice(bool confirm) {
    TRACE("=== review_choice called ===");
    TRACE("confirm: %s", confirm ? "true" : "false");

    // Cleanup display structures
    opcert_display_cleanup();

    // Answer, display a status page and go back to main
    finalize_sign_opcert(confirm);

    if (confirm) {
        TRACE("User confirmed - showing signed status");
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_SIGNED, ui_menu_main);
    } else {
        TRACE("User rejected - showing rejected status");
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
    }
    TRACE("=== review_choice end ===");
}

/**
 * Helper to allocate and copy a string for display
 * @return Allocated string or NULL on failure
 */
static char* opcert_strdup(const char* src, size_t len) {
    char* dst = (char*) app_mem_alloc(len + 1);
    if (dst == NULL) {
        TRACE("ERROR: opcert_strdup failed to allocate %u bytes", (unsigned)(len + 1));
        return NULL;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    return dst;
}

// Public function to start the operational certificate review
// - Check if the app is in the right state for opcert review
// - Format and dynamically allocate display strings
// - Display the review screen with optional warning
int ui_display_opcert(security_policy_t securityPolicy) {
    TRACE("=== ui_display_opcert START ===");
    TRACE("securityPolicy: %d", securityPolicy);

    if (G_context.req_type != REQUEST_SIGN_OPCERT || G_context.state != STATE_PARSED) {
        TRACE("Bad state detected - returning error");
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    const parsed_opcert_t* opcert = &G_context.opcert_info.opcert;

    // Cleanup any previous display structures
    opcert_display_cleanup();

    // Allocate pair array (5 items)
    g_pairs = (nbgl_contentTagValue_t*) app_mem_alloc(5 * sizeof(nbgl_contentTagValue_t));
    if (g_pairs == NULL) {
        TRACE("ERROR: Failed to allocate pairs array");
        return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
    }
    explicit_bzero(g_pairs, 5 * sizeof(nbgl_contentTagValue_t));

    // Allocate pairsList structure
    g_pairsList = (nbgl_contentTagValueList_t*) app_mem_alloc(sizeof(nbgl_contentTagValueList_t));
    if (g_pairsList == NULL) {
        TRACE("ERROR: Failed to allocate pairsList");
        opcert_display_cleanup();
        return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
    }

    // Temporary buffer for formatting (will be allocated once and reused)
    char* tempBuffer = (char*) app_mem_alloc(BECH32_STRING_SIZE_MAX);
    if (tempBuffer == NULL) {
        TRACE("ERROR: Failed to allocate temporary buffer");
        opcert_display_cleanup();
        return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
    }

    // Build pair 0: pool cold key path
    explicit_bzero(tempBuffer, BECH32_STRING_SIZE_MAX);
    ui_getPathScreen(tempBuffer, BECH32_STRING_SIZE_MAX, &opcert->poolColdKeyPath);
    g_pairs[0].item = opcert_strdup("Pool cold key path", 18);
    g_pairs[0].value = opcert_strdup(tempBuffer, strlen(tempBuffer));
    if (g_pairs[0].item == NULL || g_pairs[0].value == NULL) {
        app_mem_free(tempBuffer);
        opcert_display_cleanup();
        return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
    }

    // Build pair 1: pool id (derived from path)
    uint8_t poolKeyHash[POOL_KEY_HASH_LENGTH] = {0};
    bip44_pathToKeyHash(&opcert->poolColdKeyPath, poolKeyHash, SIZEOF(poolKeyHash));
    explicit_bzero(tempBuffer, BECH32_STRING_SIZE_MAX);
    ui_getBech32Screen(tempBuffer,
                       BECH32_STRING_SIZE_MAX,
                       "pool",
                       poolKeyHash,
                       SIZEOF(poolKeyHash));
    g_pairs[1].item = opcert_strdup("Pool ID", 7);
    g_pairs[1].value = opcert_strdup(tempBuffer, strlen(tempBuffer));
    if (g_pairs[1].item == NULL || g_pairs[1].value == NULL) {
        app_mem_free(tempBuffer);
        opcert_display_cleanup();
        return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
    }

    // Build pair 2: KES public key
    explicit_bzero(tempBuffer, BECH32_STRING_SIZE_MAX);
    ui_getBech32Screen(tempBuffer,
                       BECH32_STRING_SIZE_MAX,
                       "kes_vk",
                       opcert->kesPublicKey,
                       KES_PUBLIC_KEY_LENGTH);
    g_pairs[2].item = opcert_strdup("KES public key", 14);
    g_pairs[2].value = opcert_strdup(tempBuffer, strlen(tempBuffer));
    if (g_pairs[2].item == NULL || g_pairs[2].value == NULL) {
        app_mem_free(tempBuffer);
        opcert_display_cleanup();
        return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
    }

    // Build pair 3: KES period
    explicit_bzero(tempBuffer, BECH32_STRING_SIZE_MAX);
    ui_getUint64Screen(tempBuffer, BECH32_STRING_SIZE_MAX, opcert->kesPeriod);
    g_pairs[3].item = opcert_strdup("KES period", 10);
    g_pairs[3].value = opcert_strdup(tempBuffer, strlen(tempBuffer));
    if (g_pairs[3].item == NULL || g_pairs[3].value == NULL) {
        app_mem_free(tempBuffer);
        opcert_display_cleanup();
        return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
    }

    // Build pair 4: issue counter
    explicit_bzero(tempBuffer, BECH32_STRING_SIZE_MAX);
    ui_getUint64Screen(tempBuffer, BECH32_STRING_SIZE_MAX, opcert->issueCounter);
    g_pairs[4].item = opcert_strdup("Issue counter", 13);
    g_pairs[4].value = opcert_strdup(tempBuffer, strlen(tempBuffer));
    if (g_pairs[4].item == NULL || g_pairs[4].value == NULL) {
        app_mem_free(tempBuffer);
        opcert_display_cleanup();
        return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
    }

    // Free temporary buffer
    app_mem_free(tempBuffer);

    // Setup pairsList structure
    g_pairsList->nbMaxLinesForValue = 0;
    g_pairsList->nbPairs = 5;
    g_pairsList->pairs = g_pairs;

    // set warning if needed
    const nbgl_warning_t* warningPtr = NULL;
    TRACE("Security policy received: %d", securityPolicy);
    switch (securityPolicy) {
        case POLICY_PROMPT_WARN_UNUSUAL:
            TRACE("Setting up warning for POLICY_PROMPT_WARN_UNUSUAL");
            explicit_bzero(&warning, sizeof(nbgl_warning_t));
            // TODO not sure about proper icons
            warning.introDetails = &warningDetails;
            warning.reviewDetails = &warningDetails;
            warning.info = &warningInfo;
            warning.introTopRightIcon = &WARNING_ICON;
            warning.reviewTopRightIcon = &WARNING_ICON;
            warningPtr = &warning;
            break;

        case POLICY_PROMPT_BEFORE_RESPONSE:
            TRACE("NO WARNING - POLICY_PROMPT_BEFORE_RESPONSE");
            break;

        default:
            TRACE("UNEXPECTED SECURITY POLICY: %d", securityPolicy);
            // Catch any truly unknown or unexpected policy values.
            ASSERT(false);
            break;
    }

    nbgl_useCaseAdvancedReview(TYPE_OPERATION,
                        g_pairsList,
                        &ICON_APP_CARDANO,
                        "Sign operational\ncertificate",
                        NULL,
                        "Sign certificate",
                        NULL,
                        warningPtr,
                        review_choice
    );

    TRACE("=== ui_display_opcert END ===");
    return 0;
}
