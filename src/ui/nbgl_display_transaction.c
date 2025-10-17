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
#include "os_io_seproxyhal.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "bip32.h"
#include "format.h"

#include "display.h"
#include "constants.h"
#include "globals.h"
#include "sw.h"
#include "address.h"
#include "tx_types.h"
#include "tx_output_types.h"
#include "tx_warnings.h"
#include "deserialize.h"
#include "menu.h"
#include "mem.h"
#include "addressUtils/addressUtilsShelley.h"
#include "nbgl_screens.h"
#include "nbgl_display_output.h"
#include "utils/textUtils.h"
#include "utils/list.h"

/**
 * Display pair structure for transaction review
 * Each pair represents a key-value item to display
 * The pair owns copies of key and value strings
 */
typedef struct {
    s_flist_node node;  // Linked list node
    char *key;          // Heap-allocated key string
    char *value;        // Heap-allocated value string
} tx_display_pair_t;

// Global state for pair construction
static tx_display_pair_t *g_pairs_list = NULL;     // Head of linked list
static uint16_t g_actual_pairs = 0;                // Count of pairs added

// NBGL display structures (populated from linked list at display time)
static nbgl_contentTagValue_t *g_pairs = NULL;
static nbgl_contentTagValueList_t *g_pairsList = NULL;

// Reusable temporary buffer for formatting display strings
static char g_tmp_display_buffer[512];

// Warning info for network warnings
static char g_warning_msg[128];
static nbgl_contentCenter_t warningInfo;
static nbgl_warningDetails_t warningDetails;
static nbgl_warning_t warning = {0};

// called when long press button on 3rd page is long-touched or when reject footer is touched
static void review_choice(bool confirm) {
    if (confirm) {
        // User approved transaction
        // Set state to APPROVED and return tx hash
        // Witnesses will be handled in separate APDUs
        G_context.state = STATE_APPROVED;

        // Initialize witness counters
        G_context.tx_info.current_witness = 0;
        // num_witnesses should be set during tx init (TODO: add to deserializer)

        // Send tx hash back to client
        io_send_response_pointer(G_context.tx_info.tx_hash, sizeof(G_context.tx_info.tx_hash), SW_OK);

        // Show status
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        // User rejected
        G_context.state = STATE_NONE;

        // Free parsed transaction outputs (dynamically allocated data)
        transaction_free_outputs(&G_context.tx_info.transaction);

        // Free transaction buffer
        if (G_context.tx_info.raw_tx != NULL) {
            app_mem_free(G_context.tx_info.raw_tx);
            G_context.tx_info.raw_tx = NULL;
        }

        io_send_sw(SW_DENY);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

/**
 * Deletion callback for pair linked list cleanup
 * Frees the key, value, and pair structure itself
 */
static void delete_tx_pair(s_flist_node *node) {
    if (node == NULL) return;

    tx_display_pair_t *pair = (tx_display_pair_t *) node;
    if (pair->key != NULL) {
        app_mem_free(pair->key);
    }
    if (pair->value != NULL) {
        app_mem_free(pair->value);
    }
    app_mem_free(pair);
}

/**
 * Initialize pair construction
 * Clears any existing pairs and resets the linked list
 */
static void tx_pairs_init(void) {
    if (g_pairs_list != NULL) {
        flist_clear((s_flist_node **) &g_pairs_list, delete_tx_pair);
    }
    g_pairs_list = NULL;
    g_actual_pairs = 0;
}

/**
 * Get the reusable temporary display buffer
 *
 * @return pointer to temporary buffer (512 bytes)
 */
char *tx_get_temp_display_buffer(void) {
    return g_tmp_display_buffer;
}

/**
 * Add a key-value pair to the linked list
 * Creates copies of both key and value strings, so caller's buffers can be freed immediately
 *
 * @param[in] key The key string (will be copied)
 * @param[in] key_len Length of key string (not including null terminator)
 * @param[in] value The value string (will be copied)
 * @param[in] value_len Length of value string (not including null terminator)
 * @return true on success, false on memory allocation failure
 */
bool tx_pairs_push(const char *key, size_t key_len,
                   const char *value, size_t value_len) {
    // Allocate pair structure
    tx_display_pair_t *pair = (tx_display_pair_t *) app_mem_alloc(sizeof(*pair));
    if (pair == NULL) {
        TRACE("ERROR: tx_pairs_push failed to allocate pair structure");
        return false;
    }

    // Initialize node
    pair->node.next = NULL;
    pair->key = NULL;
    pair->value = NULL;

    // Allocate and copy key
    pair->key = (char *) app_mem_alloc(key_len + 1);
    if (pair->key == NULL) {
        TRACE("ERROR: tx_pairs_push failed to allocate key buffer");
        app_mem_free(pair);
        return false;
    }
    memcpy(pair->key, key, key_len);
    pair->key[key_len] = '\0';

    // Allocate and copy value
    pair->value = (char *) app_mem_alloc(value_len + 1);
    if (pair->value == NULL) {
        TRACE("ERROR: tx_pairs_push failed to allocate value buffer");
        app_mem_free(pair->key);
        app_mem_free(pair);
        return false;
    }
    memcpy(pair->value, value, value_len);
    pair->value[value_len] = '\0';

    // Append to linked list
    flist_push_back((s_flist_node **) &g_pairs_list, (s_flist_node *) pair);
    g_actual_pairs++;

    return true;
}

/**
 * Convert linked list of pairs to flat array for NBGL display
 * Allocates the flat pair array and populates it from the linked list
 *
 * @return true on success, false on memory allocation failure
 */
static bool tx_pairs_build_display_array(void) {
    TRACE("tx_pairs_build_display_array: START - building array from %u pairs", g_actual_pairs);

    // Count pairs
    size_t pair_count = flist_size((s_flist_node **) &g_pairs_list);
    if (pair_count != g_actual_pairs) {
        TRACE("ERROR: pair count mismatch, size=%u, actual=%u", (unsigned)pair_count, g_actual_pairs);
        return false;
    }

    // Allocate flat pair array
    size_t array_size = pair_count * sizeof(nbgl_contentTagValue_t);
    g_pairs = (nbgl_contentTagValue_t *) app_mem_alloc(array_size);
    if (g_pairs == NULL) {
        TRACE("ERROR: failed to allocate flat pair array (%u bytes)", (unsigned)array_size);
        return false;
    }

    // Allocate pair list structure
    g_pairsList = (nbgl_contentTagValueList_t *) app_mem_alloc(sizeof(nbgl_contentTagValueList_t));
    if (g_pairsList == NULL) {
        TRACE("ERROR: failed to allocate pair list structure");
        app_mem_free(g_pairs);
        g_pairs = NULL;
        return false;
    }

    // Traverse linked list and populate flat array
    nbgl_contentTagValue_t *tag = g_pairs;
    tx_display_pair_t *pair = g_pairs_list;
    uint16_t idx = 0;
    while (pair != NULL) {
        // Validate pointers before assignment
        if (pair->key == NULL || pair->value == NULL) {
            TRACE("ERROR: pair %u has NULL key or value", idx);
            app_mem_free(g_pairs);
            app_mem_free(g_pairsList);
            g_pairs = NULL;
            g_pairsList = NULL;
            return false;
        }

        tag->item = pair->key;
        tag->value = pair->value;
        tag++;
        pair = (tx_display_pair_t *) pair->node.next;
        idx++;
    }

    // Verify iteration count matches
    if (idx != pair_count) {
        TRACE("ERROR: iteration count mismatch - iterated=%u, expected=%u", idx, (unsigned)pair_count);
        app_mem_free(g_pairs);
        app_mem_free(g_pairsList);
        g_pairs = NULL;
        g_pairsList = NULL;
        return false;
    }

    // Setup pair list structure
    g_pairsList->nbMaxLinesForValue = 0;
    g_pairsList->nbPairs = (uint16_t) pair_count;
    g_pairsList->pairs = g_pairs;

    TRACE("tx_pairs_build_display_array: END - successfully built array with %u pairs", (unsigned)pair_count);
    return true;
}

/**
 * Cleanup all pairs and display structures
 */
static void tx_pairs_destroy(void) {
    if (g_pairs_list != NULL) {
        flist_clear((s_flist_node **) &g_pairs_list, delete_tx_pair);
        g_pairs_list = NULL;
    }
    if (g_pairs != NULL) {
        app_mem_free(g_pairs);
        g_pairs = NULL;
    }
    if (g_pairsList != NULL) {
        app_mem_free(g_pairsList);
        g_pairsList = NULL;
    }
    g_actual_pairs = 0;
}

// Public function to start the transaction review
// - Check if the app is in the right state for transaction review
// - Build pairs dynamically as a linked list
// - Convert to flat array and display
int ui_display_transaction(void) {
    if (G_context.req_type != REQUEST_CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    // Read transaction fields into local variables to avoid macro expansion issues
    // with ternary operators in the original code
    uint64_t fee = G_context.tx_info.transaction.fee;
    uint16_t num_outputs = G_context.tx_info.transaction.num_outputs;
    uint16_t num_inputs = G_context.tx_info.transaction.num_inputs;
    bool include_ttl = G_context.tx_info.transaction.includeTtl;

    TRACE("Preparing transaction display (fee=%llu, ttl=%s, outputs=%u, inputs=%u)",
          fee,
          include_ttl ? "yes" : "no",
          num_outputs,
          num_inputs);

    // Initialize pair construction (linked list)
    tx_pairs_init();

    // Add fee pair
    if (!tx_fee_add_pair(fee)) {
        tx_pairs_destroy();
        return io_send_sw(SW_TX_PARSING_FAIL);
    }

    // Add TTL pair if included
    if (include_ttl) {
        if (!tx_ttl_add_pair(G_context.tx_info.transaction.ttl)) {
            tx_pairs_destroy();
            return io_send_sw(SW_TX_PARSING_FAIL);
        }
    }

    // Add all output pairs
    if (!tx_output_add_all_pairs(&G_context.tx_info.transaction)) {
        tx_pairs_destroy();
        return io_send_sw(SW_TX_PARSING_FAIL);
    }

    // Add transaction hash pair
    {
        char *temp_buf = tx_get_temp_display_buffer();
        if (temp_buf == NULL) {
            tx_pairs_destroy();
            return io_send_sw(SW_TX_PARSING_FAIL);
        }
        explicit_bzero(temp_buf, 512);
        ui_getHexBufferScreen(temp_buf, 512, G_context.tx_info.tx_hash, sizeof(G_context.tx_info.tx_hash));
        if (!tx_pairs_push("Transaction hash", 16, temp_buf, strlen(temp_buf))) {
            tx_pairs_destroy();
            return io_send_sw(SW_TX_PARSING_FAIL);
        }
    }

    // Convert linked list to flat array for NBGL display
    if (!tx_pairs_build_display_array()) {
        tx_pairs_destroy();
        return io_send_sw(SW_TX_PARSING_FAIL);
    }

    // Check if we have warnings to display
    const nbgl_warning_t* warningPtr = NULL;
    TRACE("ui_display_transaction: checking for warnings");
    if (!tx_warning_list_empty((tx_warning_list_item_t *)G_context.tx_info.warning_list)) {
        PRINTF("Warnings detected, preparing warning display\n");

        // Concatenate all warning messages
        explicit_bzero(g_warning_msg, sizeof(g_warning_msg));
        size_t offset = 0;
        tx_warning_list_item_t *warning_node = (tx_warning_list_item_t *)G_context.tx_info.warning_list;
        while (warning_node != NULL && offset < sizeof(g_warning_msg) - 2) {
            const char *msg = tx_warning_get_message(warning_node->type);
            size_t msg_len = strlen(msg);
            if (offset + msg_len + 2 < sizeof(g_warning_msg)) {
                if (offset > 0) {
                    g_warning_msg[offset++] = '\n';
                }
                memmove(g_warning_msg + offset, msg, msg_len);
                offset += msg_len;
            }
            warning_node = (tx_warning_list_item_t *)warning_node->node.next;
        }

        // Setup warning structures
        explicit_bzero(&warningInfo, sizeof(warningInfo));
        warningInfo.icon = &WARNING_ICON;
        warningInfo.title = "Transaction Warning";
        warningInfo.description = g_warning_msg;

        explicit_bzero(&warningDetails, sizeof(warningDetails));
        warningDetails.title = "Transaction Warning";
        warningDetails.type = CENTERED_INFO_WARNING;
        warningDetails.centeredInfo.icon = &WARNING_ICON;
        warningDetails.centeredInfo.title = "Transaction Warning";
        warningDetails.centeredInfo.description = g_warning_msg;

        explicit_bzero(&warning, sizeof(warning));
        warning.introDetails = &warningDetails;
        warning.reviewDetails = &warningDetails;
        warning.info = &warningInfo;
        warning.introTopRightIcon = &WARNING_ICON;
        warning.reviewTopRightIcon = &WARNING_ICON;
        warningPtr = &warning;

        PRINTF("Warning display prepared\n");
    }

    // Start review flow (with or without warnings)
    TRACE("ui_display_transaction: starting review flow, warningPtr=%p", warningPtr);
    if (warningPtr != NULL) {
        // Use advanced review with warnings
        TRACE("ui_display_transaction: calling nbgl_useCaseAdvancedReview");
        nbgl_useCaseAdvancedReview(TYPE_TRANSACTION,
                                  g_pairsList,
                                  &ICON_APP_CARDANO,
                                  "Review transaction",
                                  NULL,
                                  "Sign transaction",
                                  NULL,
                                  warningPtr,
                                  review_choice);
        TRACE("ui_display_transaction: returned from nbgl_useCaseAdvancedReview");
    } else {
        // Use simple review without warnings
        TRACE("ui_display_transaction: calling nbgl_useCaseReview");
        nbgl_useCaseReview(TYPE_TRANSACTION,
                          g_pairsList,
                          &ICON_APP_CARDANO,
                          "Review transaction",
                          NULL,
#ifdef SCREEN_SIZE_WALLET
                          "Sign transaction",
#else
                          NULL,
#endif
                          review_choice);
        TRACE("ui_display_transaction: returned from nbgl_useCaseReview");
    }
    TRACE("ui_display_transaction: END");
    return 0;
}
