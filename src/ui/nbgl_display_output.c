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

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "mem.h"
#include "constants.h"
#include "address.h"
#include "tx_types.h"
#include "tx_output_types.h"
#include "nbgl_screens.h"
#include "utils/textUtils.h"
#include "nbgl_display_transaction_internal.h"

/**
 * Add pairs for destination address of an output
 * Handles both third-party and device-owned addresses
 *
 * @param[in] output The output item
 * @param[in] output_num Output number (for labeling)
 * @return true on success, false on failure
 */
static bool tx_output_add_destination_pairs(tx_output_list_item_t *output, uint16_t output_num) {
    if (output == NULL) {
        return false;
    }

    TRACE("Processing output %u destination (type=%u)", output_num, output->output_data.destination.type);

    char *temp_buf = tx_get_temp_display_buffer();

    if (output->output_data.destination.type == DESTINATION_THIRD_PARTY) {
        // Third-party address: display address directly
        explicit_bzero(temp_buf, 512);
        ui_getAddressScreen(temp_buf, 512,
                           output->output_data.destination.address.buffer,
                           output->output_data.destination.address.size);

        // Create address pair
        char addr_label[32];
        snprintf(addr_label, sizeof(addr_label), "Output %u address", output_num);
        if (!tx_pairs_push(addr_label, strlen(addr_label),
                          temp_buf, strlen(temp_buf))) {
            return false;
        }

    } else if (output->output_data.destination.type == DESTINATION_DEVICE_OWNED) {
        // Device-owned address: derive and display address

        // Derive address
        uint8_t address_bytes[MAX_ADDRESS_SIZE];
        size_t address_size = deriveAddress(&output->output_data.destination.params,
                                           address_bytes, MAX_ADDRESS_SIZE);
        TRACE("tx_output_add_destination_pairs: deriveAddress returned size=%u", address_size);
        if (address_size > 0) {
            TRACE("tx_output_add_destination_pairs: derived address: %.*H", address_size, address_bytes);
        }
        if (address_size == 0) {
            return false;
        }

        // Format address for display
        explicit_bzero(temp_buf, 512);
        ui_getAddressScreen(temp_buf, 512,
                           address_bytes, address_size);
        TRACE("tx_output_add_destination_pairs: formatted address: %s", temp_buf);

        // Create address pair
        char addr_label[32];
        snprintf(addr_label, sizeof(addr_label), "Output %u address", output_num);
        if (!tx_pairs_push(addr_label, strlen(addr_label),
                          temp_buf, strlen(temp_buf))) {
            return false;
        }

        // Add payment info
        explicit_bzero(temp_buf, 512);
        char temp_label[32] = {0};
        ui_getPaymentInfoScreen(temp_label, sizeof(temp_label),
                               temp_buf, 512,
                               &output->output_data.destination.params);

        char payment_label[32];
        snprintf(payment_label, sizeof(payment_label), "Output %u payment", output_num);
        if (!tx_pairs_push(payment_label, strlen(payment_label),
                          temp_buf, strlen(temp_buf))) {
            return false;
        }

        // Add staking info
        explicit_bzero(temp_buf, 512);
        ui_getStakingInfoScreen(temp_label, sizeof(temp_label),
                               temp_buf, 512,
                               &output->output_data.destination.params);

        char staking_label[32];
        snprintf(staking_label, sizeof(staking_label), "Output %u staking", output_num);
        if (!tx_pairs_push(staking_label, strlen(staking_label),
                          temp_buf, strlen(temp_buf))) {
            return false;
        }

    } else {
        return false;
    }

    return true;
}

/**
 * Add amount pair for an output
 *
 * @param[in] amount The amount in lovelace
 * @param[in] output_num Output number (for labeling)
 * @return true on success, false on failure
 */
static bool tx_output_add_amount_pair(uint64_t amount, uint16_t output_num) {
    char *temp_buf = tx_get_temp_display_buffer();
    explicit_bzero(temp_buf, 512);

    if (!str_formatAdaAmount(amount, temp_buf, 512)) {
        return false;
    }

    char amount_label[32];
    snprintf(amount_label, sizeof(amount_label), "Output %u amount", output_num);
    return tx_pairs_push(amount_label, strlen(amount_label),
                        temp_buf, strlen(temp_buf));
}

/**
 * Add token information for an output
 *
 * @param[in] output The output item
 * @param[in] output_num Output number (for labeling)
 * @return true on success, false on failure
 */
static bool tx_output_add_tokens_pairs(tx_output_list_item_t *output, uint16_t output_num) {
    if (output == NULL || output->output_data.numAssetGroups == 0) {
        return true;  // No tokens to display
    }

    char *temp_buf = tx_get_temp_display_buffer();
    char label[64];

    for (uint16_t ag = 0; ag < output->output_data.numAssetGroups; ag++) {
        asset_group_t *group = &output->output_data.assetGroups[ag];

        // Display policy ID
        snprintf(label, sizeof(label), "Output %u Token Policy", output_num);
        explicit_bzero(temp_buf, 512);
        for (int i = 0; i < 28; i++) {
            snprintf(temp_buf + i*2, 3, "%02x", group->policyId[i]);
        }
        if (!tx_pairs_push(label, strlen(label), temp_buf, strlen(temp_buf))) {
            return false;
        }

        // Display each token in group
        for (uint16_t tk = 0; tk < group->numTokens; tk++) {
            output_token_t *token = &group->tokens[tk];

            // Token name
            snprintf(label, sizeof(label), "Output %u Token %u Name", output_num, tk + 1);
            explicit_bzero(temp_buf, 512);
            if (token->assetNameLen > 0) {
                for (uint8_t i = 0; i < token->assetNameLen && i < 32; i++) {
                    snprintf(temp_buf + i*2, 3, "%02x", token->assetName[i]);
                }
            } else {
                strcpy(temp_buf, "(empty)");
            }
            if (!tx_pairs_push(label, strlen(label), temp_buf, strlen(temp_buf))) {
                return false;
            }

            // Token amount
            snprintf(label, sizeof(label), "Output %u Token %u Amount", output_num, tk + 1);
            explicit_bzero(temp_buf, 512);
            snprintf(temp_buf, 512, "%lld", (long long)token->amount);
            if (!tx_pairs_push(label, strlen(label), temp_buf, strlen(temp_buf))) {
                return false;
            }
        }
    }

    return true;
}

/**
 * Add datum information for an output
 *
 * @param[in] output The output item
 * @param[in] output_num Output number (for labeling)
 * @return true on success, false on failure
 */
static bool tx_output_add_datum_pairs(tx_output_list_item_t *output, uint16_t output_num) {
    // Check if datum is present (0xFF is our NONE marker)
    if (output == NULL || output->output_data.datum.type == 0xFF) {
        return true;  // No datum to display
    }

    char *temp_buf = tx_get_temp_display_buffer();
    char label[64];

    // Display datum type
    snprintf(label, sizeof(label), "Output %u Datum Type", output_num);
    const char *type_str = (output->output_data.datum.type == DATUM_HASH) ? "Hash" : "Inline";
    if (!tx_pairs_push(label, strlen(label), type_str, strlen(type_str))) {
        return false;
    }

    if (output->output_data.datum.type == DATUM_HASH) {
        // Display datum hash
        snprintf(label, sizeof(label), "Output %u Datum Hash", output_num);
        explicit_bzero(temp_buf, 512);
        for (int i = 0; i < 32; i++) {
            snprintf(temp_buf + i*2, 3, "%02x", output->output_data.datum.hash[i]);
        }
        if (!tx_pairs_push(label, strlen(label), temp_buf, strlen(temp_buf))) {
            return false;
        }
    } else {
        // Display inline datum size
        snprintf(label, sizeof(label), "Output %u Datum Size", output_num);
        explicit_bzero(temp_buf, 512);
        snprintf(temp_buf, 512, "%u bytes", output->output_data.datum.inline_data.size);
        if (!tx_pairs_push(label, strlen(label), temp_buf, strlen(temp_buf))) {
            return false;
        }

        // Display inline datum preview (truncated if large)
        snprintf(label, sizeof(label), "Output %u Datum Data", output_num);
        explicit_bzero(temp_buf, 512);
        uint16_t show_len = (output->output_data.datum.inline_data.size > 40) ?
                           40 : output->output_data.datum.inline_data.size;
        for (uint16_t i = 0; i < show_len; i++) {
            snprintf(temp_buf + i*2, 3, "%02x", output->output_data.datum.inline_data.data[i]);
        }
        if (show_len < output->output_data.datum.inline_data.size) {
            strcat(temp_buf, "...");
        }
        if (!tx_pairs_push(label, strlen(label), temp_buf, strlen(temp_buf))) {
            return false;
        }
    }

    return true;
}

/**
 * Add reference script information for an output
 *
 * @param[in] output The output item
 * @param[in] output_num Output number (for labeling)
 * @return true on success, false on failure
 */
static bool tx_output_add_refscript_pairs(tx_output_list_item_t *output, uint16_t output_num) {
    if (output == NULL || !output->output_data.hasRefScript) {
        return true;  // No reference script to display
    }

    char *temp_buf = tx_get_temp_display_buffer();
    char label[64];

    // Display reference script size
    snprintf(label, sizeof(label), "Output %u Ref Script", output_num);
    explicit_bzero(temp_buf, 512);
    snprintf(temp_buf, 512, "%u bytes", output->output_data.refScript.size);
    if (!tx_pairs_push(label, strlen(label), temp_buf, strlen(temp_buf))) {
        return false;
    }

    // Display reference script preview (truncated if large)
    snprintf(label, sizeof(label), "Output %u Ref Script Data", output_num);
    explicit_bzero(temp_buf, 512);
    uint16_t show_len = (output->output_data.refScript.size > 40) ?
                       40 : output->output_data.refScript.size;
    for (uint16_t i = 0; i < show_len; i++) {
        snprintf(temp_buf + i*2, 3, "%02x", output->output_data.refScript.data[i]);
    }
    if (show_len < output->output_data.refScript.size) {
        strcat(temp_buf, "...");
    }
    if (!tx_pairs_push(label, strlen(label), temp_buf, strlen(temp_buf))) {
        return false;
    }

    return true;
}

/**
 * Add all output pairs to the transaction review display
 * Processes each output and adds appropriate pairs based on destination type
 *
 * @param[in] tx The transaction structure
 * @return true on success, false on memory allocation failure
 */
bool tx_output_add_all_pairs(transaction_t *tx) {
    if (tx == NULL) {
        return false;
    }

    TRACE("Adding all %u outputs to display", tx->num_outputs);

    uint16_t output_num = 1;
    s_flist_node *node = tx->outputs;

    while (node != NULL) {
        tx_output_list_item_t *output_item = (tx_output_list_item_t *) node;

        // Add destination pairs (address, and payment/staking for device-owned)
        if (!tx_output_add_destination_pairs(output_item, output_num)) {
            return false;
        }

        // Add amount pair
        if (!tx_output_add_amount_pair(output_item->output_data.adaAmount, output_num)) {
            return false;
        }

        // Add tokens pairs
        if (!tx_output_add_tokens_pairs(output_item, output_num)) {
            return false;
        }

        // Add datum pairs
        if (!tx_output_add_datum_pairs(output_item, output_num)) {
            return false;
        }

        // Add reference script pairs
        if (!tx_output_add_refscript_pairs(output_item, output_num)) {
            return false;
        }

        output_num++;
        node = node->next;
    }

    TRACE("Finished adding all outputs to display");
    return true;
}

/**
 * Add fee pair to the transaction review display
 *
 * @param[in] fee The fee amount in lovelace
 * @return true on success, false on memory allocation failure
 */
bool tx_fee_add_pair(uint64_t fee) {
    char *temp_buf = tx_get_temp_display_buffer();
    explicit_bzero(temp_buf, 512);

    if (!str_formatAdaAmount(fee, temp_buf, 512)) {
        return false;
    }

    return tx_pairs_push("Fee", 3, temp_buf, strlen(temp_buf));
}

/**
 * Add TTL (time-to-live) pair to the transaction review display
 *
 * @param[in] ttl The TTL value (slot number)
 * @return true on success, false on memory allocation failure
 */
bool tx_ttl_add_pair(uint64_t ttl) {
    char *temp_buf = tx_get_temp_display_buffer();
    explicit_bzero(temp_buf, 512);

    ui_getUint64Screen(temp_buf, 512, ttl);

    return tx_pairs_push("TTL", 3, temp_buf, strlen(temp_buf));
}
