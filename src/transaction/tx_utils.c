/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "tx_utils.h"

#include <stddef.h>
#include <string.h>

#include "mem.h"
#include "globals.h"
#include "bip44.h"
#include "assert.h"
#include "utils.h"

uint8_t* tx_alloc_temp_buffer_or_fail(size_t size) {
    uint8_t* buffer = NULL;
    bool allocated = allocate_zeroed((void**) &buffer, size);
    ASSERT(allocated && buffer != NULL);
    return buffer;
}

bool violatesSingleAccountOrStoreIt(const bip44_path_t* path) {
    ASSERT(path != NULL);
    TRACE("Considering path");
    BIP44_PRINTF(path);
    TRACE("");

    single_account_data_t* singleAccountData = &(G_context.tx_info.single_account_data);

    ASSERT(bip44_hasOrdinaryWalletKeyPrefix(path) && bip44_containsAccount(path));

    const bool isByron = bip44_hasByronPrefix(path);
    const uint32_t account = bip44_getAccount(path);

    if (singleAccountData->isStored) {
        const uint32_t storedAccount = singleAccountData->accountNumber;
        if (account != storedAccount) {
            TRACE("Account mismatch: current=%u, stored=%u", account, storedAccount);
            return true;
        }
        const bool combinesByronAndShelley = singleAccountData->isByron != isByron;
        const bool combinationAllowed = (storedAccount == bip44_harden(0));
        if (combinesByronAndShelley && !combinationAllowed) {
            TRACE("Byron/Shelley mixing not allowed for account %u", storedAccount);
            return true;
        }
    } else {
        singleAccountData->isStored = true;
        singleAccountData->isByron = isByron;
        singleAccountData->accountNumber = account;
        TRACE("Stored single account data: account=%u, isByron=%d", account, isByron);
    }

    return false;
}

bool tx_output_destination_to_address_bytes(const tx_output_destination_t* destination,
                                            uint8_t* addressBuffer,
                                            size_t addressBufferSize,
                                            size_t* outAddressLength) {
    ASSERT(destination != NULL);
    ASSERT(addressBuffer != NULL);
    ASSERT(outAddressLength != NULL);

    LEDGER_ASSERT(addressBufferSize < BUFFER_SIZE_PARANOIA,
                  "address buffer size too large: %u",
                  (unsigned) addressBufferSize);

    switch (destination->type) {
        case DESTINATION_THIRD_PARTY:
            ASSERT(destination->address.buffer != NULL);
            ASSERT(destination->address.length > 0);
            ASSERT(destination->address.length <= MAX_ADDRESS_LENGTH);
            ASSERT(destination->address.length <= addressBufferSize);

            memmove(addressBuffer, destination->address.buffer, destination->address.length);
            *outAddressLength = destination->address.length;
            return true;

        case DESTINATION_DEVICE_OWNED: {
            size_t derivedAddressLength =
                deriveAddress(&destination->params, addressBuffer, addressBufferSize);
            LEDGER_ASSERT(derivedAddressLength > 0 && derivedAddressLength <= MAX_ADDRESS_LENGTH &&
                              derivedAddressLength <= addressBufferSize,
                          "Invalid derived destination address length: %u",
                          (unsigned) derivedAddressLength);
            *outAddressLength = derivedAddressLength;
            return true;
        }

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            return false;
            // LCOV_EXCL_STOP
    }
}

__noinline_due_to_stack__ bool format_tx_output_destination_human_readable(
    const tx_output_destination_t* destination,
    char* out,
    size_t outSize) {
    // Use a stack buffer — formatters used with UI_ADD_FORMAT* must not heap-allocate.
    // See the contract note in ui_utils.h.
    uint8_t address_bytes[MAX_ADDRESS_LENGTH];
    explicit_bzero(address_bytes, sizeof(address_bytes));

    size_t address_size = 0;
    bool destination_parsed = tx_output_destination_to_address_bytes(destination,
                                                                     address_bytes,
                                                                     MAX_ADDRESS_LENGTH,
                                                                     &address_size);
    LEDGER_ASSERT(destination_parsed, "Failed to build output address bytes for UI");

    return format_address_human_readable(address_bytes, address_size, out, outSize);
}
