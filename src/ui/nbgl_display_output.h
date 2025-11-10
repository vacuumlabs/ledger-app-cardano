#pragma once

#include "tx_types.h"

/**
 * Add all output pairs to the transaction review display
 * Processes each output and adds appropriate pairs based on destination type
 *
 * @param[in] tx The transaction structure
 * @return true on success, false on memory allocation failure
 */
bool tx_output_add_all_pairs(transaction_t *tx);

/**
 * Add fee pair to the transaction review display
 *
 * @param[in] fee The fee amount in lovelace
 * @return true on success, false on memory allocation failure
 */
bool tx_fee_add_pair(uint64_t fee);

/**
 * Add TTL (time-to-live) pair to the transaction review display
 *
 * @param[in] ttl The TTL value (slot number)
 * @return true on success, false on memory allocation failure
 */
bool tx_ttl_add_pair(uint64_t ttl);
