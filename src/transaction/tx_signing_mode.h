/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "tx.h"

/**
 * Returns true if the given byte value is a valid tx signing mode accepted on
 * the wire (including SIGN_TX_SIGNINGMODE_AUTO).
 */
bool is_valid_tx_signing_mode(uint8_t raw_mode);

/**
 * Attempt to resolve SIGN_TX_SIGNINGMODE_AUTO to a concrete mode using only
 * the fields available in the init APDU (tx_params_t).
 *
 * If any Plutus indicator is set (collateral inputs, collateral output, total
 * collateral, reference inputs, or script data hash), the mode is resolved to
 * SIGN_TX_SIGNINGMODE_PLUTUS_TX immediately.
 *
 * For all other AUTO transactions (pool, ordinary, multisig) the information
 * needed to distinguish modes is not available in the init APDU, so this
 * function returns false and the caller must return
 * SWO_AMBIGUOUS_TX_SIGNING_MODE to the host.
 *
 * If tx_params->txSigningMode is not SIGN_TX_SIGNINGMODE_AUTO this function
 * is a no-op and returns true.
 *
 * On success, tx_params->txSigningMode holds a concrete (non-AUTO) mode.
 * Returns false when the mode cannot be determined.
 */
bool resolve_auto_tx_signing_mode(tx_params_t *tx_params);
