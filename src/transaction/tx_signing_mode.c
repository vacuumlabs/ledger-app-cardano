/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "tx_signing_mode.h"

#include "assert.h"
#include "tx.h"

bool is_valid_tx_signing_mode(uint8_t raw_mode) {
    switch (raw_mode) {
        case SIGN_TX_SIGNINGMODE_ORDINARY:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
        case SIGN_TX_SIGNINGMODE_MULTISIG:
        case SIGN_TX_SIGNINGMODE_PLUTUS:
        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
        case SIGN_TX_SIGNINGMODE_AUTO:
            return true;
        default:
            return false;
    }
}

static bool _has_plutus_indicator(const tx_params_t *tx_params) {
    return tx_params->num_collateral_inputs > 0 || tx_params->includeCollateralOutput ||
           tx_params->includeTotalCollateral || tx_params->num_reference_inputs > 0 ||
           tx_params->includeScriptDataHash;
}

bool resolve_auto_tx_signing_mode(tx_params_t *tx_params) {
    ASSERT(tx_params != NULL);

    if (tx_params->txSigningMode != SIGN_TX_SIGNINGMODE_AUTO) {
        return true;
    }

    if (_has_plutus_indicator(tx_params)) {
        tx_params->txSigningMode = SIGN_TX_SIGNINGMODE_PLUTUS;
        return true;
    }

    // Pool, ordinary, and multisig are indistinguishable from init-APDU fields
    // alone.  The host must supply a concrete mode for these cases.
    return false;
}
