/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>
#include "assert.h"
#include "cardano_constants.h"

/**
 * Build the CIP-0129 governance identifier header byte: high nibble = key type,
 * low nibble = credential type (see GOVERNANCE_ID_KEY_TYPE_* / GOVERNANCE_ID_CREDENTIAL_*_HASH).
 */
static inline uint8_t governance_id_header(uint8_t keyType, uint8_t credentialType) {
    switch (keyType) {
        case GOVERNANCE_ID_KEY_TYPE_COMMITTEE_HOT:
        case GOVERNANCE_ID_KEY_TYPE_COMMITTEE_COLD:
        case GOVERNANCE_ID_KEY_TYPE_DREP:
            break;
        default:
            LEDGER_ASSERT(false, "invalid governance key type");
    }
    switch (credentialType) {
        case GOVERNANCE_ID_CREDENTIAL_KEY_HASH:
        case GOVERNANCE_ID_CREDENTIAL_SCRIPT_HASH:
            break;
        default:
            LEDGER_ASSERT(false, "invalid governance credential type");
    }
    return (uint8_t) ((keyType << 4) | credentialType);
}
