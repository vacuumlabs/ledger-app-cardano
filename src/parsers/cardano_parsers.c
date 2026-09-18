/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "buffer.h"
#include "bip44.h"
#include "cardano_constants.h"
#include "cardano_parsers.h"
#include "tx_certificate_types.h"
#include "assert.h"
#include "textUtils.h"
#include "utils.h"
#include "cardano_buffer.h"

#include <string.h>

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_TX_PARSE to trace this module's parsing details.
 */
#ifdef TRACE_TX_PARSE
#define TRACE_MODULE(...) TRACE("[cardano_parsers] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif

bool buffer_read_flag_included(buffer_t *buf, bool *result) {
    ASSERT(buf != NULL);
    ASSERT(result != NULL);

    uint8_t value;
    if (!buffer_read_u8(buf, &value)) {
        return false;
    }

    switch (value) {
        case FLAG_INCLUDED_YES:
            *result = true;
            return true;
        case FLAG_INCLUDED_NO:
            *result = false;
            return true;
        default:
            TRACE("Invalid flag included value: 0x%02x", value);
            return false;
    }
}

bool buffer_read_bytes(buffer_t *buffer, uint8_t *destBuffer, size_t n) {
    ASSERT(buffer != NULL);
    ASSERT(destBuffer != NULL);

    if (!buffer_can_read(buffer, n)) {
        return false;
    }

    memmove(destBuffer, buffer_get_cur(buffer), n);
    return buffer_seek_cur(buffer, n);
}

bool buffer_read_int64(buffer_t *buffer, int64_t *value, endianness_t endianness) {
    ASSERT(buffer != NULL);
    ASSERT(value != NULL);

    uint64_t unsigned_value;
    if (!buffer_read_u64(buffer, &unsigned_value, endianness)) {
        return false;
    }

    *value = (int64_t) unsigned_value;
    return true;
}

bool buffer_read_anchor(buffer_t *buf, anchor_t *anchor) {
    ASSERT(buf != NULL);
    ASSERT(anchor != NULL);

    // used also for pool medatadata which is essentially the same thing
    STATIC_ASSERT(MAX_ANCHOR_URL_LENGTH == MAX_POOL_METADATA_URL_LENGTH,
                  "URL length limits must match");
    STATIC_ASSERT(ANCHOR_HASH_LENGTH == POOL_METADATA_HASH_LENGTH, "Hash lengths must match");

    anchor->isIncluded = false;
    anchor->url = NULL;
    anchor->urlLength = 0;
    anchor->hash = NULL;

    if (!buffer_read_flag_included(buf, &anchor->isIncluded)) {
        TRACE("Invalid anchor present flag");
        return false;
    }
    TRACE_MODULE("Anchor included flag: %u", anchor->isIncluded);
    if (!anchor->isIncluded) {
        // finished parsing
        return true;
    }

    if (!buffer_read_u16(buf, &anchor->urlLength, BE)) {
        TRACE("Failed to read anchor URL length");
        return false;
    }
    TRACE_MODULE("Anchor URL length: %u", anchor->urlLength);
    if (anchor->urlLength > MAX_ANCHOR_URL_LENGTH) {
        TRACE("Anchor URL length exceeds maximum: %u > %u",
              anchor->urlLength,
              MAX_ANCHOR_URL_LENGTH);
        return false;
    }

    if (!buffer_read_bytes_ptr(buf, &anchor->url, anchor->urlLength)) {
        TRACE("Failed to read URL");
        return false;
    }
    ASSERT(anchor->url != NULL);
    if (!str_isPrintableAsciiWithoutSpaces(anchor->url, anchor->urlLength)) {
        TRACE("Anchor URL contains non-printable ASCII or spaces");
        return false;
    }
    if (!buffer_read_bytes_ptr(buf, &anchor->hash, ANCHOR_HASH_LENGTH)) {
        TRACE("Failed to read anchor hash");
        return false;
    }
    ASSERT(anchor->hash != NULL);

    return true;
}

bool buffer_read_drep(buffer_t *buf, ext_drep_t *drep) {
    TRACE("Parsing DRep");
    uint8_t drep_type_wire;
    if (!buffer_read_u8(buf, &drep_type_wire)) {
        TRACE("Failed to read DRep type byte");
        return false;
    }

    TRACE("DRep type wire=0x%02x", drep_type_wire);
    ext_drep_type_t drep_type = {0};
    switch (drep_type_wire) {
        case EXT_DREP_KEY_HASH:
            drep_type = EXT_DREP_KEY_HASH;
            TRACE("DRep type: KEY_HASH");
            break;
        case EXT_DREP_SCRIPT_HASH:
            drep_type = EXT_DREP_SCRIPT_HASH;
            TRACE("DRep type: SCRIPT_HASH");
            break;
        case EXT_DREP_ABSTAIN:
            drep_type = EXT_DREP_ABSTAIN;
            TRACE("DRep type: ABSTAIN");
            break;
        case EXT_DREP_NO_CONFIDENCE:
            drep_type = EXT_DREP_NO_CONFIDENCE;
            TRACE("DRep type: NO_CONFIDENCE");
            break;
        case EXT_DREP_KEY_PATH:
            drep_type = EXT_DREP_KEY_PATH;
            TRACE("DRep type: KEY_PATH");
            break;
        default:
            TRACE("Invalid DRep type wire: 0x%02x", drep_type_wire);
            return false;
    }
    drep->type = drep_type;

    switch (drep_type) {
        case EXT_DREP_KEY_PATH:
            if (!buffer_read_bip44_path(buf, &drep->keyPath)) {
                TRACE("Failed to read DRep BIP44 path");
                return false;
            }
            TRACE("Successfully parsed DRep KEY_PATH");
            break;
        case EXT_DREP_KEY_HASH: {
            if (!buffer_read_bytes_ptr(buf, &drep->keyHash, ADDRESS_KEY_HASH_LENGTH)) {
                TRACE("Failed to read DRep key hash");
                return false;
            }
            TRACE("Successfully parsed DRep KEY_HASH");
            break;
        }
        case EXT_DREP_SCRIPT_HASH: {
            if (!buffer_read_bytes_ptr(buf, &drep->scriptHash, SCRIPT_HASH_LENGTH)) {
                TRACE("Failed to read DRep script hash");
                return false;
            }
            TRACE("Successfully parsed DRep SCRIPT_HASH");
            break;
        }
        case EXT_DREP_ABSTAIN:
        case EXT_DREP_NO_CONFIDENCE:
            TRACE("DRep has no additional data");
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            return false;
            // LCOV_EXCL_STOP
    }
    TRACE("Successfully parsed DRep");
    return true;
}

// =============================================================================
// Credential Parsing Implementation
// =============================================================================

/**
 * Parse credential type byte from wire format.
 *
 * Wire format values:
 *   0 = EXT_CREDENTIAL_KEY_HASH
 *   1 = EXT_CREDENTIAL_SCRIPT_HASH
 *   2 = EXT_CREDENTIAL_KEY_PATH
 *
 * @param[in] buf Buffer to read from
 * @param[out] cred_type Parsed credential type
 * @return true on success, false on failure
 */
static bool _parse_credential_type(buffer_t *buf, ext_credential_type_t *cred_type) {
    uint8_t cred_type_wire;
    if (!buffer_read_u8(buf, &cred_type_wire)) {
        TRACE("Failed to read credential type byte");
        return false;
    }

    TRACE("Parsing credential type wire=0x%02x", cred_type_wire);

    switch (cred_type_wire) {
        case EXT_CREDENTIAL_KEY_HASH:
            *cred_type = EXT_CREDENTIAL_KEY_HASH;
            break;
        case EXT_CREDENTIAL_SCRIPT_HASH:
            *cred_type = EXT_CREDENTIAL_SCRIPT_HASH;
            break;
        case EXT_CREDENTIAL_KEY_PATH:
            *cred_type = EXT_CREDENTIAL_KEY_PATH;
            break;
        default:
            TRACE("Invalid credential type wire value: 0x%02x", cred_type_wire);
            return false;
    }
    return true;
}

/**
 * Parse credential data based on its type.
 *
 * @param[in] buf Buffer to read from
 * @param[in] cred_type Credential type to parse
 * @param[out] credential Credential structure to populate
 * @return true on success, false on failure
 */
static bool _parse_credential_data(buffer_t *buf,
                                   ext_credential_type_t cred_type,
                                   ext_credential_t *credential) {
    TRACE("Parsing credential data for type=%u", cred_type);
    switch (cred_type) {
        case EXT_CREDENTIAL_KEY_PATH:
            if (!buffer_read_bip44_path(buf, &credential->keyPath)) {
                TRACE("Failed to read BIP44 path");
                return false;
            }
            break;
        case EXT_CREDENTIAL_KEY_HASH: {
            if (!buffer_read_bytes_ptr(buf, &credential->keyHash, ADDRESS_KEY_HASH_LENGTH)) {
                TRACE("Failed to read key hash");
                return false;
            }
            ASSERT(credential->keyHash != NULL);
            break;
        }
        case EXT_CREDENTIAL_SCRIPT_HASH: {
            if (!buffer_read_bytes_ptr(buf, &credential->scriptHash, SCRIPT_HASH_LENGTH)) {
                TRACE("Failed to read script hash");
                return false;
            }
            ASSERT(credential->scriptHash != NULL);
            break;
        }
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Invalid internal credential type: %u", cred_type);
            return false;
            // LCOV_EXCL_STOP
    }
    return true;
}

bool buffer_read_credential(buffer_t *buf, ext_credential_t *credential) {
    ext_credential_type_t cred_type = {0};
    if (!_parse_credential_type(buf, &cred_type)) {
        TRACE("Failed to parse credential type");
        return false;
    }
    credential->type = cred_type;

    if (!_parse_credential_data(buf, cred_type, credential)) {
        TRACE("Failed to parse credential data");
        return false;
    }
    return true;
}

bool buffer_read_pool_reward_account(buffer_t *buf, pool_reward_account_t *reward_account) {
    ASSERT(buf != NULL);
    ASSERT(reward_account != NULL);

    uint8_t reward_account_type = 0;
    if (!buffer_read_u8(buf, &reward_account_type)) {
        TRACE("Failed to read reward account type");
        return false;
    }

    switch (reward_account_type) {
        case EXT_CREDENTIAL_KEY_HASH:
            reward_account->keyReferenceType = KEY_REFERENCE_HASH;
            if (!buffer_read_bytes_ptr(buf, &reward_account->hashBuffer, REWARD_ACCOUNT_LENGTH)) {
                TRACE("Failed to read reward account hash");
                return false;
            }
            ASSERT(reward_account->hashBuffer != NULL);
            break;
        case EXT_CREDENTIAL_KEY_PATH:
            reward_account->keyReferenceType = KEY_REFERENCE_PATH;
            if (!buffer_read_bip44_path(buf, &reward_account->path)) {
                TRACE("Failed to read reward account path");
                return false;
            }
            break;
        default:
            TRACE("Unknown reward account type: 0x%02x", (unsigned) reward_account_type);
            return false;
    }

    return true;
}
