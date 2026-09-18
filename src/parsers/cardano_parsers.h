/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"
#include "cardano_buffer.h"
#include "tx_address_types.h"
#include "tx_credential_types.h"
#include "tx_certificate_types.h"

// =============================================================================
// Optional Item Flags
// =============================================================================

/**
 * Inclusion flag values for optional transaction fields.
 *
 * These values are used on the wire to indicate whether an optional
 * transaction field is present (FLAG_INCLUDED_YES) or omitted
 * (FLAG_INCLUDED_NO).
 */
typedef enum {
    FLAG_INCLUDED_NO = 1,   // Field is not included
    FLAG_INCLUDED_YES = 2,  // Field is included
} flag_included_e;

/**
 * Read and interpret a flag byte as a boolean inclusion indicator.
 *
 * @param[in] buf Buffer to read from
 * @param[out] result true if the field is included, false otherwise
 * @return true if a valid flag was read, false otherwise
 */
bool buffer_read_flag_included(buffer_t *buf, bool *result);

/**
 * Read bytes from buffer and copy to destination.
 *
 * @param[in,out] buffer Read buffer
 * @param[out] destBuffer Destination buffer
 * @param[in] n Number of bytes to read
 * @return true on success, false on failure
 */
bool buffer_read_bytes(buffer_t *buffer, uint8_t *destBuffer, size_t n);

/**
 * Read an int64 value with specified endianness.
 *
 * @param[in,out] buffer Read buffer
 * @param[out] value Parsed int64 value
 * @param[in] endianness Endianness for reading
 * @return true on success, false on failure
 */
bool buffer_read_int64(buffer_t *buffer, int64_t *value, endianness_t endianness);

/**
 * Read an optional anchor (URL + hash) from the buffer.
 *
 * The format is:
 *   - 1 byte: inclusion flag (FLAG_INCLUDED_YES/NO)
 *   - [if included] 2 bytes: URL length (big-endian)
 *   - [if included] URL bytes
 *   - [if included] 32-byte anchor hash
 *
 * @param[in,out] buf   Buffer to read from
 * @param[out]    anchor Destination anchor structure
 * @return true on success, false on failure
 */
bool buffer_read_anchor(buffer_t *buf, anchor_t *anchor);

/**
 * Read a DRep (Delegated Representative) descriptor from the buffer.
 *
 * Wire format:
 *   - 1 byte: DRep type (KEY_HASH, SCRIPT_HASH, ABSTAIN, NO_CONFIDENCE, KEY_PATH)
 *   - Optional payload: key hash/script hash/extended key path
 *
 * @param[in,out] buf Buffer to read from
 * @param[out] drep Parsed DRep structure
 * @return true on success, false otherwise
 */
bool buffer_read_drep(buffer_t *buf, ext_drep_t *drep);

// =============================================================================
// Credential Parsing
// =============================================================================

/**
 * Read an extended credential (key hash, script hash, or key path).
 *
 * Extended credentials support both CBOR credential types (key hash, script hash)
 * and an additional key path type for device-owned keys.
 *
 * Wire format:
 *   - 1 byte: credential type (0=KEY_HASH, 1=SCRIPT_HASH, 2=KEY_PATH)
 *   - Variable: credential data based on type
 *
 * @param[in] buf Buffer to read from
 * @param[out] credential Parsed credential structure
 * @return true on success, false on failure
 */
bool buffer_read_credential(buffer_t *buf, ext_credential_t *credential);

/**
 * Read a pool reward account (key hash or key path).
 *
 * Wire format:
 *   - 1 byte: reference type (0=KEY_HASH, 2=KEY_PATH)
 *   - Variable: REWARD_ACCOUNT_LENGTH-byte hash, or a BIP44 path
 *
 * @param[in] buf Buffer to read from
 * @param[out] reward_account Parsed reward account structure
 * @return true on success, false on failure
 */
bool buffer_read_pool_reward_account(buffer_t *buf, pool_reward_account_t *reward_account);
