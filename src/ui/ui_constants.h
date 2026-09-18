/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "bech32.h"

/**
 * Buffer safety margin for string allocations.
 *
 * +1: Space for null terminator (required)
 * +1: Truncation detection byte. The Ledger SDK's snprintf does not return
 *     how many characters would have been written, so we cannot detect
 *     truncation via return value. By allocating one extra byte beyond
 *     MAX_*_LENGTH, we can assert that strlen(result) <= MAX_*_LENGTH
 *     to verify the string was not truncated by snprintf.
 */
#define UI_BUFFER_SAFETY_MARGIN 2

/**
 * UI buffer size constants.
 */
#define MAX_UINT16_STRING_LENGTH            6  // uint16 max (65535) = 5 digits + null
#define MAX_UINT64_STRING_LENGTH            21
#define MAX_VALIDITY_BOUNDARY_STRING_LENGTH 35  // "epoch %u / slot %u" up to 10 digits each
#define MAX_ADA_AMOUNT_STRING_LENGTH        32  // 20 digits + "." + 6 decimals + " ADA"
#define MAX_MINT_SUMMARY_STRING_LENGTH      32  // For mint summary strings (e.g., "2 asset groups")
#define ASSET_FINGERPRINT_BASE32_LENGTH     32  // ceil(8/5 * 20)
#define MAX_TOKEN_FINGERPRINT_STRING_LENGTH                                        \
    (MAX_BECH32_PREFIX_LENGTH + BECH32_SEPARATOR_LENGTH + BECH32_CHECKSUM_LENGTH + \
     ASSET_FINGERPRINT_BASE32_LENGTH + 1)
#define MAX_TOKEN_AMOUNT_STRING_LENGTH 100
#define MAX_TX_HASH_DISPLAY_LENGTH     65  // For transaction hash hex display (32 bytes + null)
#define MAX_INPUT_DISPLAY_STRING_LENGTH \
    (MAX_TX_HASH_DISPLAY_LENGTH + 3 + MAX_UINT64_STRING_LENGTH)  // "<txhash> / <index>"
#define MAX_IPV4_TEXT_LENGTH                 15
#define MAX_IPV6_TEXT_LENGTH                 39
#define MAX_ANCHOR_HASH_STRING_LENGTH        (2 * ANCHOR_HASH_LENGTH + 1)
#define MAX_POOL_METADATA_HASH_STRING_LENGTH (2 * POOL_METADATA_HASH_LENGTH + 1)
#define MAX_REFERENCE_SCRIPT_STRING_LENGTH   40
#define MAX_INLINE_DATUM_STRING_LENGTH       40
#define MAX_RELAY_INDEX_STRING_LENGTH        20  // For relay index "#4294967295"
#define MAX_PROFIT_MARGIN_STRING_LENGTH      50  // For pool margin percentage "100.99 %"
#define MAX_EX_UNITS_STRING_LENGTH           (2 * MAX_UINT64_STRING_LENGTH + 3)  // "<memory> / <steps>"
#define MAX_VOTE_OPTION_LENGTH               16  // For vote option strings ("Abstain", "Yes", "No")
#define MAX_DREP_OPTION_LENGTH               32  // For DRep option strings ("No Confidence")
#define MAX_CERTIFICATE_TYPE_LENGTH          64  // For certificate type strings
#define MAX_GOV_ACTION_TYPE_LENGTH           64  // For gov action type strings
#define MAX_PROTOCOL_VERSION_STRING_LENGTH   24  // For "major.minor" (uint32_t.uint32_t)
#define MAX_DELEGATION_INDEX_STRING_LENGTH   6   // "#65535"
