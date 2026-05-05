/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>
#include "utils.h"

typedef enum {
    WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH = 0,
    WARNING_BIT_NETWORK_UNUSUAL,
    WARNING_BIT_NETWORK_NOT_VERIFIABLE,
    WARNING_BIT_PLUTUS_MISSING_COLLATERAL,
    WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL,
    WARNING_BIT_COLLATERAL_OUTPUT_WARNING,
    WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH,
    WARNING_BIT_OUTPUT_MISSING_DATUM,
    WARNING_BIT_CVOTE_PAYMENT_THIRD_PARTY,
    WARNING_BIT_CVOTE_PAYMENT_NONSTANDARD_OWNED,
    WARNING_BIT_CVOTE_WITNESS_NOT_FULLY_VERIFIABLE,
    WARNING_BIT_POOL_REGISTRATION_NO_OWNERS,
    WARNING_BIT_POOL_REGISTRATION_NO_RELAYS,
    WARNING_BIT_POOL_REGISTRATION_EMPTY_METADATA_URL,
    WARNING_BIT_EMPTY_ANCHOR_URL,
    WARNING_BIT_HIGH_FEE,
    WARNING_BIT_UNRESTRICTED_SIGNING,
    WARNING_BIT_COUNT,
} warning_bit_e;

typedef uint64_t warning_bits_t;

#ifdef DEBUG
static inline void _trace_warning_bit(warning_bit_e bit) {
    TRACE("Warning bit set: %u", (unsigned) bit);
}
#else
#define _trace_warning_bit(bit) \
    do {                        \
        (void) (bit);           \
    } while (0)
#endif

static inline void warning_bits_set(warning_bits_t* warnings, warning_bit_e bit)
    __attribute__((nonnull(1)));
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull-compare"
#endif
static inline void warning_bits_set(warning_bits_t* warnings, warning_bit_e bit) {
    ASSERT(warnings != NULL);
    *warnings |= (warning_bits_t) 1 << bit;
    _trace_warning_bit(bit);
}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

static inline bool warning_bits_has(warning_bits_t warnings, warning_bit_e bit) {
    return ((warnings >> bit) & 1) != 0;
}

static inline bool warning_bits_is_empty(const warning_bits_t* warnings) {
    ASSERT(warnings != NULL);
    return *warnings == 0;
}

// Mask for CVote registration (AUX_DATA) warnings.
#define CVOTE_AUX_DATA_WARNING_BITS_MASK                               \
    (((warning_bits_t) 1 << WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH) | \
     ((warning_bits_t) 1 << WARNING_BIT_CVOTE_PAYMENT_THIRD_PARTY) |   \
     ((warning_bits_t) 1 << WARNING_BIT_CVOTE_PAYMENT_NONSTANDARD_OWNED))

// CVote-only warnings that must never appear in regular transaction warning_bits.
#define CVOTE_TX_FORBIDDEN_WARNING_BITS_MASK                               \
    (((warning_bits_t) 1 << WARNING_BIT_CVOTE_PAYMENT_THIRD_PARTY) |       \
     ((warning_bits_t) 1 << WARNING_BIT_CVOTE_PAYMENT_NONSTANDARD_OWNED) | \
     ((warning_bits_t) 1 << WARNING_BIT_CVOTE_WITNESS_NOT_FULLY_VERIFIABLE))

static inline bool warning_bits_has_any_cvote_tx_forbidden(warning_bits_t warnings) {
    return (warnings & CVOTE_TX_FORBIDDEN_WARNING_BITS_MASK) != 0;
}
