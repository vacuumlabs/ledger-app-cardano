/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "cbor_canonical.h"
#include "assert.h"
#include "utils.h"

#include <string.h>

bool cbor_mapKeyFulfillsCanonicalOrdering(const uint8_t *previous_key,
                                          size_t previous_key_length,
                                          const uint8_t *next_key,
                                          size_t next_key_length) {
    ASSERT(previous_key_length < BUFFER_SIZE_PARANOIA);
    ASSERT(next_key_length < BUFFER_SIZE_PARANOIA);

    if (previous_key_length != next_key_length) {
        return previous_key_length < next_key_length;
    }
    for (size_t i = 0; i < previous_key_length; ++i) {
        if (previous_key[i] != next_key[i]) {
            return previous_key[i] < next_key[i];
        }
    }
    // key duplication is an error
    return false;
}

bool cbor_canonical_tracker_check_and_advance(cbor_canonical_tracker_t *tracker,
                                              const uint8_t *next_key,
                                              size_t next_key_length) {
    ASSERT(tracker != NULL);
    ASSERT(next_key != NULL);
    ASSERT(next_key_length <= CBOR_CANONICAL_MAX_KEY_SIZE);
    if (tracker->has_previous && !cbor_mapKeyFulfillsCanonicalOrdering(tracker->previous_key,
                                                                       tracker->previous_key_length,
                                                                       next_key,
                                                                       next_key_length)) {
        return false;
    }
    LEDGER_ASSERT(next_key_length >= tracker->previous_key_length,
                  "accepted key is shorter than previous — canonical ordering invariant violated");
    memcpy(tracker->previous_key, next_key, next_key_length);
    tracker->previous_key_length = next_key_length;
    tracker->has_previous = true;
    return true;
}
