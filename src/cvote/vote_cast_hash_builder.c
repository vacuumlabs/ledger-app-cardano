/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "vote_cast_hash_builder.h"
#include "hash.h"

// Define TRACE_VOTECAST_HASH_BUILDER to enable this module's tracing;
// it is off by default to avoid polluting the trace log.

#ifdef TRACE_VOTECAST_HASH_BUILDER
#define _TRACE(...)        TRACE(__VA_ARGS__)
#define _TRACE_BUFFER(...) TRACE_BUFFER(__VA_ARGS__)
#else
#define _TRACE(...)
#define _TRACE_BUFFER(...) (void) 0
#endif  // TRACE_VOTECAST_HASH_BUILDER

/*
The following macros and functions have dual purpose:
1. syntactic sugar for neat recording of hash computations;
2. tracing of hash computations (allows to reconstruct bytestrings we are hashing via speculos /
usbtool).
*/

#define BUILDER_APPEND_DATA(buffer, bufferSize) \
    blake2b_256_append_buffer_tx_body(&builder->hash, buffer, bufferSize)

static void blake2b_256_append_buffer_tx_body(blake2b_256_context_t *hashCtx,
                                              const uint8_t *buffer,
                                              size_t bufferSize) {
    _TRACE_BUFFER(buffer, bufferSize);
    blake2b_256_append(hashCtx, buffer, bufferSize);
}

/* End of hash computation utilities. */

// ============================== TX HASH BUILDER STATE INITIALIZATION
// ==============================

void vote_cast_hash_builder_init(votecast_hash_builder_t *builder, size_t votecastLength) {
    ASSERT(builder != NULL);
    LEDGER_ASSERT(votecastLength > 0, "Zero votecastLength");

    // Clear the entire structure to prevent stale data
    explicit_bzero(builder, sizeof(votecast_hash_builder_t));

    TRACE("votecastLength = %u", votecastLength);

    builder->remainingBytes = votecastLength;

    blake2b_256_init(&builder->hash);

    builder->state = VOTECAST_HASH_BUILDER_INIT;
}

// ============================== CHUNK ==============================

void vote_cast_hash_builder_chunk(votecast_hash_builder_t *builder,
                                  const uint8_t *chunk,
                                  size_t chunkSize) {
    TRACE("vote_cast_hash_builder_chunk");
    _TRACE("state = %d", builder->state);

    ASSERT(builder->state == VOTECAST_HASH_BUILDER_INIT ||
           builder->state == VOTECAST_HASH_BUILDER_CHUNK);

    ASSERT(chunkSize < BUFFER_SIZE_PARANOIA);
    ASSERT(chunkSize <= builder->remainingBytes);
    ASSERT(chunkSize > 0);
    builder->remainingBytes -= chunkSize;

    BUILDER_APPEND_DATA(chunk, chunkSize);

    builder->state = VOTECAST_HASH_BUILDER_CHUNK;
}

// ========================= FINALIZE ==========================

void vote_cast_hash_builder_finalize(votecast_hash_builder_t *builder,
                                     uint8_t *outBuffer,
                                     size_t outSize) {
    _TRACE("state = %d", builder->state);

    ASSERT(builder->state == VOTECAST_HASH_BUILDER_CHUNK);
    ASSERT(builder->remainingBytes == 0);

    ASSERT(outSize == VOTECAST_HASH_LENGTH);
    {
        blake2b_256_finalize(&builder->hash, outBuffer, outSize);
    }

    builder->state = VOTECAST_HASH_BUILDER_FINISHED;
}
