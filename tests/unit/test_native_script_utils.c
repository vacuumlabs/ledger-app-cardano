/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "test_native_script_utils.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>

#include "globals.h"
#include "securityPolicy/securityPolicy.h"
#include "apdu/dispatcher.h"
#include "globals.h"
#include <assert.h>

#include <cmocka.h>
#include "handler/derive_address.h"
#include "app_context.h"
#include "mock_crypto/crypto_mock_data.h"
#include "blake2b.h"
#include "mem.h"
#include "cardano_constants.h"
#include "handler/derive_native_script_hash.h"

// ----------------------------------------------------------------------
// IO Mock Implementation
// ----------------------------------------------------------------------

static uint16_t g_last_swo = 0;

#define MAX_RESPONSE_BUFFER_SIZE 28
static uint8_t g_response_buffer[MAX_RESPONSE_BUFFER_SIZE];
static size_t g_response_buffer_length = 0;

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    LEDGER_ASSERT(bufferLength <= MAX_RESPONSE_BUFFER_SIZE, "Response buffer overflow");

    // Save response data to global buffer
    if (buffer != NULL && bufferLength > 0) {
        memcpy(g_response_buffer, buffer, bufferLength);
        g_response_buffer_length = bufferLength;
    } else {
        g_response_buffer_length = 0;
    }

    g_last_swo = swo;
    return 0;
}

int io_send_sw(uint16_t swo) {
    g_last_swo = swo;
    return 0;
}

// ----------------------------------------------------------------------
// Test Utilities
// ----------------------------------------------------------------------

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

bool test_mem_init(void) {
    return mem_utils_init(test_heap, sizeof(test_heap));
}

void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
}

void reset_response_buffer(void) {
    memset(g_response_buffer, 0, sizeof(g_response_buffer));
    g_response_buffer_length = 0;
    g_last_swo = 0;
}

uint16_t get_last_swo(void) {
    return g_last_swo;
}

const uint8_t *get_response_buffer(void) {
    return g_response_buffer;
}

size_t get_response_buffer_length(void) {
    return g_response_buffer_length;
}

void run_derive_native_script_apdu(buffer_t *buffer, uint8_t p1) {
    apdu_response_begin(INS_DERIVE_NATIVE_SCRIPT_HASH);
    handler_derive_native_script_hash(buffer, p1);
    apdu_response_finalize_after_handler();
}

void run_derive_native_script_init_apdu(void) {
    buffer_t empty_buffer = {
        .ptr = NULL,
        .size = 0,
        .offset = 0,
    };
    run_derive_native_script_apdu(&empty_buffer, P1_NATIVE_SCRIPT_INIT);
}

// ----------------------------------------------------------------------
// APDU Buffer Construction Helpers
// ----------------------------------------------------------------------

void write_u32_be(uint8_t *buffer, uint32_t value) {
    buffer[0] = (value >> 24) & 0xFF;
    buffer[1] = (value >> 16) & 0xFF;
    buffer[2] = (value >> 8) & 0xFF;
    buffer[3] = value & 0xFF;
}

void build_complex_script_start_buffer(uint8_t *buffer,
                                       size_t *buffer_length,
                                       uint8_t script_type,
                                       uint32_t children_count,
                                       uint32_t required_count  // Only used for N_OF_K
) {
    LEDGER_ASSERT(script_type == NATIVE_SCRIPT_ALL || script_type == NATIVE_SCRIPT_ANY ||
                      script_type == NATIVE_SCRIPT_N_OF_K,
                  "Invalid complex script type");

    size_t offset = 0;

    // Byte 0: script type
    buffer[offset++] = script_type;

    // Bytes 1-4: children count (big-endian)
    write_u32_be(&buffer[offset], children_count);
    offset += 4;

    // Bytes 5-8: required count (only for N_OF_K)
    if (script_type == NATIVE_SCRIPT_N_OF_K) {
        write_u32_be(&buffer[offset], required_count);
        offset += 4;
    }

    *buffer_length = offset;
}
