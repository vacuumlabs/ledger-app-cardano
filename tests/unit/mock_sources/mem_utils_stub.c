/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "app_mem_utils.h"

static int32_t g_allocations_before_failure = -1;

void mem_utils_stub_fail_after_successful_allocations(uint32_t successful_allocations) {
    g_allocations_before_failure = (int32_t) successful_allocations;
}

void mem_utils_stub_reset_failure(void) {
    g_allocations_before_failure = -1;
}

static bool should_fail_allocation(void) {
    if (g_allocations_before_failure < 0) {
        return false;
    }
    if (g_allocations_before_failure == 0) {
        g_allocations_before_failure = -1;
        return true;
    }
    g_allocations_before_failure--;
    return false;
}

// Host stub: ignore heap buffer and delegate to libc.
bool mem_utils_init(void *heap_start, size_t heap_size) {
    (void) heap_start;
    (void) heap_size;
    mem_utils_stub_reset_failure();
    return true;
}

void *mem_utils_realloc(void *ptr, size_t size, const char *file, int line) {
    (void) file;
    (void) line;
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    if (should_fail_allocation()) {
        return NULL;
    }
    return realloc(ptr, size);
}

void mem_utils_free(void *ptr, const char *file, int line) {
    (void) file;
    (void) line;
    free(ptr);
}

void mem_utils_free_and_null(void **buffer, const char *file, int line) {
    (void) file;
    (void) line;
    if (buffer != NULL && *buffer != NULL) {
        free(*buffer);
        *buffer = NULL;
    }
}

bool mem_utils_calloc(void **buffer, size_t size, bool permanent, const char *file, int line) {
    (void) permanent;
    (void) file;
    (void) line;
    if (buffer == NULL) {
        return false;
    }
    if (*buffer != NULL) {
        free(*buffer);
        *buffer = NULL;
    }
    if (size == 0) {
        return true;
    }
    if (should_fail_allocation()) {
        return false;
    }
    *buffer = calloc(1, size);
    return *buffer != NULL;
}
