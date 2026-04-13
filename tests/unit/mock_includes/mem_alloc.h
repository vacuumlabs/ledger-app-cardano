/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef void* mem_ctx_t;

mem_ctx_t mem_init(void* buffer, size_t buffer_size);

void* mem_alloc(mem_ctx_t ctx, size_t size);
void* mem_realloc(mem_ctx_t ctx, void* ptr, size_t size);

void mem_free(mem_ctx_t ctx, void* ptr);
typedef bool (*mem_parse_callback_t)(void* data, uint8_t* addr, bool allocated, size_t size);

typedef struct {
    size_t total_size;
    size_t free_size;
    size_t allocated_size;
    uint32_t nb_chunks;
    uint32_t nb_allocated;
} mem_stat_t;

void mem_parse(mem_ctx_t ctx, mem_parse_callback_t callback, void* data);
void mem_stat(mem_ctx_t* ctx, mem_stat_t* stat);

void mem_dump_stats(mem_ctx_t ctx);
