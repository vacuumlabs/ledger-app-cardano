/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

// Mock io.h for unit tests
// Provides stubs for IO functions not needed in unit tests

#include <stdint.h>
#include <stddef.h>

// Mock IO send function declarations
int io_recv_command(void);
void io_init(void);
int io_send_sw(uint16_t swo);

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo);
