/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "dispatcher.h"

/**
 * Send APDU status word and reset the application context.
 *
 * @param swo Status word to return.
 */
void send_swo_and_reset(uint16_t swo);

/**
 * Centrally reset application state.
 *
 * This function ensures that all resources are released and the application
 * returns to a clean idle state. It:
 * - Cleans up UI allocations and review state
 * - Resets the transient allocator
 * - Securely zeroes out the global context
 * - Resets request type to idle
 */
void reset_app_context(void);

/**
 * Mark start of APDU handling in dispatcher.
 */
void apdu_response_begin(command_e instruction);

/**
 * Mark that APDU response will be sent asynchronously from NBGL callback.
 */
void apdu_response_deferred(void);

/**
 * Assert dispatcher returned from a handler only after either sending a response
 * or explicitly deferring it to UX callback.
 */
void apdu_response_assert_sent_or_deferred(void);

/**
 * Guarded response wrappers enforcing exactly one APDU response per command.
 */
void apdu_response_send_sw(uint16_t swo);
void apdu_response_send_data(const uint8_t *buffer, size_t bufferLength, uint16_t swo);

/**
 * Query whether the current APDU already sent a response.
 */
bool apdu_response_was_sent(void);

/**
 * Reset APDU response tracking state.
 * For use by fuzzing harnesses to clean up after a siglongjmp from app_exit()
 * that bypassed the normal apdu_response_assert_sent_or_deferred() call.
 * Not for use in production app code.
 */
void apdu_response_state_force_reset(void);
