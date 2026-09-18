/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "nbgl_use_case.h"
#include "securityWarnings.h"

void nbgl_mock_reset(void);
void nbgl_mock_set_final_decisions(const bool *decisions, size_t decision_count);
void nbgl_mock_assert_all_final_decisions_consumed(void);
void nbgl_mock_set_streaming_start_auto_complete(bool enabled, bool confirm);
void nbgl_mock_set_streaming_continue_reject_at_call(size_t call_index);
const char *nbgl_mock_last_choice_message(void);
const char *nbgl_mock_last_status_message(void);
bool nbgl_mock_last_status_success(void);

// Warning bits as they stood when the tx review was built. Captured because the review
// callback completes the flow and resets the app context, zeroing the live field.
warning_bits_t nbgl_mock_captured_warning_bits(void);
