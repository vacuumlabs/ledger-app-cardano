/* SPDX-FileCopyrightText: 2016-2025 Ledger */
/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>

void app_main(void);

/**
 * Process a single APDU command through the top-level app_main TRY/CATCH logic.
 * Exposed for host-side unit tests that need to exercise top-level exception handling
 * without entering the infinite app_main loop.
 */
void app_main_process_one_apdu(void);

void app_main_handle_unexpected_exception(uint16_t exception);
