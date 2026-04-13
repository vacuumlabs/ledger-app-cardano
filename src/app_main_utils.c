/* SPDX-FileCopyrightText: 2016-2025 Ledger */
/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>

#include "app_main.h"
#include "app_context.h"
#include "cardano_swo.h"
#include "utils.h"

void app_main_handle_unexpected_exception(uint16_t exception) {
    TRACE("Unhandled exception in app_main loop: 0x%04X", exception);
    uint16_t swo = ((exception & 0xF000) == 0x6000) ? (uint16_t) exception : SWO_UNKNOWN;
    if (apdu_response_was_sent()) {
        // A response was already delivered to the host. Swallow the follow-up exception, reset
        // local APDU state, and recover the app context without attempting a second response.
        TRACE("APDU response already sent; resetting state after exception 0x%04X", exception);
        apdu_response_state_force_reset();
        reset_app_context();
    } else {
        send_swo_and_reset(swo);
    }
}
