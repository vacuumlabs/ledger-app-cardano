/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "apdu/dispatcher.h"
#include "app_context.h"
#include "cardano_swo.h"

// CMocka group teardown helper:
// fail if a deferred APDU response from the test was not eventually completed.
static inline int assert_no_pending_apdu_response(void **state) {
    (void) state;
    apdu_response_begin(INS_GET_VERSION);
    apdu_response_send_sw(SWO_SUCCESS);
    apdu_response_finalize_after_handler();
    return 0;
}
