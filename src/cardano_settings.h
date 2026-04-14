/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "globals.h"
#include "assert.h"

enum { STORAGE_INITIALIZED = 0x01 };

enum { SETTINGS_NO = 0, SETTINGS_YES = 1 };

static inline uint8_t flip_bool_setting(uint8_t value) {
    switch (value) {
        case SETTINGS_NO:
            return SETTINGS_YES;
        case SETTINGS_YES:
            return SETTINGS_NO;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            return 0;  // Unreachable, but satisfies compiler
                       // LCOV_EXCL_STOP
    }
}

static inline bool setting_is_enabled(uint8_t value) {
    switch (value) {
        case SETTINGS_NO:
            return false;
        case SETTINGS_YES:
            return true;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            return false;  // Unreachable, but satisfies compiler
                           // LCOV_EXCL_STOP
    }
}

static inline bool is_expert_mode() {
    return setting_is_enabled(N_storage.expert_mode_enabled);
}

static inline bool is_silent_pubkey_export_allowed() {
    return setting_is_enabled(N_storage.silent_pubkey_export_enabled);
}

static inline bool is_blind_signing_enabled() {
    return setting_is_enabled(N_storage.blind_signing_enabled);
}
