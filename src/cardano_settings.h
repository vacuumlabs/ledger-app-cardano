/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "globals.h"
#include "assert.h"
#include "ledger_assert.h"

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

static inline uint8_t expert_mode_setting_value() {
    uint8_t value = N_storage.expert_mode_enabled;
    ASSERT(value == SETTINGS_NO || value == SETTINGS_YES);
    return value;
}

static inline uint8_t silent_pubkey_export_setting_value() {
    uint8_t value = N_storage.silent_pubkey_export_enabled;
    ASSERT(value == SETTINGS_NO || value == SETTINGS_YES);
    return value;
}

static inline uint8_t blind_signing_setting_value() {
    uint8_t value = N_storage.blind_signing_enabled;
    ASSERT(value == SETTINGS_NO || value == SETTINGS_YES);
    return value;
}

static inline bool is_expert_mode() {
    return setting_is_enabled(expert_mode_setting_value());
}

static inline bool is_silent_pubkey_export_allowed() {
    return setting_is_enabled(silent_pubkey_export_setting_value());
}

static inline bool is_blind_signing_enabled() {
    return setting_is_enabled(blind_signing_setting_value());
}
