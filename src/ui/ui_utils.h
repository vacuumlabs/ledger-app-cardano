/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <string.h>
#include "nbgl_use_case.h"
#include "mem.h"
#include "assert.h"
#include "ui_constants.h"
#include "bech32.h"

/**
 * UI formatting status - tracks result of UI string generation
 *
 * UI_STATUS_UNINITIALIZED (0): Default state after bzero - invalid to use, must call
 * ui_reset_error_status() UI_STATUS_SUCCESS (1):        All UI formatting succeeded
 * UI_STATUS_OUT_OF_MEMORY (2):  Memory allocation failure during UI formatting (fatal error)
 * UI_STATUS_CHUNK_FULL (3):     Pairs array is full — expected chunk boundary in streaming mode,
 *                               NOT a fatal error; must be reset to SUCCESS before next chunk
 *
 * CHUNK_FULL and OUT_OF_MEMORY are mutually exclusive: once one is set, the other must not be set.
 * Note: Once set to error/chunk-full state, cannot be changed back to success via
 * ui_set_error_status; streaming code must call ui_reset_error_status() before rendering the next
 * chunk.
 */
typedef enum {
    UI_STATUS_UNINITIALIZED = 0,
    UI_STATUS_SUCCESS = 1,
    UI_STATUS_OUT_OF_MEMORY = 2,
    UI_STATUS_CHUNK_FULL = 3,
} ui_status_t;

extern ui_status_t g_ui_error_status;

extern nbgl_contentTagValue_t *g_pairs;
extern nbgl_contentTagValueList_t *g_pairsList;

typedef struct {
    uint16_t render_from_pair_index;  /// first UI pair index to render in this session
    uint16_t next_pair_index;         /// increments for every UI_ADD_* attempt
} ui_render_session_t;

/**
 * Maximum number of UI pairs allocated for one review slab on the current screen class.
 *
 * Wallet devices can use the full 255-pair slab. Nano devices use a smaller slab to fit the
 * tighter temporary-memory budget and rely on streaming for larger reviews.
 */
#ifdef SCREEN_SIZE_WALLET
#define MAX_UI_PAIRS 255
#else
#define MAX_UI_PAIRS 127
#endif

STATIC_ASSERT(MAX_UI_PAIRS <= UINT8_MAX, "MAX_UI_PAIRS must fit in uint8_t");

/**
 * Initialize UI error status to SUCCESS before starting UI formatting
 * Must be called once at the beginning of UI string generation
 */
void ui_reset_error_status(void);

/**
 * Get final UI error status
 * Asserts if status was never initialized (still UNINITIALIZED)
 * @return UI_STATUS_SUCCESS or UI_STATUS_OUT_OF_MEMORY
 */
ui_status_t ui_get_error_status(void);

/**
 * Set UI error status
 * Cannot change from error state back to success (asserts if attempted)
 * @param status New status to set (must not be UNINITIALIZED)
 */
void ui_set_error_status(ui_status_t status);

bool ui_pairs_init(uint16_t nbPairs);
void ui_free_pairs(void);
void ui_all_cleanup(void);
uint16_t ui_pairs_get_count(void);

void ui_render_session_begin(ui_render_session_t *session, uint16_t render_from_pair_index);
void ui_render_session_end(void);

/**
 * Scoped render helpers — bundle the 3-step open/close protocol:
 *   begin: ui_reset_error_status() + ui_render_session_begin()
 *   end:   ui_get_error_status()   + ui_render_session_end()
 *
 * Prevents mismatched reset/begin and get-status/end ordering.
 */
static inline void ui_render_scope_begin(ui_render_session_t *session) {
    ui_reset_error_status();
    explicit_bzero(session, sizeof(*session));
    ui_render_session_begin(session, 0);
}

static inline ui_status_t ui_render_scope_end(void) {
    ui_status_t status = ui_get_error_status();
    ui_render_session_end();
    return status;
}

/**
 * Check whether the current pair should be skipped.
 * Always increments the next UI pair index. Returns true if the pair
 * should be skipped (before window or OOM already set).
 */
bool ui_render_should_skip(void);
void ui_check_expected_pair_delta(uint16_t pairs_before, uint16_t expected);

// UI pair count verification macros for transaction formatting.
// CHECK_COUNT is a no-op when OOM is set or when rendering a non-first chunk
// (pairs before the window are skipped, so counts won't match).
#define START_COUNT()         uint16_t _pairs_before = ui_pairs_get_count()
#define CHECK_COUNT(expected) ui_check_expected_pair_delta(_pairs_before, (uint16_t) (expected))

#ifdef __GNUC__
#define UI_STATIC_LABEL(label) ((void) sizeof(char[__builtin_constant_p(label) ? 1 : -1]), (label))
#else
#define UI_STATIC_LABEL(label) (label)
#endif

#ifdef SCREEN_SIZE_WALLET
#define UI_LABEL_BY_SCREEN(wallet_label, compact_label) UI_STATIC_LABEL(wallet_label)
#else
#define UI_LABEL_BY_SCREEN(wallet_label, compact_label) UI_STATIC_LABEL(compact_label)
#endif

/**
 * Add a label-value pair to the UI pairs list with optional shrinking
 *
 * @param label static label string (should be constant, compile-time checked by UI_STATIC_LABEL
 * macro)
 * @param tmp_buf temporary buffer containing the value (will be freed after use)
 * @param shrink if true, allocates exact size for the value; if false, uses buffer as-is
 * @return true on success, false on failure
 */
/**
 * Force the next UI pair to start a new page.
 * Must be followed by at least one UI_ADD_* call before ui_free_pairs() is called.
 */
void ui_pairs_force_new_page(void);

bool ui_pairs_add_static_label_impl(const char *label, char *tmp_buf, bool shrink);

/**
 * Add a label-value pair to the UI pairs list (legacy wrapper, always shrinks)
 * Use ui_pairs_add_static_label_impl with shrink=true for equivalent behavior
 *
 * @param label static label string (should be constant, compile-time checked by UI_STATIC_LABEL
 * macro)
 * @param tmp_buf temporary buffer containing the value (will be freed after use)
 * @return true on success, false on failure
 */
bool ui_pairs_add_static_label(const char *label, char *tmp_buf);

/**
 * Format a single-parameter value and add to UI pairs.
 *
 * Allocates buffer, calls formatting function with standard 3-parameter signature
 * (value, output_buffer, buffer_size), verifies success and no truncation,
 * and adds result to UI pairs.
 *
 * CONTRACT: format_fn MUST NOT allocate from the heap (APP_MEM_CALLOC /
 * allocate_zeroed / tx_alloc_temp_buffer_or_fail).  These macros allocate the
 * output string buffer from the heap immediately before calling format_fn; a
 * second heap allocation inside format_fn may fail with a hard ASSERT rather
 * than the graceful UI_STATUS_OUT_OF_MEMORY path, breaking the streaming
 * OOM-recovery mechanism.  Use stack-local temporaries inside formatters
 * instead, and annotate with __noinline_due_to_stack__ if the local buffer is
 * large (>= ~64 bytes).
 *
 * Formatting function signature: bool format_fn(value_type value, char *out, size_t outSize)
 *
 * @param label      Static label for UI pair (use UI_STATIC_LABEL macro)
 * @param max_len    Maximum output string length (without null terminator)
 * @param format_fn  Formatting function with signature: bool fn(value, char*, size_t)
 * @param value      Value to format (passed as first argument to format_fn)
 */
#define UI_ADD_FORMAT1(label, max_len, format_fn, value)                       \
    do {                                                                       \
        if (ui_render_should_skip()) break;                                    \
        char *_buf = NULL;                                                     \
        const size_t _buf_size = (size_t) (max_len) + UI_BUFFER_SAFETY_MARGIN; \
        if (!allocate_zeroed((void **) &_buf, _buf_size) || _buf == NULL) {    \
            ui_set_error_status(UI_STATUS_OUT_OF_MEMORY);                      \
            break;                                                             \
        }                                                                      \
        bool _ok = format_fn((value), _buf, _buf_size);                        \
        LEDGER_ASSERT(_ok, "Format fn failed");                                \
        LEDGER_ASSERT(strlen(_buf) <= (max_len), "Format output too long");    \
        if (!ui_pairs_add_static_label((label), _buf)) {                       \
            break;                                                             \
        }                                                                      \
    } while (0)

/**
 * Format a two-parameter value and add to UI pairs.
 *
 * Allocates buffer, calls formatting function with signature
 * (param1, param2, output_buffer, buffer_size), verifies success and no truncation,
 * and adds result to UI pairs.
 *
 * CONTRACT: same as UI_ADD_FORMAT1 — format_fn must not heap-allocate.
 *
 * Formatting function signature: bool format_fn(param1_type p1, param2_type p2, char *out, size_t
 * outSize)
 *
 * @param label      Static label for UI pair (use UI_STATIC_LABEL macro)
 * @param max_len    Maximum output string length (without null terminator)
 * @param format_fn  Formatting function with signature: bool fn(p1, p2, char*, size_t)
 * @param param1     First parameter to pass to format_fn
 * @param param2     Second parameter to pass to format_fn
 */
#define UI_ADD_FORMAT2(label, max_len, format_fn, param1, param2)              \
    do {                                                                       \
        if (ui_render_should_skip()) break;                                    \
        char *_buf = NULL;                                                     \
        const size_t _buf_size = (size_t) (max_len) + UI_BUFFER_SAFETY_MARGIN; \
        if (!allocate_zeroed((void **) &_buf, _buf_size) || _buf == NULL) {    \
            ui_set_error_status(UI_STATUS_OUT_OF_MEMORY);                      \
            break;                                                             \
        }                                                                      \
        bool _ok = format_fn((param1), (param2), _buf, _buf_size);             \
        LEDGER_ASSERT(_ok, "Format fn failed");                                \
        LEDGER_ASSERT(strlen(_buf) <= (max_len), "Format output too long");    \
        if (!ui_pairs_add_static_label((label), _buf)) {                       \
            break;                                                             \
        }                                                                      \
    } while (0)

/**
 * Format a three-parameter value and add to UI pairs.
 *
 * Allocates buffer, calls formatting function with signature
 * (param1, param2, param3, output_buffer, buffer_size), verifies success and no truncation,
 * and adds result to UI pairs.
 *
 * CONTRACT: same as UI_ADD_FORMAT1 — format_fn must not heap-allocate.
 *
 * Formatting function signature: bool format_fn(p1_type p1, p2_type p2, p3_type p3, char *out,
 * size_t outSize)
 *
 * @param label      Static label for UI pair (use UI_STATIC_LABEL macro)
 * @param max_len    Maximum output string length (without null terminator)
 * @param format_fn  Formatting function with signature: bool fn(p1, p2, p3, char*, size_t)
 * @param param1     First parameter to pass to format_fn
 * @param param2     Second parameter to pass to format_fn
 * @param param3     Third parameter to pass to format_fn
 */
#define UI_ADD_FORMAT3(label, max_len, format_fn, param1, param2, param3)      \
    do {                                                                       \
        if (ui_render_should_skip()) break;                                    \
        char *_buf = NULL;                                                     \
        const size_t _buf_size = (size_t) (max_len) + UI_BUFFER_SAFETY_MARGIN; \
        if (!allocate_zeroed((void **) &_buf, _buf_size) || _buf == NULL) {    \
            ui_set_error_status(UI_STATUS_OUT_OF_MEMORY);                      \
            break;                                                             \
        }                                                                      \
        bool _ok = format_fn((param1), (param2), (param3), _buf, _buf_size);   \
        LEDGER_ASSERT(_ok, "Format fn failed");                                \
        LEDGER_ASSERT(strlen(_buf) <= (max_len), "Format output too long");    \
        if (!ui_pairs_add_static_label((label), _buf)) {                       \
            break;                                                             \
        }                                                                      \
    } while (0)

/**
 * Add a static string value directly to UI pairs without formatting.
 *
 * Directly adds a static constant string to the UI pairs list.
 * This allocates and copies the string so cleanup can always free all values.
 *
 * @param label Static label for UI pair (use UI_STATIC_LABEL macro)
 * @param value NUL-terminated static string value
 */
#define UI_ADD_STATIC(label, value)                                                   \
    do {                                                                              \
        if (ui_render_should_skip()) break;                                           \
        const char *_static_value = (value);                                          \
        size_t _static_value_len = strlen(_static_value);                             \
        char *_static_value_copy = NULL;                                              \
        if (!allocate_zeroed((void **) &_static_value_copy, _static_value_len + 1)) { \
            ui_set_error_status(UI_STATUS_OUT_OF_MEMORY);                             \
            break;                                                                    \
        }                                                                             \
        memcpy(_static_value_copy, _static_value, _static_value_len + 1);             \
        if (!ui_pairs_add_static_label_impl((label), _static_value_copy, false)) {    \
            break;                                                                    \
        }                                                                             \
    } while (0)

/**
 * Format a four-parameter value and add to UI pairs.
 *
 * Allocates buffer, calls formatting function with signature
 * (param1, param2, param3, param4, output_buffer, buffer_size), verifies success and no truncation,
 * and adds result to UI pairs.
 *
 * CONTRACT: same as UI_ADD_FORMAT1 — format_fn must not heap-allocate.
 *
 * Formatting function signature: bool format_fn(p1_type p1, p2_type p2, p3_type p3, p4_type p4,
 * char *out, size_t outSize)
 *
 * @param label      Static label for UI pair (use UI_STATIC_LABEL macro)
 * @param max_len    Maximum output string length (without null terminator)
 * @param format_fn  Formatting function with signature: bool fn(p1, p2, p3, p4, char*, size_t)
 * @param param1     First parameter to pass to format_fn
 * @param param2     Second parameter to pass to format_fn
 * @param param3     Third parameter to pass to format_fn
 * @param param4     Fourth parameter to pass to format_fn
 */
#define UI_ADD_FORMAT4(label, max_len, format_fn, param1, param2, param3, param4)      \
    do {                                                                               \
        if (ui_render_should_skip()) break;                                            \
        char *_buf = NULL;                                                             \
        const size_t _buf_size = (size_t) (max_len) + UI_BUFFER_SAFETY_MARGIN;         \
        if (!allocate_zeroed((void **) &_buf, _buf_size) || _buf == NULL) {            \
            ui_set_error_status(UI_STATUS_OUT_OF_MEMORY);                              \
            break;                                                                     \
        }                                                                              \
        bool _ok = format_fn((param1), (param2), (param3), (param4), _buf, _buf_size); \
        LEDGER_ASSERT(_ok, "Format fn failed");                                        \
        LEDGER_ASSERT(strlen(_buf) <= (max_len), "Format output too long");            \
        if (!ui_pairs_add_static_label((label), _buf)) {                               \
            break;                                                                     \
        }                                                                              \
    } while (0)
