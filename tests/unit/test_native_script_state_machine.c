/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "globals.h"
#include "handler/derive_native_script_hash.h"
#include "cardano_swo.h"
#include "test_native_script_utils.h"
#include "securityPolicy.h"
#include "apdu/dispatcher.h"
#include "app_context.h"
#include "apdu_finalization_check.h"

static void reset_test_context(void) {
    reset_context();
    reset_response_buffer();
    assert_true(test_mem_init());
}

// Mock UI functions
void ui_start_native_script_streaming(void) {
    apdu_response_send_data(NULL, 0, SWO_SUCCESS);
}

// Drive native script steps forward without ragger/NBGL interaction.
// For final hash display we intentionally do nothing to model "waiting for final confirmation".
void ui_display_native_script_hash(void) {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    switch (ctx->ui_scriptType) {
        case UI_SCRIPT_DISPLAY_BECH32:
        case UI_SCRIPT_DISPLAY_POLICY_ID:
            return;
        default:
            apdu_response_send_data(NULL, 0, SWO_SUCCESS);
            return;
    }
}

static void test_finish_must_keep_request_lock_until_user_confirmation(void **state) {
    (void) state;
    reset_test_context();

    buffer_t init_buf = {
        .ptr = NULL,
        .size = 0,
        .offset = 0,
    };
    apdu_response_begin(INS_DERIVE_NATIVE_SCRIPT_HASH);
    handler_derive_native_script_hash(&init_buf, P1_NATIVE_SCRIPT_INIT);
    apdu_response_finalize_after_handler();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    // Add one simple valid script: [type=PUBKEY, cred=KEY_HASH, 28-byte hash]
    uint8_t simple_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    for (size_t i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
        simple_payload[2 + i] = (uint8_t) i;
    }
    buffer_t simple_buf = {
        .ptr = simple_payload,
        .size = sizeof(simple_payload),
        .offset = 0,
    };
    apdu_response_begin(INS_DERIVE_NATIVE_SCRIPT_HASH);
    handler_derive_native_script_hash(&simple_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    apdu_response_finalize_after_handler();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_DERIVE_NATIVE_SCRIPT_HASH);

    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32};
    buffer_t finish_buf = {
        .ptr = finish_payload,
        .size = sizeof(finish_payload),
        .offset = 0,
    };
    apdu_response_begin(INS_DERIVE_NATIVE_SCRIPT_HASH);
    handler_derive_native_script_hash(&finish_buf, P1_NATIVE_SCRIPT_FINISH);
    apdu_response_finalize_after_handler();

    // Expected invariant: request lock remains active while waiting for final confirmation.
    assert_int_equal(G_context.req_type, REQUEST_DERIVE_NATIVE_SCRIPT_HASH);

    // Close deferred APDU response to keep the next test isolated.
    send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
}

static void test_simple_parse_failure_must_not_reach_postparse_state_mutation(void **state) {
    (void) state;
    reset_test_context();

    buffer_t init_buf = {
        .ptr = NULL,
        .size = 0,
        .offset = 0,
    };
    apdu_response_begin(INS_DERIVE_NATIVE_SCRIPT_HASH);
    handler_derive_native_script_hash(&init_buf, P1_NATIVE_SCRIPT_INIT);
    apdu_response_finalize_after_handler();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    // Invalid device-owned key path fixture from reject vectors.
    uint8_t invalid_payload[27] = {0x00, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    buffer_t invalid_buf = {
        .ptr = invalid_payload,
        .size = sizeof(invalid_payload),
        .offset = 0,
    };

    // This should produce a rejection SW and clean reset only.
    apdu_response_begin(INS_DERIVE_NATIVE_SCRIPT_HASH);
    handler_derive_native_script_hash(&invalid_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    apdu_response_finalize_after_handler();
    assert_int_equal(get_last_swo(), SWO_NATIVE_SCRIPT_PARSING_FAIL_PUBKEY_CREDENTIAL);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_n_of_k_required_greater_than_remaining(void **state) {
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t complex_payload[9] = {0};
    complex_payload[0] = NATIVE_SCRIPT_N_OF_K;
    write_u32_be(&complex_payload[1], 3);
    write_u32_be(&complex_payload[5], 5);

    buffer_t buf = {
        .ptr = complex_payload,
        .size = sizeof(complex_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);

    assert_int_equal(get_last_swo(), SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_COUNT);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_invalid_display_format(void **state) {
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t simple_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    for (size_t i = 0; i < ADDRESS_KEY_HASH_LENGTH; i++) {
        simple_payload[2 + i] = (uint8_t) i;
    }
    buffer_t simple_buf = {
        .ptr = simple_payload,
        .size = sizeof(simple_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&simple_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t finish_payload[1] = {0xFF};
    buffer_t finish_buf = {
        .ptr = finish_payload,
        .size = sizeof(finish_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);

    assert_int_equal(get_last_swo(), SWO_NATIVE_SCRIPT_PARSING_FAIL_DISPLAY_FORMAT);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_max_script_depth_exceeded(void **state) {
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    for (int i = 0; i < MAX_SCRIPT_DEPTH; i++) {
        uint8_t complex_payload[5] = {0};
        complex_payload[0] = NATIVE_SCRIPT_ALL;
        write_u32_be(&complex_payload[1], 1);

        buffer_t buf = {
            .ptr = complex_payload,
            .size = sizeof(complex_payload),
            .offset = 0,
        };
        run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);

        if (i < MAX_SCRIPT_DEPTH - 1) {
            assert_int_equal(get_last_swo(), SWO_SUCCESS);
        } else {
            assert_int_equal(get_last_swo(), SWO_NATIVE_SCRIPT_PARSING_FAIL_DEPTH_UNSUPPORTED);
            assert_int_equal(G_context.req_type, REQUEST_NONE);
            return;
        }
    }

    fail_msg("Expected depth limit to be enforced");
}

static void test_finish_with_remaining_scripts(void **state) {
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t complex_payload[5] = {0};
    complex_payload[0] = NATIVE_SCRIPT_ALL;
    write_u32_be(&complex_payload[1], 2);

    buffer_t buf = {
        .ptr = complex_payload,
        .size = sizeof(complex_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t simple_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    buffer_t simple_buf = {
        .ptr = simple_payload,
        .size = sizeof(simple_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&simple_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t finish_payload[1] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32};
    buffer_t finish_buf = {
        .ptr = finish_payload,
        .size = sizeof(finish_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);

    assert_int_equal(get_last_swo(), SWO_NATIVE_SCRIPT_PARSING_FAIL_NESTING);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_pubkey_device_owned_invalid_classified_path_denied(void **state) {
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t simple_payload[1 + 1 + 1 + 5 * 4] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_PATH;
    simple_payload[2] = 5;
    write_u32_be(&simple_payload[3], bip44_harden(PURPOSE_SHELLEY));
    write_u32_be(&simple_payload[7], bip44_harden(ADA_COIN_TYPE));
    write_u32_be(&simple_payload[11], 0);
    write_u32_be(&simple_payload[15], 0);
    write_u32_be(&simple_payload[19], 0);

    buffer_t simple_buf = {
        .ptr = simple_payload,
        .size = sizeof(simple_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&simple_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);

    assert_int_equal(get_last_swo(), SWO_SECURITY_CONDITION_NOT_SATISFIED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// --- Init APDU error paths ---

static void test_init_apdu_with_extra_bytes(void **state) {
    (void) state;
    reset_test_context();
    reset_response_buffer();

    uint8_t payload[1] = {0xFF};
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    apdu_response_begin(INS_DERIVE_NATIVE_SCRIPT_HASH);
    handler_derive_native_script_hash(&buf, P1_NATIVE_SCRIPT_INIT);
    apdu_response_finalize_after_handler();

    assert_int_equal(get_last_swo(), SWO_WRONG_DATA_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_non_init_apdu_before_init_rejected(void **state) {
    (void) state;
    reset_test_context();
    reset_response_buffer();

    // Send complex-start without init: req_type is REQUEST_NONE, not
    // REQUEST_DERIVE_NATIVE_SCRIPT_HASH
    uint8_t payload[5] = {0};
    payload[0] = NATIVE_SCRIPT_ALL;
    write_u32_be(&payload[1], 1);
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    apdu_response_begin(INS_DERIVE_NATIVE_SCRIPT_HASH);
    handler_derive_native_script_hash(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);
    apdu_response_finalize_after_handler();

    assert_int_equal(get_last_swo(), SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_double_init_rejected(void **state) {
    // Init while a request is already active
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);
    assert_int_equal(G_context.req_type, REQUEST_DERIVE_NATIVE_SCRIPT_HASH);

    buffer_t init_buf = {.ptr = NULL, .size = 0, .offset = 0};
    apdu_response_begin(INS_DERIVE_NATIVE_SCRIPT_HASH);
    handler_derive_native_script_hash(&init_buf, P1_NATIVE_SCRIPT_INIT);
    apdu_response_finalize_after_handler();

    assert_int_equal(get_last_swo(), SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// --- Complex script start error paths ---

static void test_complex_start_empty_apdu(void **state) {
    // Zero-byte payload: can't read script type byte
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    buffer_t buf = {.ptr = NULL, .size = 0, .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);

    assert_int_equal(get_last_swo(), SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_TYPE);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_complex_start_truncated_remaining_scripts(void **state) {
    // 1-byte payload (script type only): can't read remainingScripts u32
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[1] = {NATIVE_SCRIPT_ALL};
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);

    assert_int_equal(get_last_swo(), SWO_WRONG_DATA_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_complex_start_all_extra_bytes(void **state) {
    // ALL with trailing padding byte
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[6] = {0};
    payload[0] = NATIVE_SCRIPT_ALL;
    write_u32_be(&payload[1], 1);
    payload[5] = 0xFF;  // extra byte
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);

    assert_int_equal(get_last_swo(), SWO_WRONG_DATA_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_complex_start_any_extra_bytes(void **state) {
    // ANY with trailing padding byte
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[6] = {0};
    payload[0] = NATIVE_SCRIPT_ANY;
    write_u32_be(&payload[1], 1);
    payload[5] = 0xFF;  // extra byte
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);

    assert_int_equal(get_last_swo(), SWO_WRONG_DATA_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_complex_start_unknown_script_type(void **state) {
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[5] = {0};
    payload[0] = 0xFF;  // unknown type
    write_u32_be(&payload[1], 1);
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);

    assert_int_equal(get_last_swo(), SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_TYPE);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_complex_start_nof_k_truncated_required(void **state) {
    // N_OF_K with only 5 bytes: script type + remainingScripts, missing requiredScripts u32
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[5] = {0};
    payload[0] = NATIVE_SCRIPT_N_OF_K;
    write_u32_be(&payload[1], 2);
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);

    assert_int_equal(get_last_swo(), SWO_WRONG_DATA_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_complex_start_nof_k_extra_bytes(void **state) {
    // N_OF_K with a trailing byte after requiredScripts
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[10] = {0};
    payload[0] = NATIVE_SCRIPT_N_OF_K;
    write_u32_be(&payload[1], 2);  // remainingScripts
    write_u32_be(&payload[5], 1);  // requiredScripts (valid: 1 <= 2)
    payload[9] = 0xFF;             // extra trailing byte
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_START_COMPLEX);

    assert_int_equal(get_last_swo(), SWO_WRONG_DATA_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_complex_start_nesting_violation(void **state) {
    // Send complex-start when no script is expected at current level (ALL with 0 children)
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    // Start an ALL with 1 child, then try to send a second complex-start at same level
    uint8_t all1_payload[5] = {0};
    all1_payload[0] = NATIVE_SCRIPT_ALL;
    write_u32_be(&all1_payload[1], 1);
    buffer_t all1_buf = {.ptr = all1_payload, .size = sizeof(all1_payload), .offset = 0};
    run_derive_native_script_apdu(&all1_buf, P1_NATIVE_SCRIPT_START_COMPLEX);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    // Add the one required child (simple pubkey hash)
    uint8_t simple_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    buffer_t simple_buf = {
        .ptr = simple_payload,
        .size = sizeof(simple_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&simple_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    // Now the root level is also complete (propagated), so adding another script
    // should trigger nesting failure
    uint8_t all2_payload[5] = {0};
    all2_payload[0] = NATIVE_SCRIPT_ALL;
    write_u32_be(&all2_payload[1], 1);
    buffer_t all2_buf = {.ptr = all2_payload, .size = sizeof(all2_payload), .offset = 0};
    run_derive_native_script_apdu(&all2_buf, P1_NATIVE_SCRIPT_START_COMPLEX);

    assert_int_equal(get_last_swo(), SWO_NATIVE_SCRIPT_PARSING_FAIL_NESTING);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// --- Simple script error paths ---

static void test_simple_script_empty_apdu(void **state) {
    // Zero-byte payload: can't read script type byte
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    buffer_t buf = {.ptr = NULL, .size = 0, .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);

    assert_int_equal(get_last_swo(), SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_TYPE);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_simple_script_unknown_type(void **state) {
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[1] = {0xFF};  // unknown simple script type
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);

    assert_int_equal(get_last_swo(), SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_TYPE);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_simple_script_nesting_violation(void **state) {
    // Send simple script when none expected (root slot already consumed)
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    // Add the one root simple script
    uint8_t simple_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    buffer_t simple_buf = {
        .ptr = simple_payload,
        .size = sizeof(simple_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&simple_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    // Now add a second simple script — no slot left at root
    buffer_t simple_buf2 = {
        .ptr = simple_payload,
        .size = sizeof(simple_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&simple_buf2, P1_NATIVE_SCRIPT_ADD_SIMPLE);

    assert_int_equal(get_last_swo(), SWO_NATIVE_SCRIPT_PARSING_FAIL_NESTING);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_pubkey_script_hash_credential_rejected(void **state) {
    // Pubkey APDU with credential type = SCRIPT_HASH is not allowed
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[1 + 1 + SCRIPT_HASH_LENGTH] = {0};
    payload[0] = NATIVE_SCRIPT_PUBKEY;
    payload[1] = EXT_CREDENTIAL_SCRIPT_HASH;
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);

    assert_int_equal(get_last_swo(), SWO_NATIVE_SCRIPT_PARSING_FAIL_PUBKEY_CREDENTIAL);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_pubkey_apdu_extra_bytes(void **state) {
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH + 1] = {0};
    payload[0] = NATIVE_SCRIPT_PUBKEY;
    payload[1] = EXT_CREDENTIAL_KEY_HASH;
    payload[sizeof(payload) - 1] = 0xFF;  // extra trailing byte
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);

    assert_int_equal(get_last_swo(), SWO_WRONG_DATA_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_invalid_before_truncated(void **state) {
    // Only 4 of the 8 required bytes for timelock u64
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[1 + 4] = {0};
    payload[0] = NATIVE_SCRIPT_INVALID_BEFORE;
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);

    assert_int_equal(get_last_swo(), SWO_NATIVE_SCRIPT_PARSING_FAIL_TIMELOCK);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_invalid_before_extra_bytes(void **state) {
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[1 + 8 + 1] = {0};
    payload[0] = NATIVE_SCRIPT_INVALID_BEFORE;
    payload[sizeof(payload) - 1] = 0xFF;  // extra byte
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);

    assert_int_equal(get_last_swo(), SWO_WRONG_DATA_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_invalid_hereafter_truncated(void **state) {
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[1 + 4] = {0};
    payload[0] = NATIVE_SCRIPT_INVALID_HEREAFTER;
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);

    assert_int_equal(get_last_swo(), SWO_NATIVE_SCRIPT_PARSING_FAIL_TIMELOCK);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_invalid_hereafter_extra_bytes(void **state) {
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t payload[1 + 8 + 1] = {0};
    payload[0] = NATIVE_SCRIPT_INVALID_HEREAFTER;
    payload[sizeof(payload) - 1] = 0xFF;  // extra byte
    buffer_t buf = {.ptr = payload, .size = sizeof(payload), .offset = 0};
    run_derive_native_script_apdu(&buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);

    assert_int_equal(get_last_swo(), SWO_WRONG_DATA_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

// --- Finish APDU error paths ---

static void test_finish_apdu_empty(void **state) {
    // Missing displayFormat byte
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t simple_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    buffer_t simple_buf = {
        .ptr = simple_payload,
        .size = sizeof(simple_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&simple_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    buffer_t finish_buf = {.ptr = NULL, .size = 0, .offset = 0};
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);

    assert_int_equal(get_last_swo(), SWO_WRONG_DATA_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_finish_apdu_extra_bytes(void **state) {
    (void) state;
    reset_test_context();
    reset_response_buffer();
    run_derive_native_script_init_apdu();
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t simple_payload[1 + 1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    simple_payload[0] = NATIVE_SCRIPT_PUBKEY;
    simple_payload[1] = EXT_CREDENTIAL_KEY_HASH;
    buffer_t simple_buf = {
        .ptr = simple_payload,
        .size = sizeof(simple_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&simple_buf, P1_NATIVE_SCRIPT_ADD_SIMPLE);
    assert_int_equal(get_last_swo(), SWO_SUCCESS);

    uint8_t finish_payload[2] = {DISPLAY_NATIVE_SCRIPT_HASH_BECH32, 0xFF};  // extra byte
    buffer_t finish_buf = {
        .ptr = finish_payload,
        .size = sizeof(finish_payload),
        .offset = 0,
    };
    run_derive_native_script_apdu(&finish_buf, P1_NATIVE_SCRIPT_FINISH);

    assert_int_equal(get_last_swo(), SWO_WRONG_DATA_LENGTH);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_finish_must_keep_request_lock_until_user_confirmation),
        cmocka_unit_test(test_simple_parse_failure_must_not_reach_postparse_state_mutation),
        cmocka_unit_test(test_n_of_k_required_greater_than_remaining),
        cmocka_unit_test(test_invalid_display_format),
        cmocka_unit_test(test_max_script_depth_exceeded),
        cmocka_unit_test(test_finish_with_remaining_scripts),
        cmocka_unit_test(test_pubkey_device_owned_invalid_classified_path_denied),
        // Init error paths
        cmocka_unit_test(test_init_apdu_with_extra_bytes),
        cmocka_unit_test(test_non_init_apdu_before_init_rejected),
        cmocka_unit_test(test_double_init_rejected),
        // Complex script start error paths
        cmocka_unit_test(test_complex_start_empty_apdu),
        cmocka_unit_test(test_complex_start_truncated_remaining_scripts),
        cmocka_unit_test(test_complex_start_all_extra_bytes),
        cmocka_unit_test(test_complex_start_any_extra_bytes),
        cmocka_unit_test(test_complex_start_unknown_script_type),
        cmocka_unit_test(test_complex_start_nof_k_truncated_required),
        cmocka_unit_test(test_complex_start_nof_k_extra_bytes),
        cmocka_unit_test(test_complex_start_nesting_violation),
        // Simple script error paths
        cmocka_unit_test(test_simple_script_empty_apdu),
        cmocka_unit_test(test_simple_script_unknown_type),
        cmocka_unit_test(test_simple_script_nesting_violation),
        cmocka_unit_test(test_pubkey_script_hash_credential_rejected),
        cmocka_unit_test(test_pubkey_apdu_extra_bytes),
        cmocka_unit_test(test_invalid_before_truncated),
        cmocka_unit_test(test_invalid_before_extra_bytes),
        cmocka_unit_test(test_invalid_hereafter_truncated),
        cmocka_unit_test(test_invalid_hereafter_extra_bytes),
        // Finish APDU error paths
        cmocka_unit_test(test_finish_apdu_empty),
        cmocka_unit_test(test_finish_apdu_extra_bytes),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_apdu_response);
}
