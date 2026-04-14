/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include <cmocka.h>

#include "apdu/dispatcher.h"
#include "buffer.h"
#include "cardano_swo.h"
#include "globals.h"
#include "app_context.h"
#include "ledger_assert.h"

static uint16_t g_last_swo = 0;
static uint8_t g_last_called_ins = 0;
static int g_last_handler_variant = 0;
static uint8_t g_last_handler_p1_or_p2 = 0;
static bool g_apdu_response_active = false;
static bool g_apdu_response_sent = false;
static bool g_apdu_response_deferred = false;
static bool g_get_serial_should_defer = false;

static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    g_last_swo = 0;
    g_last_called_ins = 0;
    g_last_handler_variant = 0;
    g_last_handler_p1_or_p2 = 0;
    g_apdu_response_active = false;
    g_apdu_response_sent = false;
    g_apdu_response_deferred = false;
    g_get_serial_should_defer = false;
}

enum {
    HANDLER_VARIANT_NONE = 0,
    HANDLER_VARIANT_SIGN_TX,
    HANDLER_VARIANT_SIGN_TX_WITNESS,
    HANDLER_VARIANT_SIGN_TX_AUX_DATA,
};

// -------------------------------------------------------------------------
// App context / IO hooks
// -------------------------------------------------------------------------
//
// This test intentionally provides its own minimal IO/APDU plumbing instead of
// using io_capture.c or apdu_finalization_check.h. The dispatcher behavior under
// test is centered on interleaving / deferred-response state, and these local
// stubs expose that state directly without pulling in the shared helper
// implementation or its weak overrides.

void reset_app_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    G_context.req_type = REQUEST_NONE;
}

void send_swo_and_reset(uint16_t swo) {
    reset_app_context();
    apdu_response_send_sw(swo);
}

int io_send_sw(uint16_t swo) {
    g_last_swo = swo;
    return 0;
}

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    (void) buffer;
    (void) bufferLength;
    g_last_swo = swo;
    return 0;
}

void apdu_response_begin(command_e instruction) {
    (void) instruction;
    if (g_apdu_response_active) {
        abort();
    }
    g_apdu_response_active = true;
    g_apdu_response_sent = false;
    g_apdu_response_deferred = false;
}

void apdu_response_deferred(void) {
    if (!g_apdu_response_active || g_apdu_response_sent) {
        abort();
    }
    g_apdu_response_deferred = true;
}

void apdu_response_finalize_after_handler(void) {
    if (!g_apdu_response_active) {
        abort();
    }
    if (!g_apdu_response_sent && !g_apdu_response_deferred) {
        abort();
    }
    if (g_apdu_response_sent) {
        g_apdu_response_active = false;
        g_apdu_response_sent = false;
        g_apdu_response_deferred = false;
    }
}

bool apdu_response_is_pending_ux(void) {
    return !g_apdu_response_sent && g_apdu_response_deferred;
}

void apdu_response_send_sw(uint16_t swo) {
    if (g_apdu_response_active) {
        if (g_apdu_response_sent) {
            abort();
        }
        g_apdu_response_sent = true;
    }
    int result = io_send_sw(swo);
    LEDGER_ASSERT(result >= 0, "io_send_sw failed");
    if (g_apdu_response_active && g_apdu_response_deferred && g_apdu_response_sent) {
        g_apdu_response_active = false;
        g_apdu_response_sent = false;
        g_apdu_response_deferred = false;
    }
}

void apdu_response_send_data(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    if (g_apdu_response_active) {
        if (g_apdu_response_sent) {
            abort();
        }
        g_apdu_response_sent = true;
    }
    int result = io_send_response_pointer(buffer, bufferLength, swo);
    LEDGER_ASSERT(result >= 0, "io_send_response_pointer failed");
    if (g_apdu_response_active && g_apdu_response_deferred && g_apdu_response_sent) {
        g_apdu_response_active = false;
        g_apdu_response_sent = false;
        g_apdu_response_deferred = false;
    }
}

// -------------------------------------------------------------------------
// Handler stubs used by dispatcher
// -------------------------------------------------------------------------

void handler_get_serial(buffer_t *cdata) {
    (void) cdata;
    g_last_called_ins = INS_GET_SERIAL;
    if (g_get_serial_should_defer) {
        apdu_response_deferred();
        return;
    }
    apdu_response_send_sw(SWO_SUCCESS);
}

void handler_get_version(buffer_t *cdata) {
    (void) cdata;
    g_last_called_ins = INS_GET_VERSION;
    apdu_response_send_sw(SWO_SUCCESS);
}

void handler_get_app_name(buffer_t *cdata) {
    (void) cdata;
    g_last_called_ins = INS_GET_APP_NAME;
    apdu_response_send_sw(SWO_SUCCESS);
}

void handler_get_public_key(buffer_t *cdata) {
    (void) cdata;
    g_last_called_ins = INS_GET_PUBLIC_KEY;
    apdu_response_send_sw(SWO_SUCCESS);
}

void handler_derive_address(buffer_t *cdata, uint8_t p1) {
    (void) cdata;
    g_last_called_ins = INS_DERIVE_ADDRESS;
    g_last_handler_p1_or_p2 = p1;
    apdu_response_send_sw(SWO_SUCCESS);
}

void handler_derive_native_script_hash(buffer_t *cdata, uint8_t script_type) {
    (void) cdata;
    g_last_called_ins = INS_DERIVE_NATIVE_SCRIPT_HASH;
    g_last_handler_p1_or_p2 = script_type;
    apdu_response_send_sw(SWO_SUCCESS);
}

void handler_sign_tx(buffer_t *cdata, uint8_t p1) {
    (void) cdata;
    g_last_called_ins = INS_SIGN_TX;
    g_last_handler_variant = HANDLER_VARIANT_SIGN_TX;
    g_last_handler_p1_or_p2 = p1;
    apdu_response_send_sw(SWO_SUCCESS);
}

void handler_sign_tx_witness(buffer_t *cdata) {
    (void) cdata;
    g_last_called_ins = INS_SIGN_TX;
    g_last_handler_variant = HANDLER_VARIANT_SIGN_TX_WITNESS;
    apdu_response_send_sw(SWO_SUCCESS);
}

void handler_sign_tx_aux_data(buffer_t *cdata, uint8_t p2) {
    (void) cdata;
    g_last_called_ins = INS_SIGN_TX;
    g_last_handler_variant = HANDLER_VARIANT_SIGN_TX_AUX_DATA;
    g_last_handler_p1_or_p2 = p2;
    apdu_response_send_sw(SWO_SUCCESS);
}

void handler_sign_opcert(buffer_t *cdata) {
    (void) cdata;
    g_last_called_ins = INS_SIGN_OPCERT;
    apdu_response_send_sw(SWO_SUCCESS);
}

void handler_sign_cvote(buffer_t *cdata, uint8_t p1) {
    (void) cdata;
    g_last_called_ins = INS_SIGN_CVOTE;
    g_last_handler_p1_or_p2 = p1;
    apdu_response_send_sw(SWO_SUCCESS);
}

void handler_sign_msg(buffer_t *cdata, uint8_t p1) {
    (void) cdata;
    g_last_called_ins = INS_SIGN_MSG;
    g_last_handler_p1_or_p2 = p1;
    apdu_response_send_sw(SWO_SUCCESS);
}

#ifdef DEBUG
void handler_debug_set_settings(buffer_t *cdata) {
    (void) cdata;
    g_last_called_ins = INS_DEBUG_SET_SETTINGS;
    apdu_response_send_sw(SWO_SUCCESS);
}
#endif

static command_t make_command(uint8_t ins, uint8_t p1, uint8_t p2) {
    static uint8_t dummy = 0;
    command_t cmd = {
        .cla = CLA,
        .ins = ins,
        .p1 = p1,
        .p2 = p2,
        .lc = 0,
        .data = &dummy,
    };
    return cmd;
}

static command_t make_command_with_cla(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2) {
    command_t cmd = make_command(ins, p1, p2);
    cmd.cla = cla;
    return cmd;
}

static void test_interleaving_guard_blocks_other_instructions(void **state) {
    (void) state;

    const struct {
        request_type_e req;
        uint8_t expected_ins;
    } cases[] = {
        {REQUEST_EXPORT_PUBKEY, INS_GET_PUBLIC_KEY},
        {REQUEST_SIGN_TRANSACTION, INS_SIGN_TX},
        {REQUEST_SIGN_OPCERT, INS_SIGN_OPCERT},
        {REQUEST_DERIVE_ADDRESS, INS_DERIVE_ADDRESS},
        {REQUEST_DERIVE_NATIVE_SCRIPT_HASH, INS_DERIVE_NATIVE_SCRIPT_HASH},
        {REQUEST_CVOTE, INS_SIGN_CVOTE},
        {REQUEST_SIGN_MSG, INS_SIGN_MSG},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        reset_test_context();
        G_context.req_type = cases[i].req;

        uint8_t attempted_ins = INS_GET_VERSION;
        if (attempted_ins == cases[i].expected_ins) {
            attempted_ins = INS_GET_APP_NAME;
        }
        command_t cmd = make_command(attempted_ins, P1_UNUSED, P2_UNUSED);
        apdu_dispatcher(&cmd);

        assert_int_equal(g_last_swo, SWO_COMMAND_NOT_ALLOWED);
        assert_int_equal(G_context.req_type, cases[i].req);
        assert_false(g_apdu_response_active);
    }
}

static void test_interleaving_during_deferred_response_preserves_original_state(void **state) {
    (void) state;

    reset_test_context();
    g_get_serial_should_defer = true;

    command_t deferred_cmd = make_command(INS_GET_SERIAL, P1_UNUSED, P2_UNUSED);
    apdu_dispatcher(&deferred_cmd);

    assert_int_equal(g_last_called_ins, INS_GET_SERIAL);
    assert_true(g_apdu_response_active);
    assert_true(g_apdu_response_deferred);

    G_context.req_type = REQUEST_EXPORT_PUBKEY;

    command_t stray_cmd = make_command(INS_GET_VERSION, P1_UNUSED, P2_UNUSED);
    apdu_dispatcher(&stray_cmd);

    assert_int_equal(g_last_swo, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(G_context.req_type, REQUEST_EXPORT_PUBKEY);
    assert_true(g_apdu_response_active);
    assert_true(g_apdu_response_deferred);
}

static void test_same_instruction_during_deferred_response_is_rejected(void **state) {
    (void) state;

    reset_test_context();
    g_get_serial_should_defer = true;

    command_t deferred_cmd = make_command(INS_GET_SERIAL, P1_UNUSED, P2_UNUSED);
    apdu_dispatcher(&deferred_cmd);

    assert_int_equal(g_last_called_ins, INS_GET_SERIAL);
    assert_true(g_apdu_response_active);
    assert_true(g_apdu_response_deferred);

    command_t same_ins_cmd = make_command(INS_GET_SERIAL, P1_UNUSED, P2_UNUSED);
    apdu_dispatcher(&same_ins_cmd);

    assert_int_equal(g_last_swo, SWO_COMMAND_NOT_ALLOWED);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
    assert_true(g_apdu_response_active);
    assert_true(g_apdu_response_deferred);
}

static void test_interleaving_allows_expected_instruction(void **state) {
    (void) state;

    const struct {
        request_type_e req;
        uint8_t ins;
        uint8_t p1;
        uint8_t p2;
    } cases[] = {
        {REQUEST_EXPORT_PUBKEY, INS_GET_PUBLIC_KEY, P1_UNUSED, P2_UNUSED},
        {REQUEST_SIGN_TRANSACTION, INS_SIGN_TX, P1_TX_INIT, P2_UNUSED},
        {REQUEST_SIGN_OPCERT, INS_SIGN_OPCERT, P1_UNUSED, P2_UNUSED},
        {REQUEST_DERIVE_ADDRESS, INS_DERIVE_ADDRESS, P1_ADDRESS_RETURN, P2_UNUSED},
        {REQUEST_DERIVE_NATIVE_SCRIPT_HASH,
         INS_DERIVE_NATIVE_SCRIPT_HASH,
         P1_NATIVE_SCRIPT_FINISH,
         P2_UNUSED},
        {REQUEST_CVOTE, INS_SIGN_CVOTE, P1_CVOTE_INIT, P2_UNUSED},
        {REQUEST_SIGN_MSG, INS_SIGN_MSG, P1_SIGN_MSG_INIT, P2_UNUSED},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        reset_test_context();
        G_context.req_type = cases[i].req;
        command_t cmd = make_command(cases[i].ins, cases[i].p1, cases[i].p2);
        apdu_dispatcher(&cmd);

        assert_int_equal(g_last_swo, SWO_SUCCESS);
        assert_int_equal(g_last_called_ins, cases[i].ins);
    }
}

static void test_deferred_response_is_allowed(void **state) {
    (void) state;

    reset_test_context();
    g_get_serial_should_defer = true;

    command_t cmd = make_command(INS_GET_SERIAL, P1_UNUSED, P2_UNUSED);
    apdu_dispatcher(&cmd);

    assert_int_equal(g_last_called_ins, INS_GET_SERIAL);
    assert_int_equal(g_last_swo, 0);
    assert_true(g_apdu_response_active);
    assert_true(g_apdu_response_deferred);

    apdu_response_send_sw(SWO_SUCCESS);
    assert_int_equal(g_last_swo, SWO_SUCCESS);
    assert_false(g_apdu_response_active);
}

static void test_invalid_cla_is_rejected(void **state) {
    (void) state;

    reset_test_context();

    command_t cmd = make_command_with_cla(CLA + 1, INS_GET_VERSION, P1_UNUSED, P2_UNUSED);
    apdu_dispatcher(&cmd);

    assert_int_equal(g_last_swo, SWO_INVALID_CLA);
    assert_int_equal(g_last_called_ins, 0);
}

static void test_stateless_dispatch_routes_to_basic_handlers(void **state) {
    (void) state;

    const struct {
        uint8_t ins;
        uint8_t expected_ins;
    } cases[] = {
        {INS_GET_SERIAL, INS_GET_SERIAL},
        {INS_GET_VERSION, INS_GET_VERSION},
        {INS_GET_APP_NAME, INS_GET_APP_NAME},
        {INS_GET_PUBLIC_KEY, INS_GET_PUBLIC_KEY},
        {INS_SIGN_OPCERT, INS_SIGN_OPCERT},
#ifdef DEBUG
        {INS_DEBUG_SET_SETTINGS, INS_DEBUG_SET_SETTINGS},
#endif
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        reset_test_context();

        command_t cmd = make_command(cases[i].ins, P1_UNUSED, P2_UNUSED);
        apdu_dispatcher(&cmd);

        assert_int_equal(g_last_swo, SWO_SUCCESS);
        assert_int_equal(g_last_called_ins, cases[i].expected_ins);
    }
}

static void test_invalid_instruction_is_rejected(void **state) {
    (void) state;

    reset_test_context();

    command_t cmd = make_command(0xEE, P1_UNUSED, P2_UNUSED);
    apdu_dispatcher(&cmd);

    assert_int_equal(g_last_swo, SWO_INVALID_INS);
    assert_int_equal(G_context.req_type, REQUEST_NONE);
}

static void test_dispatcher_rejects_invalid_p1_p2_combinations(void **state) {
    (void) state;

    const struct {
        uint8_t ins;
        uint8_t p1;
        uint8_t p2;
    } cases[] = {
        {INS_GET_SERIAL, 0x01, P2_UNUSED},
        {INS_GET_VERSION, P1_UNUSED, 0x01},
        {INS_GET_APP_NAME, 0x01, P2_UNUSED},
        {INS_GET_PUBLIC_KEY, P1_UNUSED, 0x01},
        {INS_DERIVE_ADDRESS, 0xEE, P2_UNUSED},
        {INS_DERIVE_NATIVE_SCRIPT_HASH, 0xEE, P2_UNUSED},
        {INS_SIGN_TX, P1_TX_INIT, 0x01},
        {INS_SIGN_TX, P1_TX_AUX_DATA, 0xEE},
        {INS_SIGN_CVOTE, 0xEE, P2_UNUSED},
        {INS_SIGN_MSG, 0xEE, P2_UNUSED},
        {INS_SIGN_OPCERT, 0x01, P2_UNUSED},
#ifdef DEBUG
        {INS_DEBUG_SET_SETTINGS, P1_UNUSED, 0x01},
#endif
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        reset_test_context();

        command_t cmd = make_command(cases[i].ins, cases[i].p1, cases[i].p2);
        apdu_dispatcher(&cmd);

        assert_int_equal(g_last_swo, SWO_INCORRECT_P1_P2);
        assert_int_equal(g_last_called_ins, 0);
        assert_int_equal(G_context.req_type, REQUEST_NONE);
    }
}

static void test_sign_tx_special_branches_are_dispatched(void **state) {
    (void) state;

    const struct {
        uint8_t p1;
        uint8_t p2;
        int expected_variant;
        uint8_t expected_p1_or_p2;
    } cases[] = {
        {P1_TX_INIT, P2_UNUSED, HANDLER_VARIANT_SIGN_TX, P1_TX_INIT},
        {P1_TX_SIGN_WITNESS, P2_UNUSED, HANDLER_VARIANT_SIGN_TX_WITNESS, 0},
        {P1_TX_AUX_DATA, P2_AUX_DATA_INIT, HANDLER_VARIANT_SIGN_TX_AUX_DATA, P2_AUX_DATA_INIT},
        {P1_TX_AUX_DATA,
         P2_AUX_DATA_DELEGATION,
         HANDLER_VARIANT_SIGN_TX_AUX_DATA,
         P2_AUX_DATA_DELEGATION},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        reset_test_context();

        command_t cmd = make_command(INS_SIGN_TX, cases[i].p1, cases[i].p2);
        apdu_dispatcher(&cmd);

        assert_int_equal(g_last_swo, SWO_SUCCESS);
        assert_int_equal(g_last_called_ins, INS_SIGN_TX);
        assert_int_equal(g_last_handler_variant, cases[i].expected_variant);
        assert_int_equal(g_last_handler_p1_or_p2, cases[i].expected_p1_or_p2);
    }
}

static void test_multi_phase_handlers_accept_all_supported_p1_values(void **state) {
    (void) state;

    const struct {
        uint8_t ins;
        const uint8_t *valid_p1_values;
        size_t valid_p1_values_count;
    } cases[] = {
        {INS_DERIVE_ADDRESS, (const uint8_t[]){P1_ADDRESS_RETURN, P1_ADDRESS_DISPLAY}, 2},
        {INS_DERIVE_NATIVE_SCRIPT_HASH,
         (const uint8_t[]){P1_NATIVE_SCRIPT_INIT,
                           P1_NATIVE_SCRIPT_START_COMPLEX,
                           P1_NATIVE_SCRIPT_ADD_SIMPLE,
                           P1_NATIVE_SCRIPT_FINISH},
         4},
        {INS_SIGN_CVOTE, (const uint8_t[]){P1_CVOTE_INIT, P1_CVOTE_CHUNK, P1_CVOTE_CONFIRM}, 3},
        {INS_SIGN_MSG,
         (const uint8_t[]){P1_SIGN_MSG_INIT, P1_SIGN_MSG_CHUNK, P1_SIGN_MSG_CONFIRM},
         3},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        for (size_t j = 0; j < cases[i].valid_p1_values_count; j++) {
            reset_test_context();

            command_t cmd = make_command(cases[i].ins, cases[i].valid_p1_values[j], P2_UNUSED);
            apdu_dispatcher(&cmd);

            assert_int_equal(g_last_swo, SWO_SUCCESS);
            assert_int_equal(g_last_called_ins, cases[i].ins);
            assert_int_equal(g_last_handler_p1_or_p2, cases[i].valid_p1_values[j]);
        }
    }
}

static int assert_no_pending_deferred_response(void **state) {
    (void) state;
    // This test cannot use the shared assert_no_pending_apdu_response() helper
    // because it replaces the APDU response functions with file-local stubs.
    assert_false(g_apdu_response_active && g_apdu_response_deferred && !g_apdu_response_sent);
    return 0;
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_interleaving_guard_blocks_other_instructions),
        cmocka_unit_test(test_interleaving_during_deferred_response_preserves_original_state),
        cmocka_unit_test(test_same_instruction_during_deferred_response_is_rejected),
        cmocka_unit_test(test_interleaving_allows_expected_instruction),
        cmocka_unit_test(test_deferred_response_is_allowed),
        cmocka_unit_test(test_invalid_cla_is_rejected),
        cmocka_unit_test(test_stateless_dispatch_routes_to_basic_handlers),
        cmocka_unit_test(test_invalid_instruction_is_rejected),
        cmocka_unit_test(test_dispatcher_rejects_invalid_p1_p2_combinations),
        cmocka_unit_test(test_sign_tx_special_branches_are_dispatched),
        cmocka_unit_test(test_multi_phase_handlers_accept_all_supported_p1_values),
    };
    return cmocka_run_group_tests(tests, NULL, assert_no_pending_deferred_response);
}
