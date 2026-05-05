/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "tx.h"
#include "tx_signing_mode.h"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static tx_params_t make_params(sign_tx_signingmode_t mode) {
    tx_params_t p;
    memset(&p, 0, sizeof(p));
    p.txSigningMode = mode;
    return p;
}

// ---------------------------------------------------------------------------
// is_valid_tx_signing_mode
// ---------------------------------------------------------------------------

static void test_is_valid_accepts_all_concrete_modes(void **state) {
    (void) state;
    assert_true(is_valid_tx_signing_mode(SIGN_TX_SIGNINGMODE_ORDINARY));
    assert_true(is_valid_tx_signing_mode(SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER));
    assert_true(is_valid_tx_signing_mode(SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR));
    assert_true(is_valid_tx_signing_mode(SIGN_TX_SIGNINGMODE_MULTISIG));
    assert_true(is_valid_tx_signing_mode(SIGN_TX_SIGNINGMODE_PLUTUS));
    assert_true(is_valid_tx_signing_mode(SIGN_TX_SIGNINGMODE_UNRESTRICTED));
}

static void test_is_valid_accepts_auto(void **state) {
    (void) state;
    assert_true(is_valid_tx_signing_mode(SIGN_TX_SIGNINGMODE_AUTO));
}

static void test_is_valid_rejects_unknown_values(void **state) {
    (void) state;
    assert_false(is_valid_tx_signing_mode(0));
    assert_false(is_valid_tx_signing_mode(1));
    assert_false(is_valid_tx_signing_mode(2));
    assert_false(is_valid_tx_signing_mode(8));
    assert_false(is_valid_tx_signing_mode(0xFF));
}

// ---------------------------------------------------------------------------
// resolve_auto_tx_signing_mode — non-AUTO passthrough
// ---------------------------------------------------------------------------

static void test_resolve_noop_on_concrete_mode(void **state) {
    (void) state;
    tx_params_t p = make_params(SIGN_TX_SIGNINGMODE_ORDINARY);
    assert_true(resolve_auto_tx_signing_mode(&p));
    assert_int_equal(p.txSigningMode, SIGN_TX_SIGNINGMODE_ORDINARY);

    p = make_params(SIGN_TX_SIGNINGMODE_PLUTUS);
    assert_true(resolve_auto_tx_signing_mode(&p));
    assert_int_equal(p.txSigningMode, SIGN_TX_SIGNINGMODE_PLUTUS);

    p = make_params(SIGN_TX_SIGNINGMODE_MULTISIG);
    assert_true(resolve_auto_tx_signing_mode(&p));
    assert_int_equal(p.txSigningMode, SIGN_TX_SIGNINGMODE_MULTISIG);

    p = make_params(SIGN_TX_SIGNINGMODE_UNRESTRICTED);
    assert_true(resolve_auto_tx_signing_mode(&p));
    assert_int_equal(p.txSigningMode, SIGN_TX_SIGNINGMODE_UNRESTRICTED);
}

// ---------------------------------------------------------------------------
// resolve_auto_tx_signing_mode — AUTO → PLUTUS via each Plutus indicator
// ---------------------------------------------------------------------------

static void test_resolve_auto_via_collateral_inputs(void **state) {
    (void) state;
    tx_params_t p = make_params(SIGN_TX_SIGNINGMODE_AUTO);
    p.num_collateral_inputs = 1;
    assert_true(resolve_auto_tx_signing_mode(&p));
    assert_int_equal(p.txSigningMode, SIGN_TX_SIGNINGMODE_PLUTUS);
}

static void test_resolve_auto_via_collateral_output(void **state) {
    (void) state;
    tx_params_t p = make_params(SIGN_TX_SIGNINGMODE_AUTO);
    p.includeCollateralOutput = true;
    assert_true(resolve_auto_tx_signing_mode(&p));
    assert_int_equal(p.txSigningMode, SIGN_TX_SIGNINGMODE_PLUTUS);
}

static void test_resolve_auto_via_total_collateral(void **state) {
    (void) state;
    tx_params_t p = make_params(SIGN_TX_SIGNINGMODE_AUTO);
    p.includeTotalCollateral = true;
    assert_true(resolve_auto_tx_signing_mode(&p));
    assert_int_equal(p.txSigningMode, SIGN_TX_SIGNINGMODE_PLUTUS);
}

static void test_resolve_auto_via_reference_inputs(void **state) {
    (void) state;
    tx_params_t p = make_params(SIGN_TX_SIGNINGMODE_AUTO);
    p.num_reference_inputs = 1;
    assert_true(resolve_auto_tx_signing_mode(&p));
    assert_int_equal(p.txSigningMode, SIGN_TX_SIGNINGMODE_PLUTUS);
}

static void test_resolve_auto_via_script_data_hash(void **state) {
    (void) state;
    tx_params_t p = make_params(SIGN_TX_SIGNINGMODE_AUTO);
    p.includeScriptDataHash = true;
    assert_true(resolve_auto_tx_signing_mode(&p));
    assert_int_equal(p.txSigningMode, SIGN_TX_SIGNINGMODE_PLUTUS);
}

// ---------------------------------------------------------------------------
// resolve_auto_tx_signing_mode — AUTO → ambiguous (no Plutus indicators)
// ---------------------------------------------------------------------------

static void test_resolve_auto_ambiguous_no_plutus_indicators(void **state) {
    (void) state;
    tx_params_t p = make_params(SIGN_TX_SIGNINGMODE_AUTO);
    assert_false(resolve_auto_tx_signing_mode(&p));
    // mode must remain AUTO (not silently changed to something else)
    assert_int_equal(p.txSigningMode, SIGN_TX_SIGNINGMODE_AUTO);
}

static void test_resolve_auto_ambiguous_with_non_plutus_fields(void **state) {
    (void) state;
    // Certs, withdrawals, mint, TTL — none are Plutus indicators
    tx_params_t p = make_params(SIGN_TX_SIGNINGMODE_AUTO);
    p.num_certificates = 2;
    p.num_withdrawals = 1;
    p.num_mint_asset_groups = 3;
    p.includeTtl = true;
    p.includeValidityIntervalStart = true;
    assert_false(resolve_auto_tx_signing_mode(&p));
    assert_int_equal(p.txSigningMode, SIGN_TX_SIGNINGMODE_AUTO);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_is_valid_accepts_all_concrete_modes),
        cmocka_unit_test(test_is_valid_accepts_auto),
        cmocka_unit_test(test_is_valid_rejects_unknown_values),
        cmocka_unit_test(test_resolve_noop_on_concrete_mode),
        cmocka_unit_test(test_resolve_auto_via_collateral_inputs),
        cmocka_unit_test(test_resolve_auto_via_collateral_output),
        cmocka_unit_test(test_resolve_auto_via_total_collateral),
        cmocka_unit_test(test_resolve_auto_via_reference_inputs),
        cmocka_unit_test(test_resolve_auto_via_script_data_hash),
        cmocka_unit_test(test_resolve_auto_ambiguous_no_plutus_indicators),
        cmocka_unit_test(test_resolve_auto_ambiguous_with_non_plutus_fields),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
