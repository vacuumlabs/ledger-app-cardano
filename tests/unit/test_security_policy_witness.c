/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Focused policy tests for witness and CVote vote-key functions.
 *
 * Philosophy: we test non-trivial invariants that would be hard to catch
 * through handler-level fixtures alone, not exhaustive mirrors of the
 * switch/case logic.  Three invariants are covered:
 *
 *  1. Plutus witness policy never DENYs any ordinarily-valid signing path.
 *     (Plutus is the most permissive mode; a regression here would silently
 *      block legitimate Plutus tx witnesses.)
 *
 *  2. policyForSignCVoteWitness: only PATH_CVOTE_KEY is allowed; every
 *     other path class is DENY.  This is a tight allowlist with security
 *     implications.
 *
 *  3. policyForCVoteRegistrationVoteKey: KEY_PATH credential is rejected
 *     when the format is CIP15 (only CIP36 permits a path-based vote key).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "securityPolicy/securityPolicy.h"
#include "addressUtils/bip44.h"
#include "globals.h"

static void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
}

// ======================================================================
// Path builders
// Chain index values mirror the CARDANO_CHAIN_* local enum in bip44.c:
//   external=0, internal=1, staking=2, drep=3, committee_cold=4, committee_hot=5
// ======================================================================

static bip44_path_t make_shelley_payment_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_SHELLEY);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 0;  // external chain
    p.path[4] = 0;
    return p;
}

static bip44_path_t make_shelley_staking_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_SHELLEY);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 2;  // staking key chain
    p.path[4] = 0;
    return p;
}

static bip44_path_t make_multisig_payment_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_MULTISIG);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 0;  // external chain
    p.path[4] = 0;
    return p;
}

static bip44_path_t make_multisig_staking_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_MULTISIG);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 2;  // staking key chain
    p.path[4] = 0;
    return p;
}

static bip44_path_t make_drep_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_SHELLEY);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 3;  // drep key chain
    p.path[4] = 0;
    return p;
}

static bip44_path_t make_committee_cold_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_SHELLEY);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 4;  // committee cold key chain
    p.path[4] = 0;
    return p;
}

static bip44_path_t make_committee_hot_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_SHELLEY);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 5;  // committee hot key chain
    p.path[4] = 0;
    return p;
}

static bip44_path_t make_mint_path(void) {
    bip44_path_t p = {0};
    p.length = 3;
    p.path[0] = bip44_harden(PURPOSE_MINT);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    return p;
}

static bip44_path_t make_pool_cold_key_path(void) {
    bip44_path_t p = {0};
    p.length = 4;
    p.path[0] = bip44_harden(PURPOSE_POOL_COLD_KEY);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = bip44_harden(0);
    return p;
}

static bip44_path_t make_cvote_key_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_CVOTE_KEY);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 0;
    p.path[4] = 0;
    return p;
}

// ======================================================================
// 1. Plutus witness policy never DENYs ordinarily-valid signing paths
// ======================================================================

static void test_plutus_witness_payment_path_not_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_shelley_payment_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_PLUTUS, false, &path, false, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_plutus_witness_staking_path_not_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_shelley_staking_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_PLUTUS, false, &path, false, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_plutus_witness_multisig_payment_path_not_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_multisig_payment_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_PLUTUS, false, &path, false, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_plutus_witness_multisig_staking_path_not_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_multisig_staking_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_PLUTUS, false, &path, false, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_plutus_witness_drep_path_not_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_drep_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_PLUTUS, false, &path, false, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_plutus_witness_committee_cold_path_not_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_committee_cold_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_PLUTUS, false, &path, false, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_plutus_witness_committee_hot_path_not_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_committee_hot_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_PLUTUS, false, &path, false, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_plutus_witness_mint_path_not_denied_when_mint_present(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_mint_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignTxWitness(SIGN_TX_SIGNINGMODE_PLUTUS,
                                                      false,
                                                      &path,
                                                      true /* mintPresent */,
                                                      NULL,
                                                      &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

// Pool cold key is the one path class explicitly denied in Plutus mode —
// verify the DENY is still in place (regression guard for the opposite direction).
static void test_plutus_witness_pool_cold_key_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_pool_cold_key_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_PLUTUS, false, &path, false, NULL, &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_unrestricted_witness_pool_cold_key_allowed(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_pool_cold_key_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_UNRESTRICTED, false, &path, false, NULL, &w);
    assert_int_equal(policy, POLICY_SHOW);
}

static void test_unrestricted_witness_mint_key_allowed_without_mint(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_mint_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_UNRESTRICTED, false, &path, false, NULL, &w);
    assert_int_equal(policy, POLICY_SHOW);
}

// ======================================================================
// 2. Swap witness policy: isSwap=true branch of policyForSignTxWitness
//
// _swapWitnessPolicy invariants:
//   a. Only SIGN_TX_SIGNINGMODE_ORDINARY is accepted — all other modes DENY.
//   b. Only PATH_ORDINARY_PAYMENT_KEY is accepted — all other path classes DENY.
//   c. Reasonable payment path → HIDE (no UI confirmation required in swap flow).
//   d. Payment path from a second account → DENY (single-account invariant).
//   e. Unusual-index payment path (account 0, address index >= 1000000) → DENY
//      (bip44_isPathReasonable check, because swap has no witness UI to warn user).
// ======================================================================

// a. Only ORDINARY_TX mode is accepted in swap flow.
static void test_swap_witness_non_ordinary_mode_denied(void **state) {
    (void) state;
    const sign_tx_signingmode_t non_ordinary_modes[] = {
        SIGN_TX_SIGNINGMODE_MULTISIG,
        SIGN_TX_SIGNINGMODE_PLUTUS,
        SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER,
        SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR,
    };
    bip44_path_t path = make_shelley_payment_path();
    for (size_t i = 0; i < sizeof(non_ordinary_modes) / sizeof(non_ordinary_modes[0]); i++) {
        reset_context();
        warning_bits_t w = 0;
        security_policy_t policy =
            policyForSignTxWitness(non_ordinary_modes[i], true, &path, false, NULL, &w);
        assert_int_equal(policy, POLICY_DENY);
    }
}

// b. Non-payment-key paths are denied in swap flow.
static void test_swap_witness_staking_path_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_shelley_staking_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_ORDINARY, true, &path, false, NULL, &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_swap_witness_multisig_payment_path_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_multisig_payment_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_ORDINARY, true, &path, false, NULL, &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_swap_witness_pool_cold_key_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_pool_cold_key_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_ORDINARY, true, &path, false, NULL, &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_swap_witness_drep_path_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_drep_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_ORDINARY, true, &path, false, NULL, &w);
    assert_int_equal(policy, POLICY_DENY);
}

// c. A reasonable ordinary payment path in ORDINARY_TX swap mode → HIDE.
static void test_swap_witness_ordinary_payment_path_hidden(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_shelley_payment_path();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_ORDINARY, true, &path, false, NULL, &w);
    assert_int_equal(policy, POLICY_HIDE);
}

// d. Second-account payment path → DENY (single-account invariant).
// Call with account 0 first to store it, then call with account 1.
static void test_swap_witness_second_account_payment_path_denied(void **state) {
    (void) state;
    reset_context();

    // First call: account 0 — stores the account in single_account_data.
    bip44_path_t path_account0 = make_shelley_payment_path();  // account = harden(0)
    warning_bits_t w = 0;
    security_policy_t first_policy = policyForSignTxWitness(SIGN_TX_SIGNINGMODE_ORDINARY,
                                                            true,
                                                            &path_account0,
                                                            false,
                                                            NULL,
                                                            &w);
    assert_int_equal(first_policy, POLICY_HIDE);

    // Second call: account 1 — must be denied.
    bip44_path_t path_account1 = {0};
    path_account1.length = 5;
    path_account1.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path_account1.path[1] = bip44_harden(ADA_COIN_TYPE);
    path_account1.path[2] = bip44_harden(1);  // account 1
    path_account1.path[3] = 0;                // external chain
    path_account1.path[4] = 0;
    w = 0;
    security_policy_t second_policy = policyForSignTxWitness(SIGN_TX_SIGNINGMODE_ORDINARY,
                                                             true,
                                                             &path_account1,
                                                             false,
                                                             NULL,
                                                             &w);
    assert_int_equal(second_policy, POLICY_DENY);
}

// e. Unusual address index (>= 1000000) → DENY (bip44_isPathReasonable fails).
// Swap has no witness UI so unusual derivations cannot be flagged to the user.
static void test_swap_witness_unusual_index_payment_path_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = {0};
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(0);
    path.path[3] = 0;        // external chain
    path.path[4] = 1000001;  // exceeds MAX_REASONABLE_ADDRESS (1000000), so not reasonable
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxWitness(SIGN_TX_SIGNINGMODE_ORDINARY, true, &path, false, NULL, &w);
    assert_int_equal(policy, POLICY_DENY);
}

// ======================================================================
// 3. policyForSignCVoteWitness: tight allowlist — only cvote key allowed
// ======================================================================

static void test_cvote_witness_cvote_key_allowed(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_cvote_key_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignCVoteWitness(&path, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_cvote_witness_payment_path_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_shelley_payment_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignCVoteWitness(&path, &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_cvote_witness_staking_path_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_shelley_staking_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignCVoteWitness(&path, &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_cvote_witness_pool_cold_key_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_pool_cold_key_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignCVoteWitness(&path, &w);
    assert_int_equal(policy, POLICY_DENY);
}

// ======================================================================
// 3. policyForCVoteRegistrationVoteKey: KEY_PATH requires CIP36 format
// ======================================================================

static void test_cvote_vote_key_path_denied_for_cip15(void **state) {
    (void) state;
    reset_context();
    cvote_credential_t credential = {0};
    credential.type = CVOTE_CREDENTIAL_KEY_PATH;
    credential.keyPath = make_cvote_key_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForCVoteRegistrationVoteKey(&credential, CIP15, &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_cvote_vote_key_path_allowed_for_cip36(void **state) {
    (void) state;
    reset_context();
    cvote_credential_t credential = {0};
    credential.type = CVOTE_CREDENTIAL_KEY_PATH;
    credential.keyPath = make_cvote_key_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForCVoteRegistrationVoteKey(&credential, CIP36, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

// Raw public key credential is always allowed regardless of format
static void test_cvote_vote_key_raw_pubkey_allowed_for_cip15(void **state) {
    (void) state;
    reset_context();
    cvote_credential_t credential = {0};
    credential.type = CVOTE_CREDENTIAL_KEY;
    warning_bits_t w = 0;
    security_policy_t policy = policyForCVoteRegistrationVoteKey(&credential, CIP15, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

// ======================================================================
// Main
// ======================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        // Plutus witness: ordinarily-valid paths not denied
        cmocka_unit_test(test_plutus_witness_payment_path_not_denied),
        cmocka_unit_test(test_plutus_witness_staking_path_not_denied),
        cmocka_unit_test(test_plutus_witness_multisig_payment_path_not_denied),
        cmocka_unit_test(test_plutus_witness_multisig_staking_path_not_denied),
        cmocka_unit_test(test_plutus_witness_drep_path_not_denied),
        cmocka_unit_test(test_plutus_witness_committee_cold_path_not_denied),
        cmocka_unit_test(test_plutus_witness_committee_hot_path_not_denied),
        cmocka_unit_test(test_plutus_witness_mint_path_not_denied_when_mint_present),
        cmocka_unit_test(test_plutus_witness_pool_cold_key_denied),
        cmocka_unit_test(test_unrestricted_witness_pool_cold_key_allowed),
        cmocka_unit_test(test_unrestricted_witness_mint_key_allowed_without_mint),
        // Swap witness: mode gating and path allowlist
        cmocka_unit_test(test_swap_witness_non_ordinary_mode_denied),
        cmocka_unit_test(test_swap_witness_staking_path_denied),
        cmocka_unit_test(test_swap_witness_multisig_payment_path_denied),
        cmocka_unit_test(test_swap_witness_pool_cold_key_denied),
        cmocka_unit_test(test_swap_witness_drep_path_denied),
        cmocka_unit_test(test_swap_witness_ordinary_payment_path_hidden),
        cmocka_unit_test(test_swap_witness_second_account_payment_path_denied),
        cmocka_unit_test(test_swap_witness_unusual_index_payment_path_denied),
        // CVote witness allowlist
        cmocka_unit_test(test_cvote_witness_cvote_key_allowed),
        cmocka_unit_test(test_cvote_witness_payment_path_denied),
        cmocka_unit_test(test_cvote_witness_staking_path_denied),
        cmocka_unit_test(test_cvote_witness_pool_cold_key_denied),
        // CVote vote key: KEY_PATH format gating
        cmocka_unit_test(test_cvote_vote_key_path_denied_for_cip15),
        cmocka_unit_test(test_cvote_vote_key_path_allowed_for_cip36),
        cmocka_unit_test(test_cvote_vote_key_raw_pubkey_allowed_for_cip15),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
