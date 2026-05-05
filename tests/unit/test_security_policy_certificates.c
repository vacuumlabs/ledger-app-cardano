/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "securityPolicy/securityPolicy.h"
#include "tx_credential_types.h"
#include "addressUtils/bip44.h"
#include "cardano_constants.h"
#include "globals.h"

extern bool unit_test_expert_mode_enabled;

static void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    unit_test_expert_mode_enabled = false;
}

static bip44_path_t make_ordinary_staking_path(void) {
    bip44_path_t path;
    memset(&path, 0, sizeof(path));
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(0);
    path.path[3] = 2;  // CARDANO_CHAIN_STAKING_KEY (not exported in headers)
    path.path[4] = 0;
    return path;
}

static bip44_path_t make_pool_cold_key_path(void) {
    bip44_path_t path;
    memset(&path, 0, sizeof(path));
    path.length = 4;
    path.path[0] = bip44_harden(PURPOSE_POOL_COLD_KEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(0);
    path.path[3] = bip44_harden(0);
    return path;
}

static bip44_path_t make_ordinary_staking_path_account_one(void) {
    bip44_path_t path;
    memset(&path, 0, sizeof(path));
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(1);
    path.path[3] = 2;  // CARDANO_CHAIN_STAKING_KEY
    path.path[4] = 0;
    return path;
}

static bip44_path_t make_ordinary_payment_path(void) {
    bip44_path_t path;
    memset(&path, 0, sizeof(path));
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(0);
    path.path[3] = 0;
    path.path[4] = 0;
    return path;
}

static ext_credential_t make_stake_credential(void) {
    ext_credential_t credential;
    memset(&credential, 0, sizeof(credential));
    credential.type = EXT_CREDENTIAL_KEY_PATH;
    credential.keyPath = make_ordinary_staking_path();
    return credential;
}

static ext_credential_t make_pool_cold_credential(void) {
    ext_credential_t credential;
    memset(&credential, 0, sizeof(credential));
    credential.type = EXT_CREDENTIAL_KEY_PATH;
    credential.keyPath = make_pool_cold_key_path();
    return credential;
}

static address_params_t make_standard_device_owned_base_output_params(void) {
    address_params_t params;
    memset(&params, 0, sizeof(params));
    params.type = BASE_PAYMENT_KEY_STAKE_KEY;
    params.networkId = MAINNET_NETWORK_ID;
    params.paymentPartType = PAYMENT_PART_KEY_PATH;
    params.paymentKeyPath = make_ordinary_payment_path();
    params.stakingPartType = STAKING_PART_KEY_PATH;
    params.stakingKeyPath = make_ordinary_staking_path();
    return params;
}

static void test_reward_key_third_party_output_denied(void **state) {
    (void) state;
    reset_context();

    static const uint8_t reward_key_address[] = {
        0xe0, 0xdb, 0x21, 0x9e, 0xe5, 0xce, 0x9a, 0x74, 0xf9, 0x8f, 0xda, 0xdc, 0x2d, 0xe1, 0x3e,
        0xfc, 0xed, 0x5a, 0x15, 0x4e, 0xf8, 0xd4, 0xd4, 0x19, 0x29, 0xd5, 0xbf, 0x9f, 0xf6,
    };
    tx_output_description_t output = {
        .format = ARRAY_LEGACY,
        .destination =
            {
                .type = DESTINATION_THIRD_PARTY,
                .address =
                    {
                        .buffer = reward_key_address,
                        .length = sizeof(reward_key_address),
                    },
            },
        .amount = 10,
        .numAssetGroups = 0,
        .includeDatum = false,
        .includeRefScript = false,
    };
    warning_bits_t w = 0;

    security_policy_t policy = policyForSignTxOutput(&output,
                                                     SIGN_TX_SIGNINGMODE_ORDINARY,
                                                     MAINNET_NETWORK_ID,
                                                     764824073,
                                                     &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_reward_script_third_party_output_denied(void **state) {
    (void) state;
    reset_context();

    static const uint8_t reward_script_address[] = {
        0xf0, 0x12, 0x2a, 0x94, 0x6b, 0x9a, 0xd3, 0xd2, 0xdd, 0xf0, 0x29, 0xd3, 0xa8, 0x28, 0xf0,
        0x46, 0x8a, 0xec, 0xe7, 0x68, 0x95, 0xf1, 0x5c, 0x9e, 0xfb, 0xd6, 0x9b, 0x42, 0x77,
    };
    tx_output_description_t output = {
        .format = ARRAY_LEGACY,
        .destination =
            {
                .type = DESTINATION_THIRD_PARTY,
                .address =
                    {
                        .buffer = reward_script_address,
                        .length = sizeof(reward_script_address),
                    },
            },
        .amount = 10,
        .numAssetGroups = 0,
        .includeDatum = false,
        .includeRefScript = false,
    };
    warning_bits_t w = 0;

    security_policy_t policy = policyForSignTxOutput(&output,
                                                     SIGN_TX_SIGNINGMODE_ORDINARY,
                                                     MAINNET_NETWORK_ID,
                                                     764824073,
                                                     &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_device_owned_output_denied_in_pool_registration_owner_mode(void **state) {
    (void) state;
    reset_context();

    tx_output_description_t output = {
        .format = ARRAY_LEGACY,
        .destination =
            {
                .type = DESTINATION_DEVICE_OWNED,
                .params = make_standard_device_owned_base_output_params(),
            },
        .amount = 10,
        .numAssetGroups = 0,
        .includeDatum = false,
        .includeRefScript = false,
    };
    warning_bits_t w = 0;

    security_policy_t policy = policyForSignTxOutput(&output,
                                                     SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER,
                                                     MAINNET_NETWORK_ID,
                                                     764824073,
                                                     &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_committee_hot_key_hash_voter_denied_in_ordinary_tx(void **state) {
    (void) state;
    reset_context();

    static const uint8_t committee_hot_key_hash[] = {
        0x7a, 0xfd, 0x02, 0x8b, 0x50, 0x4c, 0x36, 0x68, 0x10, 0x2b, 0x12, 0x9b, 0x37, 0xa8,
        0x6c, 0x09, 0xa2, 0x87, 0x2f, 0x76, 0x74, 0x1d, 0xc7, 0xa6, 0x8e, 0x21, 0x49, 0xc8,
    };
    ext_voter_t voter = {
        .type = EXT_VOTER_COMMITTEE_HOT_KEY_HASH,
        .keyHash = committee_hot_key_hash,
    };
    warning_bits_t w = 0;

    security_policy_t policy =
        policyForSignTxVotingProcedure(SIGN_TX_SIGNINGMODE_ORDINARY, &voter, &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_committee_hot_key_hash_voter_denied_in_multisig_tx(void **state) {
    (void) state;
    reset_context();

    static const uint8_t committee_hot_key_hash[] = {
        0x7a, 0xfd, 0x02, 0x8b, 0x50, 0x4c, 0x36, 0x68, 0x10, 0x2b, 0x12, 0x9b, 0x37, 0xa8,
        0x6c, 0x09, 0xa2, 0x87, 0x2f, 0x76, 0x74, 0x1d, 0xc7, 0xa6, 0x8e, 0x21, 0x49, 0xc8,
    };
    ext_voter_t voter = {
        .type = EXT_VOTER_COMMITTEE_HOT_KEY_HASH,
        .keyHash = committee_hot_key_hash,
    };
    warning_bits_t w = 0;

    security_policy_t policy =
        policyForSignTxVotingProcedure(SIGN_TX_SIGNINGMODE_MULTISIG, &voter, &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_stake_registration_denied_in_pool_registration_owner(void **state) {
    (void) state;
    reset_context();

    ext_credential_t stake_credential = make_stake_credential();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxCertificateStaking(SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER,
                                          CERTIFICATE_STAKE_REGISTRATION,
                                          &stake_credential,
                                          &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_stake_registration_denied_in_pool_registration_operator(void **state) {
    (void) state;
    reset_context();

    ext_credential_t stake_credential = make_stake_credential();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxCertificateStaking(SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR,
                                          CERTIFICATE_STAKE_REGISTRATION,
                                          &stake_credential,
                                          &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_pool_retirement_denied_in_multisig(void **state) {
    (void) state;
    reset_context();

    ext_credential_t pool_credential = make_pool_cold_credential();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxCertificateStakePoolRetirement(SIGN_TX_SIGNINGMODE_MULTISIG,
                                                      &pool_credential,
                                                      0,
                                                      &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_pool_retirement_denied_in_pool_registration_owner(void **state) {
    (void) state;
    reset_context();

    ext_credential_t pool_credential = make_pool_cold_credential();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxCertificateStakePoolRetirement(SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER,
                                                      &pool_credential,
                                                      0,
                                                      &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_pool_retirement_denied_in_pool_registration_operator(void **state) {
    (void) state;
    reset_context();

    ext_credential_t pool_credential = make_pool_cold_credential();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignTxCertificateStakePoolRetirement(
        SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR,
        &pool_credential,
        0,
        &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_pool_retirement_allowed_in_ordinary(void **state) {
    (void) state;
    reset_context();

    ext_credential_t pool_credential = make_pool_cold_credential();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxCertificateStakePoolRetirement(SIGN_TX_SIGNINGMODE_ORDINARY,
                                                      &pool_credential,
                                                      0,
                                                      &w);
    assert_int_equal(policy, POLICY_SHOW);
}

static void test_pool_retirement_allowed_in_plutus(void **state) {
    (void) state;
    reset_context();

    ext_credential_t pool_credential = make_pool_cold_credential();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxCertificateStakePoolRetirement(SIGN_TX_SIGNINGMODE_PLUTUS,
                                                      &pool_credential,
                                                      0,
                                                      &w);
    assert_int_equal(policy, POLICY_SHOW);
}

static void test_unrestricted_init_requires_expert_mode(void **state) {
    (void) state;
    reset_context();

    tx_params_t tx_params = {
        .txSigningMode = SIGN_TX_SIGNINGMODE_UNRESTRICTED,
        .networkId = MAINNET_NETWORK_ID,
        .protocolMagic = MAINNET_PROTOCOL_MAGIC,
        .num_inputs = 1,
    };
    warning_bits_t w = 0;

    unit_test_expert_mode_enabled = false;
    assert_int_equal(policyForSignTxInit(&tx_params, &w), POLICY_DENY);

    unit_test_expert_mode_enabled = true;
    w = 0;
    assert_int_equal(policyForSignTxInit(&tx_params, &w), POLICY_SHOW);
    assert_true(warning_bits_has(w, WARNING_BIT_UNRESTRICTED_SIGNING));
}

static void test_pool_retirement_allowed_in_unrestricted(void **state) {
    (void) state;
    reset_context();

    ext_credential_t pool_credential = make_pool_cold_credential();
    warning_bits_t w = 0;
    security_policy_t policy =
        policyForSignTxCertificateStakePoolRetirement(SIGN_TX_SIGNINGMODE_UNRESTRICTED,
                                                      &pool_credential,
                                                      0,
                                                      &w);
    assert_int_equal(policy, POLICY_SHOW);
}

static void test_pool_registration_denied_in_unrestricted(void **state) {
    (void) state;
    reset_context();

    warning_bits_t w = 0;
    security_policy_t policy = policyForSignTxStakePoolRegistrationInit(
        SIGN_TX_SIGNINGMODE_UNRESTRICTED,
        1,
        1,
        0,
        &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_stake_pool_key_hash_voter_allowed_in_unrestricted(void **state) {
    (void) state;
    reset_context();

    static const uint8_t stake_pool_key_hash[ADDRESS_KEY_HASH_LENGTH] = {0};
    ext_voter_t voter = {
        .type = EXT_VOTER_STAKE_POOL_KEY_HASH,
        .keyHash = stake_pool_key_hash,
    };
    warning_bits_t w = 0;

    security_policy_t policy =
        policyForSignTxVotingProcedure(SIGN_TX_SIGNINGMODE_UNRESTRICTED, &voter, &w);
    assert_int_equal(policy, POLICY_SHOW);
}

static void test_stake_pool_key_path_voter_allowed_in_unrestricted(void **state) {
    (void) state;
    reset_context();

    ext_voter_t voter = {
        .type = EXT_VOTER_STAKE_POOL_KEY_PATH,
        .keyPath = make_pool_cold_key_path(),
    };
    warning_bits_t w = 0;

    security_policy_t policy =
        policyForSignTxVotingProcedure(SIGN_TX_SIGNINGMODE_UNRESTRICTED, &voter, &w);
    assert_int_equal(policy, POLICY_SHOW);
}

static void test_pool_cold_required_signer_allowed_in_unrestricted(void **state) {
    (void) state;
    reset_context();

    required_signer_t required_signer = {
        .type = REQUIRED_SIGNER_WITH_PATH,
        .keyPath = make_pool_cold_key_path(),
    };
    warning_bits_t w = 0;

    security_policy_t policy =
        policyForSignTxRequiredSigner(SIGN_TX_SIGNINGMODE_UNRESTRICTED, &required_signer, &w);
    assert_int_equal(policy, POLICY_SHOW);
}

static void test_pool_registration_reward_account_path_compatibility(void **state) {
    (void) state;
    reset_context();

    pool_reward_account_t reward_account;
    memset(&reward_account, 0, sizeof(reward_account));
    reward_account.keyReferenceType = KEY_REFERENCE_PATH;
    reward_account.path = make_ordinary_staking_path_account_one();

    warning_bits_t w = 0;
    security_policy_t policy = policyForSignTxStakePoolRegistrationRewardAccount(
        SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER,
        MAINNET_NETWORK_ID,
        &reward_account,
        &w);
    assert_int_equal(policy, POLICY_SHOW);
}

// ======================================================================
// combine_security_policies: exhaustive combination matrix
// ======================================================================

static void test_combine_security_policies_all_combinations(void **state) {
    (void) state;
    // DENY dominates: any DENY input yields DENY
    assert_int_equal(combine_security_policies(POLICY_DENY, POLICY_DENY), POLICY_DENY);
    assert_int_equal(combine_security_policies(POLICY_DENY, POLICY_SHOW), POLICY_DENY);
    assert_int_equal(combine_security_policies(POLICY_DENY, POLICY_HIDE), POLICY_DENY);
    assert_int_equal(combine_security_policies(POLICY_SHOW, POLICY_DENY), POLICY_DENY);
    assert_int_equal(combine_security_policies(POLICY_HIDE, POLICY_DENY), POLICY_DENY);
    // SHOW dominates over HIDE
    assert_int_equal(combine_security_policies(POLICY_SHOW, POLICY_SHOW), POLICY_SHOW);
    assert_int_equal(combine_security_policies(POLICY_SHOW, POLICY_HIDE), POLICY_SHOW);
    assert_int_equal(combine_security_policies(POLICY_HIDE, POLICY_SHOW), POLICY_SHOW);
    // HIDE only when both are HIDE
    assert_int_equal(combine_security_policies(POLICY_HIDE, POLICY_HIDE), POLICY_HIDE);
}

static void test_pool_registration_owner_with_script_hash_denied(void **state) {
    (void) state;
    reset_context();

    // Hand-crafted test case to cover policy branch that is normally unreachable
    // from ragger tests because the CommandBuilder does not allow invalid values for that enum
    // (and specifically does not support script hash for pool owners).
    static const uint8_t script_hash[] = {
        0x29, 0xfb, 0x5f, 0xd4, 0xaa, 0x8c, 0xad, 0xd6, 0x70, 0x5a, 0xcc, 0x82, 0x63, 0xce,
        0xe0, 0xfc, 0x62, 0xed, 0xca, 0x5a, 0xc3, 0x8d, 0xb5, 0x93, 0xfe, 0xc2, 0xf9, 0xfd,
    };
    ext_credential_t owner_credential = {
        .type = EXT_CREDENTIAL_SCRIPT_HASH,
        .scriptHash = script_hash,
    };
    warning_bits_t w = 0;

    security_policy_t policy =
        policyForSignTxStakePoolRegistrationOwner(SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR,
                                                  &owner_credential,
                                                  &w);
    assert_int_equal(policy, POLICY_DENY);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_reward_key_third_party_output_denied),
        cmocka_unit_test(test_reward_script_third_party_output_denied),
        cmocka_unit_test(test_device_owned_output_denied_in_pool_registration_owner_mode),
        cmocka_unit_test(test_committee_hot_key_hash_voter_denied_in_ordinary_tx),
        cmocka_unit_test(test_committee_hot_key_hash_voter_denied_in_multisig_tx),
        cmocka_unit_test(test_stake_registration_denied_in_pool_registration_owner),
        cmocka_unit_test(test_stake_registration_denied_in_pool_registration_operator),
        cmocka_unit_test(test_pool_retirement_denied_in_multisig),
        cmocka_unit_test(test_pool_retirement_denied_in_pool_registration_owner),
        cmocka_unit_test(test_pool_retirement_denied_in_pool_registration_operator),
        cmocka_unit_test(test_pool_retirement_allowed_in_ordinary),
        cmocka_unit_test(test_pool_retirement_allowed_in_plutus),
        cmocka_unit_test(test_unrestricted_init_requires_expert_mode),
        cmocka_unit_test(test_pool_retirement_allowed_in_unrestricted),
        cmocka_unit_test(test_pool_registration_denied_in_unrestricted),
        cmocka_unit_test(test_stake_pool_key_hash_voter_allowed_in_unrestricted),
        cmocka_unit_test(test_stake_pool_key_path_voter_allowed_in_unrestricted),
        cmocka_unit_test(test_pool_cold_required_signer_allowed_in_unrestricted),
        cmocka_unit_test(test_pool_registration_reward_account_path_compatibility),
        cmocka_unit_test(test_pool_registration_owner_with_script_hash_denied),
        cmocka_unit_test(test_combine_security_policies_all_combinations),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
