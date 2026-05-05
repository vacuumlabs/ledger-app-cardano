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
#include "addressUtilsShelley.h"
#include "addressUtils/bip44.h"
#include "transaction/tx_output_types.h"
#include "transaction/tx_parse_outputs.h"
#include "cardano_constants.h"
#include "globals.h"

extern bool unit_test_expert_mode_enabled;

static void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
}

static bip44_path_t make_payment_path(uint32_t account, uint32_t index) {
    bip44_path_t path = {0};
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    path.path[3] = 0;
    path.path[4] = index;
    return path;
}

static bip44_path_t make_staking_path(uint32_t account, uint32_t index) {
    bip44_path_t path = {0};
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    path.path[3] = 2;
    path.path[4] = index;
    return path;
}

static void init_standard_device_owned_address_params(address_params_t *params) {
    assert_non_null(params);
    memset(params, 0, sizeof(*params));

    params->type = BASE_PAYMENT_KEY_STAKE_KEY;
    params->networkId = MAINNET_NETWORK_ID;
    params->paymentPartType = PAYMENT_PART_KEY_PATH;
    params->paymentKeyPath = make_payment_path(0, 0);
    params->stakingPartType = STAKING_PART_KEY_PATH;
    params->stakingKeyPath = make_staking_path(0, 0);
}

static void init_third_party_enterprise_address(uint8_t *address, size_t address_size) {
    assert_non_null(address);
    assert_int_equal(address_size, 1 + ADDRESS_KEY_HASH_LENGTH);

    memset(address, 0, address_size);
    address[0] = constructShelleyAddressHeader(ENTERPRISE_KEY, MAINNET_NETWORK_ID);
    for (size_t i = 1; i < address_size; i++) {
        address[i] = (uint8_t) i;
    }
}

static tx_output_description_t make_collateral_output_description_device_owned(
    uint16_t num_asset_groups) {
    static address_params_t params;
    init_standard_device_owned_address_params(&params);

    tx_output_description_t output = {
        .destination = tx_output_destination_make_device_owned(&params),
        .amount = 1,
        .numAssetGroups = num_asset_groups,
        .includeDatum = false,
        .includeRefScript = false,
        .format = ARRAY_LEGACY,
    };
    return output;
}

static tx_output_description_t make_collateral_output_description_third_party(
    uint16_t num_asset_groups) {
    static uint8_t address[1 + ADDRESS_KEY_HASH_LENGTH];
    init_third_party_enterprise_address(address, SIZEOF(address));

    tx_output_description_t output = {
        .destination = tx_output_destination_make_third_party(address, SIZEOF(address)),
        .amount = 1,
        .numAssetGroups = num_asset_groups,
        .includeDatum = false,
        .includeRefScript = false,
        .format = ARRAY_LEGACY,
    };
    return output;
}

static void test_collateral_output_top_level_policy_device_owned(void **state) {
    (void) state;
    reset_context();

    tx_output_description_t output = make_collateral_output_description_device_owned(0);
    warning_bits_t w = 0;

    security_policy_t policy_without_total =
        policyForSignTxCollateralOutputAddress(&output,
                                               SIGN_TX_SIGNINGMODE_PLUTUS,
                                               MAINNET_NETWORK_ID,
                                               MAINNET_PROTOCOL_MAGIC,
                                               false,
                                               &w);
    assert_int_equal(policy_without_total, POLICY_SHOW);

    security_policy_t policy_with_total =
        policyForSignTxCollateralOutputAddress(&output,
                                               SIGN_TX_SIGNINGMODE_PLUTUS,
                                               MAINNET_NETWORK_ID,
                                               MAINNET_PROTOCOL_MAGIC,
                                               true,
                                               &w);
    assert_int_equal(policy_with_total, POLICY_HIDE);
}

static void test_collateral_output_top_level_policy_third_party(void **state) {
    (void) state;
    reset_context();

    tx_output_description_t output = make_collateral_output_description_third_party(0);
    warning_bits_t w = 0;

    security_policy_t policy_without_total =
        policyForSignTxCollateralOutputAddress(&output,
                                               SIGN_TX_SIGNINGMODE_PLUTUS,
                                               MAINNET_NETWORK_ID,
                                               MAINNET_PROTOCOL_MAGIC,
                                               false,
                                               &w);
    assert_int_equal(policy_without_total, POLICY_SHOW);

    security_policy_t policy_with_total =
        policyForSignTxCollateralOutputAddress(&output,
                                               SIGN_TX_SIGNINGMODE_PLUTUS,
                                               MAINNET_NETWORK_ID,
                                               MAINNET_PROTOCOL_MAGIC,
                                               true,
                                               &w);
    assert_int_equal(policy_with_total, POLICY_SHOW);
}

static void test_collateral_output_subpolicy_matrix(void **state) {
    (void) state;
    reset_context();

    const bool expert_modes[] = {false, true};
    const bool total_collateral_present_modes[] = {false, true};
    const bool device_owned_modes[] = {false, true};
    const uint16_t asset_group_counts[] = {0, 1};

    for (size_t expert_mode_index = 0; expert_mode_index < ARRAY_LEN(expert_modes);
         expert_mode_index++) {
        unit_test_expert_mode_enabled = expert_modes[expert_mode_index];

        for (size_t total_collateral_index = 0;
             total_collateral_index < ARRAY_LEN(total_collateral_present_modes);
             total_collateral_index++) {
            const bool total_collateral_present =
                total_collateral_present_modes[total_collateral_index];

            for (size_t device_owned_index = 0; device_owned_index < ARRAY_LEN(device_owned_modes);
                 device_owned_index++) {
                const bool device_owned = device_owned_modes[device_owned_index];

                for (size_t asset_groups_index = 0;
                     asset_groups_index < ARRAY_LEN(asset_group_counts);
                     asset_groups_index++) {
                    const uint16_t num_asset_groups = asset_group_counts[asset_groups_index];

                    tx_output_description_t output =
                        device_owned
                            ? make_collateral_output_description_device_owned(num_asset_groups)
                            : make_collateral_output_description_third_party(num_asset_groups);
                    warning_bits_t w = 0;

                    security_policy_t top_level_policy =
                        policyForSignTxCollateralOutputAddress(&output,
                                                               SIGN_TX_SIGNINGMODE_PLUTUS,
                                                               MAINNET_NETWORK_ID,
                                                               MAINNET_PROTOCOL_MAGIC,
                                                               total_collateral_present,
                                                               &w);
                    assert_true(top_level_policy == POLICY_SHOW || top_level_policy == POLICY_HIDE);

                    security_policy_t ada_policy =
                        policyForSignTxCollateralOutputAdaAmount(top_level_policy,
                                                                 SIGN_TX_SIGNINGMODE_PLUTUS,
                                                                 total_collateral_present,
                                                                 &w);
                    security_policy_t tokens_policy =
                        policyForSignTxCollateralOutputTokens(top_level_policy,
                                                              SIGN_TX_SIGNINGMODE_PLUTUS,
                                                              &output,
                                                              &w);

                    if (top_level_policy == POLICY_HIDE) {
                        assert_int_equal(ada_policy, POLICY_HIDE);
                        assert_int_equal(tokens_policy, POLICY_HIDE);
                        continue;
                    }

                    const security_policy_t expected_ada_policy =
                        (!total_collateral_present && unit_test_expert_mode_enabled) ? POLICY_SHOW
                                                                                     : POLICY_HIDE;
                    assert_int_equal(ada_policy, expected_ada_policy);

                    const bool loss_of_control =
                        (output.destination.type == DESTINATION_THIRD_PARTY);
                    const security_policy_t expected_tokens_policy =
                        (loss_of_control && unit_test_expert_mode_enabled) ? POLICY_SHOW
                                                                           : POLICY_HIDE;
                    assert_int_equal(tokens_policy, expected_tokens_policy);
                }
            }
        }
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_collateral_output_top_level_policy_device_owned),
        cmocka_unit_test(test_collateral_output_top_level_policy_third_party),
        cmocka_unit_test(test_collateral_output_subpolicy_matrix),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
