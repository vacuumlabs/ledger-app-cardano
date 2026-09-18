/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "cardano_constants.h"
#include "addressUtils/addressUtilsShelley.h"
#include "addressUtils/bip44.h"
#include "swap.h"

#define HD                 HARDENED_BIP32
#define MAX_ADDRESS_LENGTH 128

// Packed wire format: 1 length byte, then length * 4 big-endian path components.
static uint8_t build_packed_path(uint8_t *out, const uint32_t *elements, uint8_t length) {
    out[0] = length;
    for (uint8_t i = 0; i < length; i++) {
        out[1 + i * 4 + 0] = (uint8_t) (elements[i] >> 24);
        out[1 + i * 4 + 1] = (uint8_t) (elements[i] >> 16);
        out[1 + i * 4 + 2] = (uint8_t) (elements[i] >> 8);
        out[1 + i * 4 + 3] = (uint8_t) (elements[i]);
    }
    return (uint8_t) (1 + length * 4);
}

// Reproduce the address swap_handle_check_address derives for a payment path
static void derive_expected_address(const uint32_t *payment_path, char *out, size_t out_size) {
    address_params_t params = {0};
    params.type = BASE_PAYMENT_KEY_STAKE_KEY;
    params.networkId = MAINNET_NETWORK_ID;
    params.paymentPartType = PAYMENT_PART_KEY_PATH;
    params.paymentKeyPath.length = 5;
    memcpy(params.paymentKeyPath.path, payment_path, 5 * sizeof(uint32_t));
    params.stakingPartType = STAKING_PART_KEY_PATH;
    params.stakingKeyPath = params.paymentKeyPath;
    params.stakingKeyPath.path[BIP44_I_CHAIN] = 2;
    params.stakingKeyPath.path[BIP44_I_ADDRESS] = 0;

    uint8_t raw[MAX_ADDRESS_LENGTH] = {0};
    size_t raw_len = deriveAddress(&params, raw, sizeof(raw));
    assert_true(format_address_human_readable(raw, raw_len, out, out_size));
}

static void test_null_address_parameters(void **state) {
    (void) state;
    char address[MAX_HUMAN_ADDRESS_LENGTH] = "addr1anything";
    check_address_parameters_t params = {0};
    params.address_parameters = NULL;
    params.address_to_check = address;
    params.result = 1;
    swap_handle_check_address(&params);
    assert_int_equal(params.result, 0);
}

static void test_null_address_to_check(void **state) {
    (void) state;
    const uint32_t path[] = {HD + PURPOSE_SHELLEY, HD + ADA_COIN_TYPE, HD + 0, 0, 1};
    uint8_t packed[64] = {0};
    uint8_t packed_len = build_packed_path(packed, path, 5);
    check_address_parameters_t params = {0};
    params.address_parameters = packed;
    params.address_parameters_length = packed_len;
    params.address_to_check = NULL;
    params.result = 1;
    swap_handle_check_address(&params);
    assert_int_equal(params.result, 0);
}

static void test_bad_bip44_path(void **state) {
    (void) state;
    // Claims 5 components but supplies only 2 payload bytes -> parse fails.
    uint8_t packed[3] = {0x05, 0x00, 0x00};
    char address[MAX_HUMAN_ADDRESS_LENGTH] = "addr1anything";
    check_address_parameters_t params = {0};
    params.address_parameters = packed;
    params.address_parameters_length = sizeof(packed);
    params.address_to_check = address;
    params.result = 1;
    swap_handle_check_address(&params);
    assert_int_equal(params.result, 0);
}

static void test_trailing_bytes_after_path(void **state) {
    (void) state;
    const uint32_t path[] = {HD + PURPOSE_SHELLEY, HD + ADA_COIN_TYPE, HD + 0, 0, 1};
    uint8_t packed[64] = {0};
    uint8_t packed_len = build_packed_path(packed, path, 5);
    packed[packed_len] = 0xAA;  // one extra byte
    char address[MAX_HUMAN_ADDRESS_LENGTH] = "addr1anything";
    check_address_parameters_t params = {0};
    params.address_parameters = packed;
    params.address_parameters_length = (uint8_t) (packed_len + 1);
    params.address_to_check = address;
    params.result = 1;
    swap_handle_check_address(&params);
    assert_int_equal(params.result, 0);
}

static void test_valid_shelley_match(void **state) {
    (void) state;
    const uint32_t path[] = {HD + PURPOSE_SHELLEY, HD + ADA_COIN_TYPE, HD + 0, 0, 1};
    uint8_t packed[64] = {0};
    uint8_t packed_len = build_packed_path(packed, path, 5);
    char expected[MAX_HUMAN_ADDRESS_LENGTH] = {0};
    derive_expected_address(path, expected, sizeof(expected));
    check_address_parameters_t params = {0};
    params.address_parameters = packed;
    params.address_parameters_length = packed_len;
    params.address_to_check = expected;
    params.result = 0;
    swap_handle_check_address(&params);
    assert_int_equal(params.result, 1);
}

static void test_address_mismatch(void **state) {
    (void) state;
    const uint32_t path[] = {HD + PURPOSE_SHELLEY, HD + ADA_COIN_TYPE, HD + 0, 0, 1};
    uint8_t packed[64] = {0};
    uint8_t packed_len = build_packed_path(packed, path, 5);
    // Valid path, but a non-matching address string.
    char wrong[MAX_HUMAN_ADDRESS_LENGTH] = "addr1notthisdevice";
    check_address_parameters_t params = {0};
    params.address_parameters = packed;
    params.address_parameters_length = packed_len;
    params.address_to_check = wrong;
    params.result = 1;
    swap_handle_check_address(&params);
    assert_int_equal(params.result, 0);
}

static void test_non_shelley_prefix_rejected(void **state) {
    (void) state;
    // Byron purpose (44') fails bip44_hasShelleyPrefix.
    const uint32_t byron_path[] = {HD + PURPOSE_BYRON, HD + ADA_COIN_TYPE, HD + 0, 0, 1};
    uint8_t packed[64] = {0};
    uint8_t packed_len = build_packed_path(packed, byron_path, 5);
    char address[MAX_HUMAN_ADDRESS_LENGTH] = "addr1anything";
    check_address_parameters_t params = {0};
    params.address_parameters = packed;
    params.address_parameters_length = packed_len;
    params.address_to_check = address;
    params.result = 1;
    swap_handle_check_address(&params);
    assert_int_equal(params.result, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_null_address_parameters),
        cmocka_unit_test(test_null_address_to_check),
        cmocka_unit_test(test_bad_bip44_path),
        cmocka_unit_test(test_trailing_bytes_after_path),
        cmocka_unit_test(test_valid_shelley_match),
        cmocka_unit_test(test_address_mismatch),
        cmocka_unit_test(test_non_shelley_prefix_rejected),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
