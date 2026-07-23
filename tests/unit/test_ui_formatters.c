/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#include <cmocka.h>

#include "ui_formatters.h"
#include "hexUtils.h"
#include "cardano_constants.h"
#include "bech32_cardano.h"
static void test_format_hex_bytes(void **state) {
    (void) state;

    const uint8_t input[] = {0x00, 0xab, 0xcd};
    char out[10] = {0};

    bool success = format_hex_bytes(input, sizeof(input), out, sizeof(out));
    assert_true(success);
    assert_string_equal(out, "00abcd");
}

static void test_format_uint64(void **state) {
    (void) state;

    struct {
        uint64_t number;
        const char *expected;
    } testVectors[] = {
        {0, "0"},
        {1, "1"},
        {4924800, "4924800"},
        {4924799, "4924799"},
        {(uint64_t) (-1ll), "18446744073709551615"},  // Max uint64
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        char tmp[100] = {0};
        explicit_bzero(tmp, sizeof(tmp));
        bool success = format_uint64(testVectors[i].number, tmp, sizeof(tmp));
        assert_true(success);
        assert_string_equal(tmp, testVectors[i].expected);
    }
}

static void test_format_decimal_amount(void **state) {
    (void) state;

    struct {
        uint64_t amount;
        size_t places;
        const char *expected;
    } testVectors[] = {
        {0, 0, "0"},
        {0, 4, "0.0000"},
        {1, 8, "0.00000001"},
        {10, 8, "0.00000010"},
        {123456, 4, "12.3456"},
        {1000000, 3, "1,000.000"},
        {12345678901234567890u, 12, "12,345,678.901234567890"},
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        char tmp[100] = {0};
        bool success =
            format_decimal_amount(testVectors[i].amount, testVectors[i].places, tmp, sizeof(tmp));
        assert_true(success);
        size_t len = strlen(tmp);
        assert_int_equal(len, strlen(testVectors[i].expected));
        assert_string_equal(tmp, testVectors[i].expected);
    }
}

static void test_format_ada_amount(void **state) {
    (void) state;

    struct {
        uint64_t amount;
        const char *expected;
    } testVectors[] = {
        {0, "0.000000 ADA"},
        {1, "0.000001 ADA"},
        {10, "0.000010 ADA"},
        {123456, "0.123456 ADA"},
        {1000000, "1.000000 ADA"},
        {12345678901234567890u, "12,345,678,901,234.567890 ADA"},
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        char tmp[100] = {0};
        bool success = format_ada_amount(testVectors[i].amount, tmp, sizeof(tmp));
        assert_true(success);
        size_t len = strlen(tmp);
        assert_int_equal(len, strlen(testVectors[i].expected));
        assert_string_equal(tmp, testVectors[i].expected);
    }
}

static void test_format_validity_boundary(void **state) {
    (void) state;

    // Mainnet uses epoch/slot formatting
    {
        char tmp[100] = {0};
        bool success = format_validity_boundary(4492800,
                                                MAINNET_NETWORK_ID,
                                                MAINNET_PROTOCOL_MAGIC,
                                                tmp,
                                                sizeof(tmp));
        assert_true(success);
        assert_string_equal(tmp, "epoch 208 / slot 0");
    }

    // Testnet uses raw slot formatting
    {
        char tmp[100] = {0};
        bool success = format_validity_boundary(12345,
                                                TESTNET_NETWORK_ID,
                                                TESTNET_PROTOCOL_MAGIC_LEGACY,
                                                tmp,
                                                sizeof(tmp));
        assert_true(success);
        assert_string_equal(tmp, "12345");
    }

    // Mainnet with wrong protocol magic uses raw slot formatting
    {
        char tmp[100] = {0};
        bool success = format_validity_boundary(12345,
                                                MAINNET_NETWORK_ID,
                                                TESTNET_PROTOCOL_MAGIC_LEGACY,
                                                tmp,
                                                sizeof(tmp));
        assert_true(success);
        assert_string_equal(tmp, "12345");
    }

    // Mainnet boundary with large slots (epoch over limit)
    {
        char tmp[100] = {0};
        bool success = format_validity_boundary(1000001llu * 432000 + 124,
                                                MAINNET_NETWORK_ID,
                                                MAINNET_PROTOCOL_MAGIC,
                                                tmp,
                                                sizeof(tmp));
        assert_true(success);
        assert_string_equal(tmp, "epoch > 1000000");
    }
}

static void test_format_pool_margin(void **state) {
    (void) state;

    struct {
        uint64_t numerator;
        uint64_t denominator;
        const char *expected;
    } testVectors[] = {
        {500, 10000, "5.00 %"},
        {123, 10000, "1.23 %"},
        {1, 3, "33.33 %"},
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        char tmp[20] = {0};
        bool success = format_pool_margin(testVectors[i].numerator,
                                          testVectors[i].denominator,
                                          tmp,
                                          sizeof(tmp));
        assert_true(success);
        assert_string_equal(tmp, testVectors[i].expected);
    }
}

static void test_format_uint16(void **state) {
    (void) state;

    struct {
        uint16_t value;
        const char *expected;
    } testVectors[] = {
        {0, "0"},
        {65535, "65535"},
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        char tmp[20] = {0};
        bool success = format_uint16(testVectors[i].value, tmp, sizeof(tmp));
        assert_true(success);
        assert_string_equal(tmp, testVectors[i].expected);
    }
}

static void test_format_index_with_prefix(void **state) {
    (void) state;

    char tmp[20] = {0};
    bool success = format_index_with_prefix(0, tmp, sizeof(tmp));
    assert_true(success);
    assert_string_equal(tmp, "#0");

    memset(tmp, 0, sizeof(tmp));
    success = format_index_with_prefix(42, tmp, sizeof(tmp));
    assert_true(success);
    assert_string_equal(tmp, "#42");
}

static void test_format_vote_option(void **state) {
    (void) state;

    char tmp[20] = {0};
    bool success = format_vote_option(VOTE_NO, tmp, sizeof(tmp));
    assert_true(success);
    assert_string_equal(tmp, "No");

    memset(tmp, 0, sizeof(tmp));
    success = format_vote_option(VOTE_YES, tmp, sizeof(tmp));
    assert_true(success);
    assert_string_equal(tmp, "Yes");

    memset(tmp, 0, sizeof(tmp));
    success = format_vote_option(VOTE_ABSTAIN, tmp, sizeof(tmp));
    assert_true(success);
    assert_string_equal(tmp, "Abstain");
}

static void test_format_constant_drep(void **state) {
    (void) state;

    char tmp[40] = {0};
    bool success = format_constant_drep(EXT_DREP_ABSTAIN, tmp, sizeof(tmp));
    assert_true(success);
    assert_string_equal(tmp, "Abstain");

    memset(tmp, 0, sizeof(tmp));
    success = format_constant_drep(EXT_DREP_NO_CONFIDENCE, tmp, sizeof(tmp));
    assert_true(success);
    assert_string_equal(tmp, "No Confidence");
}

static void test_format_certificate_type(void **state) {
    (void) state;

    char tmp[40] = {0};
    bool success = format_certificate_type(CERTIFICATE_STAKE_REGISTRATION, tmp, sizeof(tmp));
    assert_true(success);
    assert_string_equal(tmp, "Stake Registration");

    memset(tmp, 0, sizeof(tmp));
    success = format_certificate_type(CERTIFICATE_STAKE_POOL_REGISTRATION, tmp, sizeof(tmp));
    assert_true(success);
    assert_string_equal(tmp, "Pool Registration");

    memset(tmp, 0, sizeof(tmp));
    success = format_certificate_type(CERTIFICATE_DREP_UPDATE, tmp, sizeof(tmp));
    assert_true(success);
    assert_string_equal(tmp, "DRep Update");
}

static void test_format_url(void **state) {
    (void) state;

    const uint8_t url[] = "example.com";
    char tmp[32] = {0};
    bool success = format_url(url, strlen((const char *) url), tmp, sizeof(tmp));
    assert_true(success);
    assert_string_equal(tmp, "example.com");

    char too_small[5] = {0};
    success = format_url(url, strlen((const char *) url), too_small, sizeof(too_small));
    assert_false(success);
}

static void test_format_dns_name(void **state) {
    (void) state;

    const uint8_t dns_name[] = "relay.example.com";
    char tmp[32] = {0};
    bool success = format_dns_name(dns_name, strlen((const char *) dns_name), tmp, sizeof(tmp));
    assert_true(success);
    assert_string_equal(tmp, "relay.example.com");

    // Buffer exactly dnsLength+1 — no room for null terminator
    char exact[18] = {0};  // "relay.example.com" is 17 chars, +1 = 18, so 18 >= 17+1 → should fail
    success = format_dns_name(dns_name, strlen((const char *) dns_name), exact, sizeof(exact));
    assert_false(success);

    // Buffer one byte too small
    char too_small[17] = {0};
    success =
        format_dns_name(dns_name, strlen((const char *) dns_name), too_small, sizeof(too_small));
    assert_false(success);
}

static void test_format_decimal_amount_buffer_too_small(void **state) {
    (void) state;

    char buf[2] = {0};
    // "0" requires 2 bytes (char + null); outSize=1 is too small
    bool success = format_decimal_amount(0, 0, buf, 1);
    assert_false(success);

    // "1,000" requires 6 bytes; outSize=5 is too small
    char buf2[6] = {0};
    success = format_decimal_amount(1000, 0, buf2, 5);
    assert_false(success);
}

static void test_format_input_with_index_buffer_too_small(void **state) {
    (void) state;

    const uint8_t hash[TX_HASH_LENGTH] = {
        0x3b, 0x40, 0x26, 0x51, 0x11, 0xd8, 0xbb, 0x3c, 0x3c, 0x60, 0x8d,
        0x95, 0xb3, 0xa0, 0xbf, 0x83, 0x46, 0x1a, 0xce, 0x32, 0xd7, 0x93,
        0x36, 0x57, 0x9a, 0x19, 0x39, 0xb3, 0xaa, 0xd1, 0xc0, 0xb7,
    };
    const tx_input_t input = {.txHash = hash, .index = 0};

    // Buffer too small for hex conversion: TX_HASH_LENGTH*2+1 = 65 bytes needed
    char buf_hex_fail[64] = {0};
    bool success = format_input_with_index(&input, buf_hex_fail, sizeof(buf_hex_fail));
    assert_false(success);

    // Buffer exactly 65 bytes: hex fits but no room for " / 0"
    char buf_suffix_fail[65] = {0};
    success = format_input_with_index(&input, buf_suffix_fail, sizeof(buf_suffix_fail));
    assert_false(success);

    // Buffer large enough: should succeed
    char buf_ok[100] = {0};
    success = format_input_with_index(&input, buf_ok, sizeof(buf_ok));
    assert_true(success);
}

static void test_format_asset_fingerprint_bech32(void **state) {
    (void) state;

    struct {
        const char *policyIdHex;
        const char *assetNameHex;
        const char *expectedBech32;
    } testVectors[] = {
        // Test vectors from CIP 14 proposal
        {"7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
         "",
         "asset1rjklcrnsdzqp65wjgrg55sy9723kw09mlgvlc3"},

        {"1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209",
         "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
         "asset1aqrdypg669jgazruv5ah07nuyqe0wxjhe2el6f"},

        {"1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209",
         "504154415445",
         "asset1hv4p5tv2a837mzqrst04d0dcptdjmluqvdx9k3"},

        {"7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
         "0000000000000000000000000000000000000000000000000000000000000000",
         "asset1pkpwyknlvul7az0xx8czhl60pyel45rpje4z8w"},
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        uint8_t policyId[MINTING_POLICY_ID_LENGTH] = {0};
        size_t policyIdSize = 0;
        bool success_policy =
            decode_hex(testVectors[i].policyIdHex, policyId, sizeof(policyId), &policyIdSize);
        assert_true(success_policy);
        assert_int_equal(policyIdSize, MINTING_POLICY_ID_LENGTH);

        uint8_t assetName[MAX_ASSET_NAME_LENGTH] = {0};
        size_t assetNameSize = 0;
        bool success =
            decode_hex(testVectors[i].assetNameHex, assetName, sizeof(assetName), &assetNameSize);
        assert_true(success);

        char fingerprint[200] = {0};
        success = format_asset_fingerprint_bech32(policyId,
                                                  assetName,
                                                  assetNameSize,
                                                  fingerprint,
                                                  sizeof(fingerprint));
        assert_true(success);
        assert_string_equal(fingerprint, testVectors[i].expectedBech32);
    }
}

static void test_format_governance_identifier(void **state) {
    (void) state;

    struct {
        uint8_t headerByte;
        const char *bech32Prefix;
        size_t expectedHashLength;
        const char *credentialHashHex;
        const char *expectedBech32;
    } testVectors[] = {
        // Test vectors from CIP-0129
        {0x02,
         BECH32_PREFIX_COMMITTEE_HOT,
         ADDRESS_KEY_HASH_LENGTH,
         "00000000000000000000000000000000000000000000000000000000",
         "cc_hot1qgqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqvcdjk7"},

        {0x13,
         BECH32_PREFIX_COMMITTEE_COLD,
         SCRIPT_HASH_LENGTH,
         "00000000000000000000000000000000000000000000000000000000",
         "cc_cold1zvqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6kflvs"},

        {0x22,
         BECH32_PREFIX_DREP,
         ADDRESS_KEY_HASH_LENGTH,
         "00000000000000000000000000000000000000000000000000000000",
         "drep1ygqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq7vlc9n"},
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        uint8_t credentialHash[SCRIPT_HASH_LENGTH] = {0};
        size_t credentialHashSize = 0;
        bool success_hash = decode_hex(testVectors[i].credentialHashHex,
                                       credentialHash,
                                       sizeof(credentialHash),
                                       &credentialHashSize);
        assert_true(success_hash);
        assert_int_equal(credentialHashSize, testVectors[i].expectedHashLength);

        char identifier[200] = {0};
        bool success = format_governance_identifier(testVectors[i].bech32Prefix,
                                                    testVectors[i].headerByte,
                                                    credentialHash,
                                                    credentialHashSize,
                                                    identifier,
                                                    sizeof(identifier));
        assert_true(success);
        assert_string_equal(identifier, testVectors[i].expectedBech32);
    }
}

static void test_format_governance_action_id(void **state) {
    (void) state;

    struct {
        const char *txHashHex;
        uint32_t govActionIndex;
        const char *expectedBech32;
    } testVectors[] = {
        // Test vectors from CIP-0129
        {"0000000000000000000000000000000000000000000000000000000000000000",
         17,
         "gov_action1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpzklpgpf"},

        {"1111111111111111111111111111111111111111111111111111111111111111",
         0,
         "gov_action1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsq6dmejn"},
    };

    for (size_t i = 0; i < sizeof(testVectors) / sizeof(testVectors[0]); i++) {
        uint8_t txHash[TX_HASH_LENGTH] = {0};
        size_t txHashSize = 0;
        bool success_hash =
            decode_hex(testVectors[i].txHashHex, txHash, sizeof(txHash), &txHashSize);
        assert_true(success_hash);
        assert_int_equal(txHashSize, TX_HASH_LENGTH);

        char identifier[200] = {0};
        bool success = format_governance_action_id(txHash,
                                                   testVectors[i].govActionIndex,
                                                   identifier,
                                                   sizeof(identifier));
        assert_true(success);
        assert_string_equal(identifier, testVectors[i].expectedBech32);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_format_hex_bytes),
        cmocka_unit_test(test_format_uint64),
        cmocka_unit_test(test_format_decimal_amount),
        cmocka_unit_test(test_format_ada_amount),
        cmocka_unit_test(test_format_validity_boundary),
        cmocka_unit_test(test_format_pool_margin),
        cmocka_unit_test(test_format_uint16),
        cmocka_unit_test(test_format_index_with_prefix),
        cmocka_unit_test(test_format_vote_option),
        cmocka_unit_test(test_format_constant_drep),
        cmocka_unit_test(test_format_certificate_type),
        cmocka_unit_test(test_format_url),
        cmocka_unit_test(test_format_dns_name),
        cmocka_unit_test(test_format_decimal_amount_buffer_too_small),
        cmocka_unit_test(test_format_input_with_index_buffer_too_small),
        cmocka_unit_test(test_format_asset_fingerprint_bech32),
        cmocka_unit_test(test_format_governance_identifier),
        cmocka_unit_test(test_format_governance_action_id),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
