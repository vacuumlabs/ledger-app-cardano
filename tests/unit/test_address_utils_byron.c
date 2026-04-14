/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "cardano_constants.h"
#include "addressUtils/addressUtilsByron.h"
#include "hexUtils.h"

// Test case for successful protocol magic extraction
static void testcase_extractProtocolMagicSucceeds(const char *addressHex,
                                                  uint32_t expectedProtocolMagic) {
    uint8_t address[100] = {0};
    size_t addressSize;
    bool success = decode_hex(addressHex, address, sizeof(address), &addressSize);
    assert_true(success);

    uint32_t protocolMagic = 0;
    bool extractSuccess = extractProtocolMagic(address, addressSize, &protocolMagic);

    assert_true(extractSuccess);
    assert_int_equal(protocolMagic, expectedProtocolMagic);
}

// Test case for failed protocol magic extraction
static void testcase_extractProtocolMagicFails(const char *addressHex) {
    uint8_t address[100] = {0};
    size_t addressSize;
    bool success = decode_hex(addressHex, address, sizeof(address), &addressSize);
    assert_true(success);

    uint32_t protocolMagic = 0;
    bool extractSuccess = extractProtocolMagic(address, addressSize, &protocolMagic);

    assert_false(extractSuccess);
}

// ======================== Protocol Magic Extraction Tests ========================

static void test_extract_protocol_magic_mainnet_simple(void **state) {
    (void) state;

    testcase_extractProtocolMagicSucceeds(
        "82d818582183581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a0001ad7ed912f",
        MAINNET_PROTOCOL_MAGIC);
}

static void test_extract_protocol_magic_mainnet_complex1(void **state) {
    (void) state;

    testcase_extractProtocolMagicSucceeds(
        "82d818584283581cd2348b8ef7b8a6d1c922efa499c669b151eeef99e4ce3521e88223f8a101581e581cf281e6"
        "48a89015a9861bd9e992414d1145ddaf80690be53235b0e2e5001a19983465",
        MAINNET_PROTOCOL_MAGIC);
}

static void test_extract_protocol_magic_mainnet_complex2(void **state) {
    (void) state;

    testcase_extractProtocolMagicSucceeds(
        "82d818584983581c9c708538a763ff27169987a489e35057ef3cd3778c05e96f7ba9450ea201581e581c9c1722"
        "f7e446689256e1a30260f3510d558d99d0c391f2ba89cb697702451a4170cb17001a6979126c",
        TESTNET_PROTOCOL_MAGIC_LEGACY);
}

static void test_extract_protocol_magic_custom_magic(void **state) {
    (void) state;

    testcase_extractProtocolMagicSucceeds(
        "82d818582583581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a10242182a001a2b7c"
        "56f6",
        42);
}

// ======================== Protocol Magic Extraction Failure Tests ========================

static void test_extract_protocol_magic_invalid_cbor(void **state) {
    (void) state;

    // Invalid CBOR
    testcase_extractProtocolMagicFails("deadbeef");
}

static void test_extract_protocol_magic_shelley_address(void **state) {
    (void) state;

    // Shelley address (not Byron format)
    testcase_extractProtocolMagicFails(
        "035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aa"
        "b3127cc611ddbc4999def61c");
}

static void test_extract_protocol_magic_explicit_mainnet(void **state) {
    (void) state;

    // Mainnet protocol magic explicitly encoded (invalid structure)
    testcase_extractProtocolMagicFails(
        "82d818582883581ca1eda96a9952a56c983d9f49117f935af325e8a6c9d38496e945faa8a102451a2d964a0900"
        "1a099ade84");
}

static void test_extract_protocol_magic_too_many_attributes(void **state) {
    (void) state;

    // Too many keys in address attributes
    testcase_extractProtocolMagicFails(
        "82d818583183581ca1eda96a9952a56c983d9f49117f935af325e8a6c9d38496e945faa8a40142182f0242182f"
        "0342182f0442182f001a965d526c");
}

static void test_extract_protocol_magic_attribute_not_bytes(void **state) {
    (void) state;

    // Address attributes value not bytes
    testcase_extractProtocolMagicFails(
        "82d818582483581ca1eda96a9952a56c983d9f49117f935af325e8a6c9d38496e945faa8a101182f001a1abe13"
        "ed");
}

static void test_extract_protocol_magic_invalid_crc32(void **state) {
    (void) state;

    // Invalid crc32 checksum
    testcase_extractProtocolMagicFails(
        "82d818582183581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a0001ad7ed912e");
}

// ======================== Additional Protocol Magic Extraction Failure Tests
// ========================

static void test_extract_protocol_magic_outer_array_wrong_count(void **state) {
    (void) state;
    // Outer array has 3 elements instead of 2: 83 instead of 82
    testcase_extractProtocolMagicFails(
        "83d818582183581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a0001ad7ed912f");
}

static void test_extract_protocol_magic_wrong_tag(void **state) {
    (void) state;
    // Tag 25 (0xd819) instead of tag 24 (0xd818)
    testcase_extractProtocolMagicFails(
        "82d919582183581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a0001ad7ed912f");
}

static void test_extract_protocol_magic_payload_size_exceeds_remaining(void **state) {
    (void) state;
    // array(2), tag(24), bytes(33) — but only 5 bytes of data follow (far fewer than 33)
    testcase_extractProtocolMagicFails("82d81858210102030405");
}

static void test_extract_protocol_magic_inner_array_wrong_count(void **state) {
    (void) state;
    // Inner array (inside embedded CBOR) has 2 elements instead of 3.
    // Original inner payload starts with 83 (array of 3); change to 82 (array of 2).
    // The embedded payload is: 83581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a000
    // Replace 83 with 82 at the right offset.
    testcase_extractProtocolMagicFails(
        "82d818582182581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a0001ad7ed912f");
}

static void test_extract_protocol_magic_address_root_wrong_size(void **state) {
    (void) state;
    // Address root declared as 27 bytes (0x5b = bytes(27)) instead of 28
    // Original: 581c = bytes(28); replace with 581b = bytes(27)
    testcase_extractProtocolMagicFails(
        "82d818582183581bb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a0001ad7ed912f");
}

static void test_extract_protocol_magic_address_root_truncated(void **state) {
    (void) state;
    // Address root declared as 28 bytes but buffer ends before all 28 are present.
    // Keep the size token (581c) but supply only 20 bytes of root data.
    testcase_extractProtocolMagicFails(
        "82d818581683581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e013");
}

static void test_extract_protocol_magic_protocol_magic_not_unsigned(void **state) {
    (void) state;
    // Protocol magic attribute (key 2) value contains CBOR bytes wrapping a text string
    // instead of an unsigned int.
    // Custom magic address: 82d818582583581c...a10242182a00...
    // The attribute value bytes (0242182a) = bytes(2) containing 0x182a (uint 42).
    // Replace the inner value with 0x62 (text "ab" = 0x6261) to trigger type mismatch.
    testcase_extractProtocolMagicFails(
        "82d818582583581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a102426162001a2b7c"
        "56f6");
}

static void test_extract_protocol_magic_protocol_magic_extra_bytes_in_value(void **state) {
    (void) state;
    // Protocol magic attribute value bytes(3) contains uint(42) + extra 0x00 byte;
    // sub-buffer not fully consumed → return false
    testcase_extractProtocolMagicFails(
        "82d818582683581c1cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e01368a10243182a00001ab5"
        "228dc5");
}

static void test_extract_protocol_magic_protocol_magic_too_large(void **state) {
    (void) state;
    // Protocol magic > UINT32_MAX: encode 0x1_0000_0000 as CBOR uint = 1b 0000000100000000
    // Attribute value bytes: 09 1b0000000100000000
    testcase_extractProtocolMagicFails(
        "82d8185830"  // array(2), tag(24), bytes(0x30 = 48)
        "83581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e013"
        "6881a1"                // map(1)
        "02"                    // key: 2
        "49"                    // bytes(9)
        "1b000000010000000000"  // uint64 = 0x1_0000_0000_0000 — way above UINT32_MAX
        "001a2b7c56f6");
}

static void test_extract_protocol_magic_attribute_seek_fails(void **state) {
    (void) state;
    // Attribute value size token claims 5 bytes but buffer ends before them.
    // Take the custom magic address, change value size from 2 to 5, truncate buffer.
    testcase_extractProtocolMagicFails(
        "82d818582583581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a102");
}

static void test_extract_protocol_magic_address_type_not_unsigned(void **state) {
    (void) state;
    // Address type field should be CBOR unsigned; replace with CBOR bytes token.
    // Original ends with "...881a0001ad7ed912f" where "00" is address type uint(0)
    // and "1ad7ed912f" is the CRC. Replace "00" with "40" (bytes(0)) to fail type check.
    testcase_extractProtocolMagicFails(
        "82d818582183581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a0040ad7ed912f");
}

static void test_extract_protocol_magic_address_type_parse_fails(void **state) {
    (void) state;
    // Buffer is truncated while parsing address type token.
    // The address type appears to be unsigned with 4-byte value (0x1a), but only 2 bytes of the
    // value are available in the buffer. When cbor_parseToken tries to read the full 5-byte token
    // (1 byte tag + 4 bytes value), it only finds 4 bytes, so it returns false.
    testcase_extractProtocolMagicFails(
        "82d8185821"  // outer array(2), tag(24), bytes(0x21)
        "83581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a000"  // embedded CBOR (33
                                                                              // bytes)
        "1aef29");  // incomplete CRC (needs 5 bytes: 1a + 4 bytes value, but only 4 available)
}

static void test_extract_protocol_magic_trailing_bytes(void **state) {
    (void) state;
    // Append an extra byte to an otherwise valid address (after CRC)
    testcase_extractProtocolMagicFails(
        "82d818582183581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a0001ad7ed912f00");
}

static void test_extract_protocol_magic_embedded_payload_has_trailing_bytes(void **state) {
    (void) state;
    // Embedded Byron payload bytes contain one extra trailing byte beyond the parsed
    // inner array/map/type structure. The checksum is recomputed over the full tagged
    // payload so the parser must reject based on inner payload overrun, not CRC mismatch.
    testcase_extractProtocolMagicFails(
        "82d818582283581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a000001a79043f45");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Protocol magic extraction success tests
        cmocka_unit_test(test_extract_protocol_magic_mainnet_simple),
        cmocka_unit_test(test_extract_protocol_magic_mainnet_complex1),
        cmocka_unit_test(test_extract_protocol_magic_mainnet_complex2),
        cmocka_unit_test(test_extract_protocol_magic_custom_magic),

        // Protocol magic extraction failure tests
        cmocka_unit_test(test_extract_protocol_magic_invalid_cbor),
        cmocka_unit_test(test_extract_protocol_magic_shelley_address),
        cmocka_unit_test(test_extract_protocol_magic_explicit_mainnet),
        cmocka_unit_test(test_extract_protocol_magic_too_many_attributes),
        cmocka_unit_test(test_extract_protocol_magic_attribute_not_bytes),
        cmocka_unit_test(test_extract_protocol_magic_invalid_crc32),

        // Additional structural failure tests
        cmocka_unit_test(test_extract_protocol_magic_outer_array_wrong_count),
        cmocka_unit_test(test_extract_protocol_magic_wrong_tag),
        cmocka_unit_test(test_extract_protocol_magic_payload_size_exceeds_remaining),
        cmocka_unit_test(test_extract_protocol_magic_inner_array_wrong_count),
        cmocka_unit_test(test_extract_protocol_magic_address_root_wrong_size),
        cmocka_unit_test(test_extract_protocol_magic_address_root_truncated),
        cmocka_unit_test(test_extract_protocol_magic_protocol_magic_not_unsigned),
        cmocka_unit_test(test_extract_protocol_magic_protocol_magic_extra_bytes_in_value),
        cmocka_unit_test(test_extract_protocol_magic_protocol_magic_too_large),
        cmocka_unit_test(test_extract_protocol_magic_attribute_seek_fails),
        cmocka_unit_test(test_extract_protocol_magic_address_type_not_unsigned),
        cmocka_unit_test(test_extract_protocol_magic_address_type_parse_fails),
        cmocka_unit_test(test_extract_protocol_magic_trailing_bytes),
        cmocka_unit_test(test_extract_protocol_magic_embedded_payload_has_trailing_bytes),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
