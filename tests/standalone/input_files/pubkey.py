# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Public Key check
"""

from dataclasses import dataclass

from ragger.bip import CurveChoice, calculate_public_key_and_chaincode

UNIT_TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def convert_ragger_bip_pubkey_to_app_pubkey(public_key_hex: str) -> str:
    normalized_public_key_hex = public_key_hex.removeprefix("0x")
    if len(normalized_public_key_hex) != 66:
        raise ValueError(f"ragger bip pubkey has unexpected length: {len(normalized_public_key_hex)} hex chars")
    if not normalized_public_key_hex.startswith("00"):
        raise ValueError("ragger bip pubkey is expected to use the 0x00-prefixed 33-byte representation")
    return normalized_public_key_hex[2:]


def _derive_pubkey_expected_result(path: str, mnemonic: str) -> "PubKeyExpectedResult":
    public_key_hex, chain_code_hex = calculate_public_key_and_chaincode(
        CurveChoice.Ed25519Kholaw,
        path,
        mnemonic=mnemonic,
    )
    return PubKeyExpectedResult(
        publicKeyHex=convert_ragger_bip_pubkey_to_app_pubkey(public_key_hex),
        chainCodeHex=chain_code_hex,
    )


@dataclass(kw_only=True, frozen=True)
class PubKeyExpectedResult:
    publicKeyHex: str
    chainCodeHex: str


@dataclass(kw_only=True, frozen=True)
class PubKeyTestCase:
    name: str
    path: str | None = None
    nav: bool | None = True
    unit_test_expect: PubKeyExpectedResult | None = None
    ragger_expect: PubKeyExpectedResult | None = None


# pylint: disable=line-too-long
testsByron = [
    PubKeyTestCase(
        name="Export_pubkey_byronpath_1",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="6c6d5cae98296d553056a9e61edbfc8d7ea65aa1bcafc9c68aac6354b1331ac5",
            publicKeyHex="70da3cf4d0c498b81f82887fe114bb7134e3a35bb081bfedbda7c59bcf7fc3af",
        ),
        path="m/44'/1815'/1'",
        unit_test_expect=_derive_pubkey_expected_result("m/44'/1815'/1'", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_byronpath_2",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="8cdfb0a1f0f4a00012129482f2397704411d0cf7441dd42e7aae5125604dbd6e",
            publicKeyHex="34dc3723b1cfad45456b14dbc29e15dee18973554c98e9d3cb957c07fa2dde31",
        ),
        path="m/44'/1815'/1'/0/55'",
        unit_test_expect=_derive_pubkey_expected_result("m/44'/1815'/1'/0/55'", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_byronpath_3",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="e8b123ed4814657d8b3313cba0dc3ab5b0bec0703c8bfcf563ac8d13f5b82a42",
            publicKeyHex="85ca3f6784caf2ba90529368696e1568aaa199b3343d738886a6fbd7a3f04c1f",
        ),
        path="m/44'/1815'/1'/0/12'",
        unit_test_expect=_derive_pubkey_expected_result("m/44'/1815'/1'/0/12'", UNIT_TEST_MNEMONIC),
    ),
]

testsShelleyUsual = [
    PubKeyTestCase(
        name="Export_pubkey_shelley_usual_path_0",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="c78245fc1c423386d9699317ff9e6200a7c87673d57bb2f20078eec144e91703",
            publicKeyHex="a8ae477a709323aa3ec782863f29edf86fec9e25edac6893133265f5728c0283",
        ),
        path="m/1852'/1815'/4'",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/4'", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_usual_path_1",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="3122397ba23bfb94ae6a8b20f0bc38f19b2afe7ee582456133039b83bfda1705",
            publicKeyHex="80a3ae98db92602aaee7170bc48b15ef9274d62521d37660561938066d16f658",
        ),
        path="m/1852'/1815'/0'/0/1",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0'/0/1", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_usual_path_2",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="601a07548489b1255d0469ee42a7b405d37dd3574716dbec61f51ae81202d42d",
            publicKeyHex="d78976ce65cc3409a6b037dc1d378beeb1369a4136b191e3079fa53fdbc4b4fa",
        ),
        path="m/1852'/1815'/0'/2/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0'/2/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_usual_path_3",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="7c69e7c76b107dd938dfafe24969ce5c05ef2b152e48920d3287eeabe1b2243c",
            publicKeyHex="c4b83c7a5280ad1ccf234f28db7d579eec5fcf91ed1440cae9a894ec7df5ec50",
        ),
        path="m/1852'/1815'/0'/2/1001",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0'/2/1001", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_usual_path_4",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="be224ffe9934949d2a092074f8241b51c3d4f1c755c03a24a8f5defe8b941814",
            publicKeyHex="450d42914a4b8c738fde9b83d8648c244633b9ee9f9ace3a9809f13f1fc6404d",
        ),
        path="m/1852'/1815'/0'/3/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0'/3/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_usual_path_5",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="a11b2c86d3e4b120feec09002b68287e67d7e121b95098c3c824ecb587548d9c",
            publicKeyHex="4d215c6bd6ba313cd42489028e5809cfea3c5c5198a696f5a9d08a23a1536fa3",
        ),
        path="m/1852'/1815'/0'/4/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0'/4/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_usual_path_6",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="22e6bef0bcea8ef07689d025de2f53723620ef2f365c642cd1ff181e20cf97ad",
            publicKeyHex="b25ab473176e90123d42197155b7d6a80605a2abca63b9188f3cf55af7e6f84c",
        ),
        path="m/1852'/1815'/1'/5/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/1'/5/0", UNIT_TEST_MNEMONIC),
    ),
]

testsShelleyUnusual = [
    PubKeyTestCase(
        name="Export_pubkey_shelley_unusual_path_1",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="7768430a7d46160bf5149e627ffef96e6e5211113eee40e04919b250c3efd8e1",
            publicKeyHex="3d2e4d0594d0fcb11190cc7a492e65c7a1d8ce466c008be1f943c5a31f241470",
        ),
        path="m/1852'/1815'/101'",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/101'", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_unusual_path_2",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="b24ec0284631e0a81dcff751580cc7b6bb5ff2084c1c041113a31b80709a3505",
            publicKeyHex="260e58c70331c28a1d73acf39062f109ef55566371f07d5eb30f60bf11fa96eb",
        ),
        path="m/1852'/1815'/100'/0/1000001'",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/100'/0/1000001'", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_unusual_path_3",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="9e21baf369a1d16caf8a091eb5e0c0fbd9f3f599cf7cb04780bbb4be159d1e9d",
            publicKeyHex="21f05225d4cb568f2a91dccd40ccb47e6e12288f6ab171c447bd57b14a06dcef",
        ),
        path="m/1852'/1815'/0'/2/1000001",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0'/2/1000001", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_unusual_path_4",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="6fe5a88363cc77d262c575f4a49b6d1b1b3869189ca193a794c76aa21d15b4ca",
            publicKeyHex="1f1a452164b1ded176b712c714e8161e3cb33225336e094c61e8e8e607bd556d",
        ),
        path="m/1852'/1815'/101'/3/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/101'/3/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_unusual_path_5",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="834d003edb6dc729bce3844c1856e473e4093f01d463e6e257de772e5efc61ea",
            publicKeyHex="f3019ec48400ee8350435080ad157f031fff3ed5001b00ce7df3b2ce4c6be69b",
        ),
        path="m/1852'/1815'/101'/4/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/101'/4/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_unusual_path_6",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="dc80406090918d5caad8f52923cc62946179d3a24a405d404ae5720415c71add",
            publicKeyHex="494fffd71df2e0a76e1c1507c68e52a4fae102ed179a2c10ae176671fd5ecdee",
        ),
        path="m/1852'/1815'/101'/5/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/101'/5/0", UNIT_TEST_MNEMONIC),
    ),
]

testsMultisig = [
    PubKeyTestCase(
        name="Export_pubkey_multisig_account_path_0",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="b582ca1b512ed8e19c9c096b53b003135178c2b4317a8da9c6e6d7545dbda751",
            publicKeyHex="1790a860cede80a4df302a76b8cd6eb806dc789179fab49f2c7676923abf2f6b",
        ),
        path="m/1854'/1815'/0'",
        unit_test_expect=_derive_pubkey_expected_result("m/1854'/1815'/0'", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_multisig_payment_path_0",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="7c3fed58b3bbc7336a70c427f911bd398ab54a8867df2e6172c99f359137d3d5",
            publicKeyHex="66b5700de1d8e5ac3f7d9950c32e93de74a4f21aa3cc4590381b9655ef2e5f27",
        ),
        path="m/1854'/1815'/0'/0/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1854'/1815'/0'/0/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_multisig_staking_path_0",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="50ce626ac9d211da2e1073d8d5c08cc80ec5816f38e842bbe3bfcdb7564cfaaa",
            publicKeyHex="fb6a4df9503b7bb7d80c21fd3b66e0568aa0f7b18be8db9718a87f5a1cc913a1",
        ),
        path="m/1854'/1815'/0'/2/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1854'/1815'/0'/2/0", UNIT_TEST_MNEMONIC),
    ),
]

testsColdKeys = [
    PubKeyTestCase(
        name="Export_pubkey_cold_case",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="4c11a7b9c940ffd836d11043871601a7e0d7570b6c266699cc7baebd81c9a5e0",
            publicKeyHex="09dc9a6c151df265b4dbce84457fea3366aa95edc8a7a23b8da039e2db288d60",
        ),
        path="m/1853'/1815'/0'/0'",
        unit_test_expect=_derive_pubkey_expected_result("m/1853'/1815'/0'/0'", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_cold_unusual_case",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="4c64f8c16fad94e8cd6c410bcc80aa46292b5b120771f9d7f71586178118a176",
            publicKeyHex="6cdf197de70dd9cbc1b96a7d8d6e361b799d078f8a2ec4bb60f8f87a3dcc12e9",
        ),
        path="m/1853'/1815'/0'/101'",
        unit_test_expect=_derive_pubkey_expected_result("m/1853'/1815'/0'/101'", UNIT_TEST_MNEMONIC),
    ),
]

testsCVoteKeysUsual = [
    PubKeyTestCase(
        name="Export_pubkey_CVote_keys_path_2",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="e8109edbb50fd81877b9fe4fd71d9e0e1a8fd906413d005c7f12f373fe21add6",
            publicKeyHex="971503b7341d2fb537bb5a186d87a64f8afdc5d7bbe40c78ccbc0196c8e8dd6c",
        ),
        path="m/1694'/1815'/100'",
        unit_test_expect=_derive_pubkey_expected_result("m/1694'/1815'/100'", UNIT_TEST_MNEMONIC),
    ),
]

testsCVoteKeysUnusual = [
    PubKeyTestCase(
        name="Export_pubkey_CVote_keys_path_1",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="d7fab767a624d8f0cb43d5e9624c215043c87ae9bd6f4b60e4deb30f56493205",
            publicKeyHex="b27a927781de0a463397c566ebff6b3bd357ae09a802156940a37ccfde47408c",
        ),
        path="m/1694'/1815'/0'/0/1",
        unit_test_expect=_derive_pubkey_expected_result("m/1694'/1815'/0'/0/1", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_CVote_keys_path_3",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="df5ca4fa07d3337a0c30c9056c9d027aeb0fbc1e02872d92cb9a42d90c7e06d3",
            publicKeyHex="1339902f1c89dc90a9971197c16ef91549c7303c70386b9fef727ada4cb2f54f",
        ),
        path="m/1694'/1815'/101'",
        unit_test_expect=_derive_pubkey_expected_result("m/1694'/1815'/101'", UNIT_TEST_MNEMONIC),
    ),
]

testsDRepKeys = [
    PubKeyTestCase(
        name="Export_pubkey_drep_key_path_0",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="be224ffe9934949d2a092074f8241b51c3d4f1c755c03a24a8f5defe8b941814",
            publicKeyHex="450d42914a4b8c738fde9b83d8648c244633b9ee9f9ace3a9809f13f1fc6404d",
        ),
        path="m/1852'/1815'/0'/3/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0'/3/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_multisig_drep_key_path_0",
        path="m/1854'/1815'/0'/3/0",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="b85f39b418dc2ca1c9622b04caa3fa33f94879f38f1ea05f2498f8040b2a1c9e",
            publicKeyHex="b7e837b7b4a8f1afe3bd2e180dddeabdf5b49207d16a06c8a3401a8b9da5ce7b",
        ),
        unit_test_expect=_derive_pubkey_expected_result("m/1854'/1815'/0'/3/0", UNIT_TEST_MNEMONIC),
    ),
]

testsCommitteeColdKeys = [
    PubKeyTestCase(
        name="Export_pubkey_committee_cold_key_path_0",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="a11b2c86d3e4b120feec09002b68287e67d7e121b95098c3c824ecb587548d9c",
            publicKeyHex="4d215c6bd6ba313cd42489028e5809cfea3c5c5198a696f5a9d08a23a1536fa3",
        ),
        path="m/1852'/1815'/0'/4/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0'/4/0", UNIT_TEST_MNEMONIC),
    ),
]

testsCommitteeHotKeys = [
    PubKeyTestCase(
        name="Export_pubkey_committee_hot_key_path_0",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="07eb748ef27ebafdc7037481c5f18e5388045095995d8d5b4acfd3f3d4d53c75",
            publicKeyHex="d485fbcd9bb1efe65672d27d3325178b58b155eb7f1e498ab19a0b59f770a53f",
        ),
        path="m/1852'/1815'/0'/5/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0'/5/0", UNIT_TEST_MNEMONIC),
    ),
]

testsMintKeys = [
    PubKeyTestCase(
        name="Export_pubkey_mint_key_path_0",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="27c742e0ec4d8ae93f58b26cfd3046fd6f19c48a08d8379c49ac4e2377f2ad83",
            publicKeyHex="4a07232e8d10d8e0912ee395a678f1379c53915814e2394bb8e41477475fa711",
        ),
        path="m/1855'/1815'/0'",
        unit_test_expect=_derive_pubkey_expected_result("m/1855'/1815'/0'", UNIT_TEST_MNEMONIC),
    ),
]

testsSilentExportRareKeys = [
    PubKeyTestCase(
        name="Export_pubkey_drep_key_path_0_silent",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="be224ffe9934949d2a092074f8241b51c3d4f1c755c03a24a8f5defe8b941814",
            publicKeyHex="450d42914a4b8c738fde9b83d8648c244633b9ee9f9ace3a9809f13f1fc6404d",
        ),
        path="m/1852'/1815'/0'/3/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0'/3/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_committee_cold_key_path_0_silent",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="a11b2c86d3e4b120feec09002b68287e67d7e121b95098c3c824ecb587548d9c",
            publicKeyHex="4d215c6bd6ba313cd42489028e5809cfea3c5c5198a696f5a9d08a23a1536fa3",
        ),
        path="m/1852'/1815'/0'/4/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0'/4/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_committee_hot_key_path_0_silent",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="07eb748ef27ebafdc7037481c5f18e5388045095995d8d5b4acfd3f3d4d53c75",
            publicKeyHex="d485fbcd9bb1efe65672d27d3325178b58b155eb7f1e498ab19a0b59f770a53f",
        ),
        path="m/1852'/1815'/0'/5/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0'/5/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_mint_key_path_0_silent",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="27c742e0ec4d8ae93f58b26cfd3046fd6f19c48a08d8379c49ac4e2377f2ad83",
            publicKeyHex="4a07232e8d10d8e0912ee395a678f1379c53915814e2394bb8e41477475fa711",
        ),
        path="m/1855'/1815'/0'",
        unit_test_expect=_derive_pubkey_expected_result("m/1855'/1815'/0'", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_cold_case_silent",
        ragger_expect=PubKeyExpectedResult(
            chainCodeHex="4c11a7b9c940ffd836d11043871601a7e0d7570b6c266699cc7baebd81c9a5e0",
            publicKeyHex="09dc9a6c151df265b4dbce84457fea3366aa95edc8a7a23b8da039e2db288d60",
        ),
        path="m/1853'/1815'/0'/0'",
        unit_test_expect=_derive_pubkey_expected_result("m/1853'/1815'/0'/0'", UNIT_TEST_MNEMONIC),
    ),
]


def _parse_bip44_path(path: str) -> list[tuple[int, bool]]:
    parts = path.split("/")[1:]
    parsed: list[tuple[int, bool]] = []
    for part in parts:
        hardened = part.endswith("'")
        value_str = part[:-1] if hardened else part
        parsed.append((int(value_str), hardened))
    return parsed


def _is_silent_export_path(path: str) -> bool:
    parsed = _parse_bip44_path(path)
    if len(parsed) < 3:
        return False
    purpose, purpose_hardened = parsed[0]
    coin_type, coin_type_hardened = parsed[1]
    account, account_hardened = parsed[2]
    if not (purpose_hardened and coin_type_hardened and account_hardened):
        return False
    if purpose not in {1694, 1852, 1854} or coin_type != 1815:
        return False
    if account > 100:
        return False
    if len(parsed) == 3:
        return True
    if len(parsed) != 5:
        return False
    chain, chain_hardened = parsed[3]
    address, address_hardened = parsed[4]
    if chain_hardened or address_hardened:
        return False
    if purpose == 1694:
        if chain != 0:
            return False
    elif chain not in {0, 1, 2}:
        return False
    return address <= 1000000


testsSilentExport = [
    test_case
    for test_case in (
        testsByron
        + testsShelleyUsual
        + testsShelleyUnusual
        + testsMultisig
        + testsColdKeys
        + testsCVoteKeysUsual
        + testsCVoteKeysUnusual
        + testsDRepKeys
        + testsCommitteeColdKeys
        + testsCommitteeHotKeys
        + testsMintKeys
    )
    if test_case.path is not None and _is_silent_export_path(test_case.path)
]

denyTestCases = [
    PubKeyTestCase(
        name="Export_pubkey_path_shorter_than_3_indexes",
        path="m/44'/1815'",
        unit_test_expect=_derive_pubkey_expected_result("m/44'/1815'", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_path_not_matching_cold_key_structure",
        path="m/1853'/1900'/0'/0/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1853'/1900'/0'/0/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_vote_key_path_1",
        path="m/1694'/1815'/0'/1/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1694'/1815'/0'/1/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_vote_key_path_2",
        path="m/1694'/1815'/17",
        unit_test_expect=_derive_pubkey_expected_result("m/1694'/1815'/17", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_vote_key_path_3",
        path="m/1694'/1815'/0'/1",
        unit_test_expect=_derive_pubkey_expected_result("m/1694'/1815'/0'/1", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_multisig_account_not_hardened",
        path="m/1854'/1815'/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1854'/1815'/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_multisig_chain",
        path="m/1854'/1815'/0'/6/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1854'/1815'/0'/6/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_multisig_address_hardened",
        path="m/1854'/1815'/0'/0/0'",
        unit_test_expect=_derive_pubkey_expected_result("m/1854'/1815'/0'/0/0'", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_mint_policy_not_hardened",
        path="m/1855'/1815'/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1855'/1815'/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_drep_chain",
        path="m/1852'/1815'/0'/6/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0'/6/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_committee_cold_address_hardened",
        path="m/1852'/1815'/0'/4/0'",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0'/4/0'", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_committee_hot_account_not_hardened",
        path="m/1852'/1815'/0/5/0",
        unit_test_expect=_derive_pubkey_expected_result("m/1852'/1815'/0/5/0", UNIT_TEST_MNEMONIC),
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_pool_cold_usecase",
        path="m/1853'/1815'/1'/0'",
        unit_test_expect=_derive_pubkey_expected_result("m/1853'/1815'/1'/0'", UNIT_TEST_MNEMONIC),
    ),
]
