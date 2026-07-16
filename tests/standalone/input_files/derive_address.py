# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Address check
"""

import hashlib
from dataclasses import dataclass

from bip_utils import (
    Bip32Path,
    Bip32PathParser,
    Bip39SeedGenerator,
    Bip44,
    Bip44Changes,
    Bip44Coins,
)
from ragger.bip import CurveChoice, calculate_public_key_and_chaincode

from tests.application_client.command_builder import (
    AddressParams,
    AddressType,
    FakeNet,
    Mainnet,
    P1Type,
    Testnet,
)
from tests.application_client.status_words import StatusWord
from tests.standalone.input_files.pubkey import convert_ragger_bip_pubkey_to_app_pubkey

UNIT_TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
SPECULOS_MNEMONIC = (
    "glory promote mansion idle axis finger extra february uncover one trip "
    "resource lawn turtle enact monster seven myth punch hobby comfort wild "
    "raise skin"
)


def _appenduint32(value: int) -> str:
    if value == 0:
        return "00"

    chunks: list[int] = []
    while value:
        chunks.append(value & 0x7F)
        value >>= 7

    result = ""
    while len(chunks) > 1:
        result += f"{chunks.pop() | 0x80:02x}"
    result += f"{chunks.pop():02x}"
    return result


def _derive_pubkey_for_mnemonic(path: str, mnemonic: str) -> bytes:
    public_key_hex, _ = calculate_public_key_and_chaincode(
        CurveChoice.Ed25519Kholaw,
        path,
        mnemonic=mnemonic,
    )
    return bytes.fromhex(convert_ragger_bip_pubkey_to_app_pubkey(public_key_hex))


def _derive_shelley_address_hex(params: AddressParams, mnemonic: str) -> str:
    address_hex = f"{(int(params.addrType) << 4) | int(params.netDesc.networkId):02x}"
    if params.spendingValue.startswith("m/"):
        spending_public_key = _derive_pubkey_for_mnemonic(params.spendingValue, mnemonic)
        address_hex += hashlib.blake2b(spending_public_key, digest_size=28).digest().hex()
    else:
        address_hex += params.spendingValue

    if params.addrType in (AddressType.POINTER_KEY, AddressType.POINTER_SCRIPT):
        assert params.stakingValue is not None
        address_hex += _appenduint32(int(params.stakingValue[0:8], 16))
        address_hex += _appenduint32(int(params.stakingValue[8:16], 16))
        address_hex += _appenduint32(int(params.stakingValue[16:24], 16))
        return address_hex

    assert params.stakingValue is not None
    if params.stakingValue.startswith("m/"):
        staking_public_key = _derive_pubkey_for_mnemonic(params.stakingValue, mnemonic)
        address_hex += hashlib.blake2b(staking_public_key, digest_size=28).digest().hex()
    else:
        address_hex += params.stakingValue
    return address_hex


def _derive_byron_address_string(path: str, mnemonic: str) -> str:
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44_context = Bip44.FromSeed(seed_bytes, Bip44Coins.CARDANO_BYRON_LEDGER)
    bip32_path: Bip32Path = Bip32PathParser.Parse(path).ToList()
    bip44_account = bip44_context.Purpose().Coin().Account(bip32_path[2])
    bip44_change = bip44_account.Change(Bip44Changes.CHAIN_EXT if bip32_path[3] == 0 else Bip44Changes.CHAIN_INT)
    bip44_address = bip44_change.AddressIndex(bip32_path[4])
    return str(bip44_address.PublicKey().ToAddress())


@dataclass(kw_only=True, frozen=True)
class DeriveAddressExpectedResult:
    addressHex: str
    human_readable_address: str | None = None


@dataclass(kw_only=True, frozen=True)
class DeriveAddressTestCase:
    name: str
    params: AddressParams
    p1: int = P1Type.P1_ADDRESS_RETURN
    unit_test_expect: DeriveAddressExpectedResult | None = None
    ragger_expect: DeriveAddressExpectedResult | None = None
    expected_swo: StatusWord | None = None


def pointer_to_str(blockIndex: int, txIndex: int, certificateIndex: int) -> str:
    data: str = ""
    data += f"{blockIndex.to_bytes(4, 'big').hex()}"
    data += f"{txIndex.to_bytes(4, 'big').hex()}"
    data += f"{certificateIndex.to_bytes(4, 'big').hex()}"
    return data


# pylint: disable=line-too-long
byronTestCases = [
    DeriveAddressTestCase(
        name="Derive_address_byron_mainnet_1",
        params=AddressParams(
            addrType=AddressType.BYRON,
            netDesc=Mainnet,
            spendingValue="m/44'/1815'/1'/0/55'",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="82d818582183581c9c93a34e91c16e3ce118746d1bd37fb55fa82488011174a518cf6052a0001ad1817531"
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="82d818582183581c95e0a442965b008d30376e6dfb9071ba7c93dbab45670506d1366abca0001ae8909828"
        ),
    ),
    DeriveAddressTestCase(
        name="Derive_address_byron_mainnet_2",
        params=AddressParams(
            addrType=AddressType.BYRON,
            netDesc=Mainnet,
            spendingValue="m/44'/1815'/1'/0/12'",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="82d818582183581c5487a0e1eaad2a8aab74a7fb8fdd946c86aadc53d13b3ec202674b24a0001a21430004"
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="82d818582183581c0d9260b988c368a6b683fc9d4f22082968ded01e1a948e8b5d8edee4a0001a91b812ce"
        ),
    ),
    DeriveAddressTestCase(
        name="Derive_address_byron_mainnet_3",
        params=AddressParams(
            addrType=AddressType.BYRON,
            netDesc=Mainnet,
            spendingValue="m/44'/1815'/101'/0/12'",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="82d818582183581c0ea2c567a5a8890dbf460b3b6ad73c8955ae254525a874f2ec0981dea0001ae26b0153"
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="82d818582183581c64b2c1c40661d320bd5eed569ea4aaa6655c9205b2f51d99657c2301a0001a0b78d4b3"
        ),
    ),
    DeriveAddressTestCase(
        name="Derive_address_byron_mainnet_4",
        params=AddressParams(
            addrType=AddressType.BYRON,
            netDesc=Mainnet,
            spendingValue="m/44'/1815'/0'/0/1000001'",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="82d818582183581c806b1fcd6c54132fbeaf751d096a229876d99d4681eef43488fc6285a0001a9d2b9160"
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="82d818582183581c6f64be9ebd9bc95044558237d7e469a35cc091b920f5f4083087404ca0001af62359e3"
        ),
    ),
    DeriveAddressTestCase(
        name="Derive_address_byron_testnet_1",
        params=AddressParams(
            addrType=AddressType.BYRON,
            netDesc=Testnet,
            spendingValue="m/44'/1815'/1'/0/12'",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="82d818582583581c5487a0e1eaad2a8aab74a7fb8fdd946c86aadc53d13b3ec202674b24a10242182a001ac4c46a40"
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="82d818582583581c0d9260b988c368a6b683fc9d4f22082968ded01e1a948e8b5d8edee4a10242182a001afebf98c6",
            human_readable_address="2657WMsDfac5679tC5DgShwENgGLwAuGNanDjDaCzuEEqXDsP6i2345FcVkwRYVqX",
        ),
    ),
]

denyTestCases = [
    DeriveAddressTestCase(
        name="Derive_address_path_too_short",
        params=AddressParams(
            addrType=AddressType.BYRON,
            netDesc=Mainnet,
            spendingValue="m/44'/1815'/1'",
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    DeriveAddressTestCase(
        name="Derive_address_invalid_path",
        params=AddressParams(
            addrType=AddressType.BYRON,
            netDesc=Mainnet,
            spendingValue="m/44'/1815'/1'/5/10'",
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    DeriveAddressTestCase(
        name="Derive_address_Byron_with_Shelley_path",
        params=AddressParams(
            addrType=AddressType.BYRON,
            netDesc=Mainnet,
            spendingValue="m/1852'/1815'/1'/0/10",
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    DeriveAddressTestCase(
        name="Derive_address_base_key_key_with_Byron_spending_path",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=Mainnet,
            spendingValue="m/44'/1815'/1'/0/1",
            stakingValue="m/1852'/1815'/1'/2/0",
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    DeriveAddressTestCase(
        name="Derive_address_base_key_key_with_wrong_spending_path",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=Mainnet,
            spendingValue="m/1852'/1815'/1'/2/0",
            stakingValue="m/1852'/1815'/1'/2/0",
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    DeriveAddressTestCase(
        name="Derive_address_base_key_key_with_wrong_staking_path_1",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=Mainnet,
            spendingValue="m/1852'/1815'/1'/0/0",
            stakingValue="m/1852'/1815'/1'/0/1",
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    DeriveAddressTestCase(
        name="Derive_address_base_key_script_with_Byron_spending_path",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT,
            netDesc=Mainnet,
            spendingValue="m/44'/1815'/1'/0/1",
            stakingValue="222a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    DeriveAddressTestCase(
        name="Derive_address_base_address_scripthash_keyhash_not_allowed",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,
            netDesc=Mainnet,
            spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
            stakingValue="222a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    DeriveAddressTestCase(
        name="Derive_address_pointer_with_Byron_spending_path",
        params=AddressParams(
            addrType=AddressType.POINTER_KEY,
            netDesc=Mainnet,
            spendingValue="m/44'/1815'/1'/0/0",
            stakingValue=pointer_to_str(1, 2, 3),
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    DeriveAddressTestCase(
        name="Derive_address_pointer_with_wrong_spending_path",
        params=AddressParams(
            addrType=AddressType.POINTER_KEY,
            netDesc=Mainnet,
            spendingValue="m/1852'/1815'/1'/2/0",
            stakingValue=pointer_to_str(1, 2, 3),
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    DeriveAddressTestCase(
        name="Derive_address_enterprise_with_Byron_spending_path",
        params=AddressParams(
            addrType=AddressType.ENTERPRISE_KEY,
            netDesc=Mainnet,
            spendingValue="m/44'/1815'/1'/0/0",
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    DeriveAddressTestCase(
        name="Derive_address_enterprise_with_wrong_spending_path",
        params=AddressParams(
            addrType=AddressType.ENTERPRISE_KEY,
            netDesc=Mainnet,
            spendingValue="m/1852'/1815'/1'/2/0",
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    DeriveAddressTestCase(
        name="Derive_address_display_scripthash_keyhash_not_allowed",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,
            netDesc=Mainnet,
            spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
            stakingValue="222a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
        p1=P1Type.P1_ADDRESS_DISPLAY,  # P1_ADDRESS_DISPLAY
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
]

shelleyTestCasesNoConfirm = [
    # LedgerJS: base address path/path 1
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_path_1",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=FakeNet,
            spendingValue="m/1852'/1815'/0'/0/1",
            stakingValue="m/1852'/1815'/0'/2/0",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
            human_readable_address="addr1qdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwqdquehe",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="039dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c6563db219ee5ce9a74f98fdadc2de13efced5a154ef8d4d41929d5bf9ff6"
        ),
    ),
    # LedgerJS: base address path/path 2
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_path_path_2",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=Testnet,
            spendingValue="m/1852'/1815'/0'/0/1",
            stakingValue="m/1852'/1815'/0'/2/0",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="005a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
            human_readable_address="addr_test1qpd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwq9nnhk4",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="009dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c6563db219ee5ce9a74f98fdadc2de13efced5a154ef8d4d41929d5bf9ff6"
        ),
    ),
    # LedgerJS: base address path/path multidelegation stake key usual
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_path_path_multidelegation",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=Testnet,
            spendingValue="m/1852'/1815'/0'/0/1",
            stakingValue="m/1852'/1815'/0'/2/60",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="005a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3f57d7728744a3104cca0c6184d4fac72412a0742bd5f40b653e155e2",
            human_readable_address="addr_test1qpd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vl404mjsaz2xyzvegxxrpx5ltrjgy4qws4ataqtv5lp2h3q30eyjm",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="009dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c65632d98d4780ae7b3dbec01542b10278012e1402b8624ba34a90563e17e"
        ),
    ),
    # LedgerJS: base address path/keyHash 1
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_path_keyhash_1",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=Testnet,
            spendingValue="m/1852'/1815'/0'/0/1",
            stakingValue="1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="005a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
            human_readable_address="addr_test1qpd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwq9nnhk4",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="009dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c65631d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c"
        ),
    ),
    # LedgerJS: base address path/keyHash 2
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_keyhash_2",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=FakeNet,
            spendingValue="m/1852'/1815'/0'/0/1",
            stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
            human_readable_address="addr1qdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcj922xhxkn6twlq2wn4q50q352annk3903tj00h45mgfmswz93l5",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="039dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c6563122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277"
        ),
    ),
    # LedgerJS: base address scriptHash/path
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_scripthash_path",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,
            netDesc=FakeNet,
            spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
            stakingValue="m/1852'/1815'/0'/2/0",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="13122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b42771d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
            human_readable_address="addr1zvfz49rtntfa9h0s98f6s28sg69weemgjhc4e8hm66d5yacayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwq8dxrpu",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="13122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277db219ee5ce9a74f98fdadc2de13efced5a154ef8d4d41929d5bf9ff6"
        ),
    ),
    # LedgerJS: base address scriptHash/path multidelegation
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_scripthash_path_multidelegation",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,
            netDesc=FakeNet,
            spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
            stakingValue="m/1852'/1815'/0'/2/3",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="13122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b427798acedf1c6b691f963d928147f66697c7cda3899e30c613037a4e990",
            human_readable_address="addr1zvfz49rtntfa9h0s98f6s28sg69weemgjhc4e8hm66d5yauc4nklr34kj8uk8kfgz3lkv6tu0ndr3x0rp3snqdayaxgqwrgxu2",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="13122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b427730cded62529ec7e50ee1d473ae77d00d72b977c1183d9836dd71fc7b"
        ),
    ),
    # LedgerJS: base address path/scriptHash
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_scripthash",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT,
            netDesc=FakeNet,
            spendingValue="m/1852'/1815'/0'/0/1",
            stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="235a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
            human_readable_address="addr1ydd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcj922xhxkn6twlq2wn4q50q352annk3903tj00h45mgfmssu7w24",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="239dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c6563122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277"
        ),
    ),
    # LedgerJS: base address scripthash/scriptHash
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_scripthash_scripthash",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT,
            netDesc=FakeNet,
            spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
            stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="33122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
            human_readable_address="addr1xvfz49rtntfa9h0s98f6s28sg69weemgjhc4e8hm66d5yacj922xhxkn6twlq2wn4q50q352annk3903tj00h45mgfms63y5us",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="33122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277"
        ),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_enterprise_path_1",
        params=AddressParams(
            addrType=AddressType.ENTERPRISE_KEY,
            netDesc=Testnet,
            spendingValue="m/1852'/1815'/0'/0/1",
        ),
        unit_test_expect=DeriveAddressExpectedResult(addressHex="605a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3"),
        ragger_expect=DeriveAddressExpectedResult(addressHex="609dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c6563"),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_enterprise_path_2",
        params=AddressParams(
            addrType=AddressType.ENTERPRISE_KEY,
            netDesc=FakeNet,
            spendingValue="m/1852'/1815'/0'/0/1",
        ),
        unit_test_expect=DeriveAddressExpectedResult(addressHex="635a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3"),
        ragger_expect=DeriveAddressExpectedResult(addressHex="639dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c6563"),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_enterprise_script_1",
        params=AddressParams(
            addrType=AddressType.ENTERPRISE_SCRIPT,
            netDesc=Testnet,
            spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
        unit_test_expect=DeriveAddressExpectedResult(addressHex="70122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277"),
        ragger_expect=DeriveAddressExpectedResult(addressHex="70122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277"),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_enterprise_script_2",
        params=AddressParams(
            addrType=AddressType.ENTERPRISE_SCRIPT,
            netDesc=FakeNet,
            spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
        unit_test_expect=DeriveAddressExpectedResult(addressHex="73122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277"),
        ragger_expect=DeriveAddressExpectedResult(addressHex="73122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277"),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_pointer_path_1",
        params=AddressParams(
            addrType=AddressType.POINTER_KEY,
            netDesc=Testnet,
            spendingValue="m/1852'/1815'/0'/0/1",
            stakingValue=pointer_to_str(1, 2, 3),
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="405a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3010203"
        ),
        ragger_expect=DeriveAddressExpectedResult(addressHex="409dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c6563010203"),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_pointer_path_2",
        params=AddressParams(
            addrType=AddressType.POINTER_KEY,
            netDesc=FakeNet,
            spendingValue="m/1852'/1815'/0'/0/1",
            stakingValue=pointer_to_str(24157, 177, 42),
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="435a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b381bc5d81312a"
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="439dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c656381bc5d81312a"
        ),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_pointer_path_3",
        params=AddressParams(
            addrType=AddressType.POINTER_KEY,
            netDesc=FakeNet,
            spendingValue="m/1852'/1815'/0'/0/1",
            stakingValue=pointer_to_str(0, 0, 0),
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="435a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3000000"
        ),
        ragger_expect=DeriveAddressExpectedResult(addressHex="439dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c6563000000"),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_pointer_script_1",
        params=AddressParams(
            addrType=AddressType.POINTER_SCRIPT,
            netDesc=Testnet,
            spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
            stakingValue=pointer_to_str(1, 2, 3),
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="50122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277010203"
        ),
        ragger_expect=DeriveAddressExpectedResult(addressHex="50122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277010203"),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_pointer_script_2",
        params=AddressParams(
            addrType=AddressType.POINTER_SCRIPT,
            netDesc=FakeNet,
            spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
            stakingValue=pointer_to_str(24157, 177, 42),
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="53122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b427781bc5d81312a"
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="53122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b427781bc5d81312a"
        ),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_pointer_script_3",
        params=AddressParams(
            addrType=AddressType.POINTER_SCRIPT,
            netDesc=FakeNet,
            spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
            stakingValue=pointer_to_str(0, 0, 0),
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="53122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277000000"
        ),
        ragger_expect=DeriveAddressExpectedResult(addressHex="53122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277000000"),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_reward_path_1",
        params=AddressParams(
            addrType=AddressType.REWARD_KEY,
            netDesc=Testnet,
            stakingValue="m/1852'/1815'/0'/2/0",
        ),
        unit_test_expect=DeriveAddressExpectedResult(addressHex="e01d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c"),
        ragger_expect=DeriveAddressExpectedResult(addressHex="e0db219ee5ce9a74f98fdadc2de13efced5a154ef8d4d41929d5bf9ff6"),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_reward_path_2",
        params=AddressParams(
            addrType=AddressType.REWARD_KEY,
            netDesc=FakeNet,
            stakingValue="m/1852'/1815'/0'/2/0",
        ),
        unit_test_expect=DeriveAddressExpectedResult(addressHex="e31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c"),
        ragger_expect=DeriveAddressExpectedResult(addressHex="e3db219ee5ce9a74f98fdadc2de13efced5a154ef8d4d41929d5bf9ff6"),
    ),
    # LedgerJS: reward multidelegation usual
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_reward_multidelegation",
        params=AddressParams(
            addrType=AddressType.REWARD_KEY,
            netDesc=Testnet,
            stakingValue="m/1852'/1815'/0'/2/1",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="e02cb40ca18704f49908b18bdfb4eee1ec80e2c3534b6924c3e6f50dc4",
            human_readable_address="stake_test1uqktgr9psuz0fxggkx9ald8wu8kgpckr2d9kjfxrum6sm3qp87652",
        ),
        ragger_expect=DeriveAddressExpectedResult(addressHex="e042bffc523b76535a17dee330dddf21334cb9da9616c560c43458cbdc"),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_reward_script_1",
        params=AddressParams(
            addrType=AddressType.REWARD_SCRIPT,
            netDesc=Testnet,
            stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
        unit_test_expect=DeriveAddressExpectedResult(addressHex="f0122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277"),
        ragger_expect=DeriveAddressExpectedResult(addressHex="f0122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277"),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_reward_script_2",
        params=AddressParams(
            addrType=AddressType.REWARD_SCRIPT,
            netDesc=FakeNet,
            stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
        unit_test_expect=DeriveAddressExpectedResult(addressHex="f3122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277"),
        ragger_expect=DeriveAddressExpectedResult(addressHex="f3122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277"),
    ),
]

shelleyTestCasesWithConfirm = [
    # LedgerJS: base address path/path unusual spending path account
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_path_unusual_spending_account",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=FakeNet,
            spendingValue="m/1852'/1815'/101'/0/1",
            stakingValue="m/1852'/1815'/0'/2/0",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="0334dc13790d917e116f174b23229799cbd1aca43925865cd8f99b79b61d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
            human_readable_address="addr1qv6dcymepkghuyt0za9jxg5hn89art9y8yjcvhxclxdhndsayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwqdqq9xn",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="03102b4fa906bc3491c2a3797cfe03681642ff89f1b2a0f1a1d7d74524db219ee5ce9a74f98fdadc2de13efced5a154ef8d4d41929d5bf9ff6"
        ),
    ),
    # LedgerJS: base address path/path unusual spending path address index
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_path_unusual_spending_index",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=FakeNet,
            spendingValue="m/1852'/1815'/1'/0/1000001",
            stakingValue="m/1852'/1815'/0'/2/0",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="03ce37595ec377a6602af2820c38115c502cf5e0a19d0508f510b321db1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
            human_readable_address="addr1q08rwk27cdm6vcp272pqcwq3t3gzea0q5xws2z84zzejrkcayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwq2cxp3q",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="03fd02349134a66b5676f827fcb5095ccff46334f7a5e9a4dd0d3f25e3db219ee5ce9a74f98fdadc2de13efced5a154ef8d4d41929d5bf9ff6"
        ),
    ),
    # LedgerJS: base address path/path unusual staking path account
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_path_unusual_staking_account",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=FakeNet,
            spendingValue="m/1852'/1815'/10'/0/4",
            stakingValue="m/1852'/1815'/101'/2/0",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="0383c42aab7238d7aaafa32780151b5dc1119f31eebf13d2833c83644a69749dcfca74ebc31f36a461b2c9af3556d2918769a9d51661a0d28c",
            human_readable_address="addr1qwpug24twgud02405vncq9gmthq3r8e3a6l3855r8jpkgjnfwjwuljn5a0p37d4yvxevnte42mffrpmf4823vcdq62xqm8xq3j",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="03bdc706b8e3a9a137925b06edb64ba4931ccce4dacf0c166138b07f1c20b3cdc6d7ea5757877bd0eb3e3ba9e9e402324056ee86adfa073d66"
        ),
    ),
    # LedgerJS: base address path/path multidelegation stake key unusual account
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_path_multidelegation_unusual_account",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=FakeNet,
            spendingValue="m/1852'/1815'/0'/0/1",
            stakingValue="m/1852'/1815'/101'/2/60",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b37c436829bf4e9cacd8e6a812b4fb2cf1574cede07cc5cf4dd8209b14",
            human_readable_address="addr1qdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vmugd5zn06wnjkd3e4gz260kt832axwmcruch85mkpqnv2qzt38al",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="039dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c6563ac4c779e6af80feb0c8c56adc07fd36a7e62e67f8717d84005ebe9ea"
        ),
    ),
    # LedgerJS: base address path/path multidelegation stake key unusual index
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_path_multidelegation_unusual_index",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=FakeNet,
            spendingValue="m/1852'/1815'/0'/0/1",
            stakingValue="m/1852'/1815'/0'/2/1000001",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3c2f7f9a41e78ef4b6818a0a7d0ad7b5da17a58934961f40109a6ada8",
            human_readable_address="addr1qdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63v7z7lu6g8ncaa9ksx9q5lg2676a59a93y6fv86qzzdx4k5qjp9hw2",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="039dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c65639b3fd2461f2d5fd88872aa74ff728b53076dfa549e9fca7ac14fa617"
        ),
    ),
    # LedgerJS: base address path/keyHash unusual account
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_path_keyhash_unusual_account",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=Testnet,
            spendingValue="m/1852'/1815'/101'/0/1",
            stakingValue="1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="0034dc13790d917e116f174b23229799cbd1aca43925865cd8f99b79b61d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
            human_readable_address="addr_test1qq6dcymepkghuyt0za9jxg5hn89art9y8yjcvhxclxdhndsayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwq9n0t8l",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="00102b4fa906bc3491c2a3797cfe03681642ff89f1b2a0f1a1d7d745241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c"
        ),
    ),
    # LedgerJS: base address path/keyHash unusual address index
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_path_keyhash_unusual_index",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            netDesc=Testnet,
            spendingValue="m/1852'/1815'/0'/0/1'",
            stakingValue="1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="00433895dc2f44713298d5a85b65f2571bb908955733f0c252c75a97a51d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
            human_readable_address="addr_test1qppn39wu9az8zv5c6k59ke0j2udmjzy42uelpsjjcadf0fgayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwqelwlvz",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="008ea7ec4df052418690cce387cde8674be95b77f9f38070c1627bbb3f1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c"
        ),
    ),
    # LedgerJS: base address scripthash/path unusual account
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_scripthash_path_unusual_account",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,
            netDesc=Testnet,
            spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
            stakingValue="m/1852'/1815'/200'/2/0",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="10122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277adf34012e3ec937857aa74e84316f9e39dba68ba443cfc748945e5d2",
            human_readable_address="addr_test1zqfz49rtntfa9h0s98f6s28sg69weemgjhc4e8hm66d5yaad7dqp9clvjdu902n5app3d70rnkax3wjy8n78fz29uhfqzs7q26",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="10122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277a060c2df50b1f70098514e955e13336b1f4959c52c980e5e59f1ce8f"
        ),
    ),
    # LedgerJS: base address path/scriptHash unusual account
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_path_scripthash_unusual_account",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT,
            netDesc=Testnet,
            spendingValue="m/1852'/1815'/101'/0/1",
            stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="2034dc13790d917e116f174b23229799cbd1aca43925865cd8f99b79b6122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
            human_readable_address="addr_test1yq6dcymepkghuyt0za9jxg5hn89art9y8yjcvhxclxdhndsj922xhxkn6twlq2wn4q50q352annk3903tj00h45mgfmsc0du6n",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="20102b4fa906bc3491c2a3797cfe03681642ff89f1b2a0f1a1d7d74524122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277"
        ),
    ),
    # LedgerJS: base address path/scriptHash unusual address index
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_path_scripthash_unusual_index",
        params=AddressParams(
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT,
            netDesc=Testnet,
            spendingValue="m/1852'/1815'/0'/0/1'",
            stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="20433895dc2f44713298d5a85b65f2571bb908955733f0c252c75a97a5122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
            human_readable_address="addr_test1yppn39wu9az8zv5c6k59ke0j2udmjzy42uelpsjjcadf0fgj922xhxkn6twlq2wn4q50q352annk3903tj00h45mgfmsyrvg3w",
        ),
        ragger_expect=DeriveAddressExpectedResult(
            addressHex="208ea7ec4df052418690cce387cde8674be95b77f9f38070c1627bbb3f122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277"
        ),
    ),
    # LedgerJS: pointer address unusual account
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_pointer_unusual_account",
        params=AddressParams(
            addrType=AddressType.POINTER_KEY,
            netDesc=Testnet,
            spendingValue="m/1852'/1815'/1000'/0/1",
            stakingValue=pointer_to_str(1, 0, 0),
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="400ec65e2f75b3add1df5190e453fce43c2fbc233db2e9080f71088ee9010000",
            human_readable_address="addr_test1gq8vvh30wke6m5wl2xgwg5luus7zl0pr8kewjzq0wyyga6gpqqqqze3mqg",
        ),
        ragger_expect=DeriveAddressExpectedResult(addressHex="4021d1f24c49ebcecfbe5079ca2594c23b87a6f19a32ecd52129f78d7c010000"),
    ),
    # LedgerJS: pointer address unusual address index
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_pointer_unusual_index",
        params=AddressParams(
            addrType=AddressType.POINTER_KEY,
            netDesc=Testnet,
            spendingValue="m/1852'/1815'/0'/0/1'",
            stakingValue=pointer_to_str(0, 7, 0),
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="40433895dc2f44713298d5a85b65f2571bb908955733f0c252c75a97a5000700",
            human_readable_address="addr_test1gppn39wu9az8zv5c6k59ke0j2udmjzy42uelpsjjcadf0fgqquqqpn6uug",
        ),
        ragger_expect=DeriveAddressExpectedResult(addressHex="408ea7ec4df052418690cce387cde8674be95b77f9f38070c1627bbb3f000700"),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_reward_multidelegation_unusual_account",
        params=AddressParams(
            addrType=AddressType.REWARD_KEY,
            netDesc=Testnet,
            stakingValue="m/1852'/1815'/101'/2/1",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="e05fcdb2be38b326b0931b5bd6b642c0973ded41bc010f7b08b939dbe8",
            human_readable_address="stake_test1up0umv478zejdvynrddaddjzcztnmm2phsqs77cghyuah6qnjw5hh",
        ),
        ragger_expect=DeriveAddressExpectedResult(addressHex="e0a9ac9841a1cd182f72c2cd42a502767a01ef8e582020c60631d11c86"),
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_reward_multidelegation_unusual_index",
        params=AddressParams(
            addrType=AddressType.REWARD_KEY,
            netDesc=Testnet,
            stakingValue="m/1852'/1815'/0'/2/20000000",
        ),
        unit_test_expect=DeriveAddressExpectedResult(addressHex="e0d132d41c7e5cb5e93efd601d4b7464994e45165e5822575050265512"),
        ragger_expect=DeriveAddressExpectedResult(addressHex="e08f2df9048352042b2693df894e52311ca0322d78db4493cf446a4045"),
    ),
    # LedgerJS: reward path unusual account
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_reward_unusual_account",
        params=AddressParams(
            addrType=AddressType.REWARD_KEY,
            netDesc=FakeNet,
            stakingValue="m/1852'/1815'/300'/2/0",
        ),
        unit_test_expect=DeriveAddressExpectedResult(
            addressHex="e3cf7d34dd943bd5cfb627c6da85b748d9e147f612200d3d376665c33d",
            human_readable_address="stake1u08h6dxajsaatnakylrd4pdhfrv7z3lkzgsq60fhvejux0gpcrd2j",
        ),
        ragger_expect=DeriveAddressExpectedResult(addressHex="e398153c743f2a67aa612db8292c48e6cdb65282c71f6020078068eb6f"),
    ),
]
