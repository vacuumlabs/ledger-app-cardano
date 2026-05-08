# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Sign Message
"""

from typing import Optional
from dataclasses import dataclass, field

from tests.application_client.command_builder import AddressParams, AddressType, Mainnet
from tests.application_client.security_warnings import WarningBit
from tests.application_client.status_words import StatusWord
from tests.application_client.command_builder import (
    CommandBuilder,
    InsType,
    MessageAddressFieldType,
    MessageData,
    P1Type,
    P2Type,
)


@dataclass(kw_only=True, frozen=True)
class SignMsgExpectedResult:
    signatureHex: str
    signingPublicKeyHex: str
    addressFieldHex: str


@dataclass(kw_only=True, frozen=True)
class SignMsgTestCase:
    name: str
    msgData: Optional[MessageData] = None
    unit_test_expect: Optional[SignMsgExpectedResult] = None
    expected_warnings: tuple[WarningBit, ...] = field(default_factory=tuple)
    ragger_expect: Optional[SignMsgExpectedResult] = None


@dataclass(kw_only=True, frozen=True)
class SignMsgDenyTestCase:
    name: str
    msgData: MessageData
    expected_swo: StatusWord
    # INIT-phase manipulation options
    invalid_address_field_type: Optional[int] = None
    invalid_msg_length: Optional[int] = None  # Override msgLength in INIT (4 bytes BE)
    truncate_init_apdu_at: Optional[int] = None  # Truncate INIT APDU at byte position
    trailing_init_bytes: int = (
        0  # Append N extra garbage bytes after valid INIT payload
    )
    # CHUNK-phase manipulation options
    invalid_chunk_size: Optional[int] = None  # Override chunk size in first CHUNK
    truncate_chunk_data_at: Optional[int] = (
        None  # Truncate chunk APDU payload to N bytes after size header
    )
    # Multi-phase testing: if True, manually craft APDU sequence
    send_chunk_without_init: bool = False
    send_init_when_active: bool = (
        False  # Send a second INIT while a session is already active
    )
    send_confirm_without_chunks: bool = False  # Skip CHUNK phase entirely
    send_confirm_with_payload: bool = False  # Add non-empty payload to CONFIRM
    send_confirm_without_init: bool = (
        False  # Send CONFIRM with no prior INIT (req_type mismatch)
    )
    send_chunk_when_in_confirm: bool = (
        False  # Complete chunks, then send extra CHUNK in CONFIRM state
    )


def build_sign_msg_init_apdu_for_deny(test_case: SignMsgDenyTestCase) -> bytes:
    transient_success_case = SignMsgTestCase(
        name=test_case.name,
        msgData=test_case.msgData,
    )
    init_apdu = bytearray(CommandBuilder().sign_msg_init(transient_success_case))

    # Apply INIT-phase manipulations
    if test_case.invalid_msg_length is not None:
        # Message length is in payload (after 5-byte header), first 4 bytes
        payload_offset = 5
        init_apdu[payload_offset : payload_offset + 4] = (
            test_case.invalid_msg_length.to_bytes(4, "big")
        )

    if test_case.invalid_address_field_type is not None:
        # KEY_HASH has no trailing address params; addressFieldType is the last cdata byte.
        init_apdu[-1] = test_case.invalid_address_field_type

    if test_case.truncate_init_apdu_at is not None:
        # Truncate the APDU and fix the Lc field to match the truncated payload length
        # APDU structure: CLA(1) INS(1) P1(1) P2(1) Lc(1) [payload...]
        # truncate_init_apdu_at is the total APDU length after truncation
        init_apdu = init_apdu[: test_case.truncate_init_apdu_at]
        # Update Lc field (byte 4) to match actual payload length
        new_payload_length = len(init_apdu) - 5  # Subtract 5-byte header
        if new_payload_length >= 0:
            init_apdu[4] = new_payload_length

    if test_case.trailing_init_bytes > 0:
        # Append garbage bytes after the valid payload and update Lc
        init_apdu.extend([0xFF] * test_case.trailing_init_bytes)
        init_apdu[4] = len(init_apdu) - 5  # Update Lc

    return bytes(init_apdu)


def build_sign_msg_chunk_apdu_for_deny(
    test_case: SignMsgDenyTestCase, chunk_index: int = 0
) -> bytes:
    """Build a CHUNK APDU with optional manipulation for deny testing."""
    transient_success_case = SignMsgTestCase(
        name=test_case.name,
        msgData=test_case.msgData,
    )
    chunk_apdus = CommandBuilder().sign_msg_chunks(transient_success_case)

    if chunk_index >= len(chunk_apdus):
        # Return empty chunk if no chunks needed (e.g., empty message)
        return CommandBuilder().serialize(
            InsType.INS_SIGN_MSG, P1Type.P1_SIGN_MSG_CHUNK, P2Type.P2_UNUSED, bytes()
        )

    chunk_apdu = bytearray(chunk_apdus[chunk_index])

    # Apply CHUNK-phase manipulations
    if test_case.invalid_chunk_size is not None and chunk_index == 0:
        # Chunk size is in the APDU data payload (first 4 bytes after APDU header)
        # APDU format: CLA INS P1 P2 Lc [chunk_size(4) chunk_data(...)]
        # The chunk_size field starts at offset 5 (after CLA/INS/P1/P2/Lc)
        chunk_apdu[5:9] = test_case.invalid_chunk_size.to_bytes(4, "big")

    if test_case.truncate_chunk_data_at is not None and chunk_index == 0:
        # Truncate the APDU payload to N bytes total (header + N data bytes)
        # This simulates a short-read where the chunk size header is present but data is cut short
        total_len = 5 + test_case.truncate_chunk_data_at
        chunk_apdu = chunk_apdu[:total_len]
        chunk_apdu[4] = test_case.truncate_chunk_data_at  # Update Lc

    return bytes(chunk_apdu)


def build_sign_msg_confirm_apdu_for_deny(test_case: SignMsgDenyTestCase) -> bytes:
    """Build a CONFIRM APDU with optional manipulation for deny testing."""
    if test_case.send_confirm_with_payload:
        # Add non-empty payload (should be denied)
        payload = b"\xde\xad\xbe\xef"
    else:
        payload = bytes()

    return CommandBuilder().serialize(
        InsType.INS_SIGN_MSG, P1Type.P1_SIGN_MSG_CONFIRM, P2Type.P2_UNUSED, payload
    )


# pylint: disable=line-too-long
signMsgTestCases = [
    SignMsgTestCase(
        name="Sign_msg_empty_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex="",
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="4ac0d7422617cb794c166b7137a4f097d08bb01b58091ca8c6e0b3816288a2869c8121daddab958cdc58899cc6e1e564e36d35753f9e032f23df00b249149e06",
            signingPublicKeyHex="b3d5f4158f0c391ee2a28a2e285f218f3e895ff6ff59cb9369c64b03b5bab5eb",
            addressFieldHex="5a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="bf03293e01d6039e8a9179cab3e76d4f96ac31ccb585767f78cc1a224e9770a2397934deb54446030f40ec788cf1994148028856a5bcea28e6f7c651ceb05007",
            signingPublicKeyHex="80a3ae98db92602aaee7170bc48b15ef9274d62521d37660561938066d16f658",
            addressFieldHex="9dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c6563",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_empty_ascii_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex="",
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=True,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="4ac0d7422617cb794c166b7137a4f097d08bb01b58091ca8c6e0b3816288a2869c8121daddab958cdc58899cc6e1e564e36d35753f9e032f23df00b249149e06",
            signingPublicKeyHex="b3d5f4158f0c391ee2a28a2e285f218f3e895ff6ff59cb9369c64b03b5bab5eb",
            addressFieldHex="5a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="bf03293e01d6039e8a9179cab3e76d4f96ac31ccb585767f78cc1a224e9770a2397934deb54446030f40ec788cf1994148028856a5bcea28e6f7c651ceb05007",
            signingPublicKeyHex="80a3ae98db92602aaee7170bc48b15ef9274d62521d37660561938066d16f658",
            addressFieldHex="9dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c6563",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_short_nonhashed_ascii_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex="68656c6c6f20776f726c64",  # "hello world"
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="d1fc9388b6cc0d7e80f4f72267ef53caae6d53420997128004b6e44cc1618b90496f1f4bdb63dcf9d1311cf2633cfbb0ec759a715825c6d509154739beecb607",
            signingPublicKeyHex="b3d5f4158f0c391ee2a28a2e285f218f3e895ff6ff59cb9369c64b03b5bab5eb",
            addressFieldHex="5a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="fd289169e3f5cecb19351e14ead979327f3cdf68a13bfb626fe75632ce8e9aacf58cc8eeebc17a44517c00e02ed451d8bb3ece43c8f14dbac9551c3a43277408",
            signingPublicKeyHex="80a3ae98db92602aaee7170bc48b15ef9274d62521d37660561938066d16f658",
            addressFieldHex="9dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c6563",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_short_hashed_ascii_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex="68656c6c6f20776f726c64",  # "hello world"
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=True,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="8a77cbd7000ca92ac902b76822abfc502074151b183857afa179c043dacd1b9230c0daa55558e7e2d32e6c2f5a9c4d41ae13da90ce4e70637a5f80b841286a05",
            signingPublicKeyHex="b3d5f4158f0c391ee2a28a2e285f218f3e895ff6ff59cb9369c64b03b5bab5eb",
            addressFieldHex="5a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="52d37a162674efec4d617cf581e3b65e7c0590dd6389a24fbeb83b7d347eb8d54f32e253ab3ed77368ba9922373869e3bd4d32552ab657dad4b2f41f8b8a2b03",
            signingPublicKeyHex="80a3ae98db92602aaee7170bc48b15ef9274d62521d37660561938066d16f658",
            addressFieldHex="9dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c6563",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_short_nonhashed_ascii_message_displayed_as_hex",
        msgData=MessageData(
            messageHex="68656c6c6f20776f726c64",  # "hello world"
            signingPath="m/1852'/1815'/0'/4/0",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="30ac6ab7f4ddc7779701324b163c52c68d4c0fd4af968122f1b43eea49b9586b366567395833ffb863ba1054863ab7191d09bdc5781f668db5c30b982fd37e07",
            signingPublicKeyHex="bc8c8a37d6ab41339bb073e72ce2e776cefed98d1a6d070ea5fada80dc7d6737",
            addressFieldHex="cf737588be6e9edeb737eb2e6d06e5cbd292bd8ee32e410c0bba1ba6",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="f96ef6b9baa7fb0cca50ad09e409d14aad5a9e57560b4cdf56a9d7aacd5a43a8ee76c4867bf9ab67f804903008f7117047673e0e69552cd1771f94e9faccf20e",
            signingPublicKeyHex="4d215c6bd6ba313cd42489028e5809cfea3c5c5198a696f5a9d08a23a1536fa3",
            addressFieldHex="32aad58ff63f0b6d601886d013f05cf80f045001a75f098e8fb3439d",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_short_nonhashed_hex_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex="ff656c6c6f20776f726c64",
            signingPath="m/1853'/1815'/0'/0'",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="3dcc9abb30584a15fd9ce39f790662a80331243d9f2978eca8549fba99740a8980c4bba73e6fc1cc1eee466e303c91542a13b9ee330c1c708cd04f9b093da403",
            signingPublicKeyHex="3d7e84dca8b4bc322401a2cc814af7c84d2992a22f99554fe340d7df7910768d",
            addressFieldHex="dbfee4665e58c8f8e9b9ff02b17f32e08a42c855476a5d867c2737b7",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="9a1706d14282da1411418f9fcf5f73ae661ec07f9770c4a4c235dc4f8212cec1b676b876ff6c06b518e5023793c668630110eec7f5a144befbca1f743d9c2706",
            signingPublicKeyHex="09dc9a6c151df265b4dbce84457fea3366aa95edc8a7a23b8da039e2db288d60",
            addressFieldHex="bc49ef1a996a510c0d794564bfa1ba96f25bb3f099d8aab5c39d91a3",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_short_hashed_hex_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex="ff656c6c6f20776f726c64",
            signingPath="m/1853'/1815'/0'/0'",
            hashPayload=True,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="0cd0dea4600a2eda7ab145bf600ca252d4a5911959a56fe0294e48e71a249db6e95ded5228e76c97b0add2aa1a8dfc0aed65acd46fc71ac0e99d4b917b1b870d",
            signingPublicKeyHex="3d7e84dca8b4bc322401a2cc814af7c84d2992a22f99554fe340d7df7910768d",
            addressFieldHex="dbfee4665e58c8f8e9b9ff02b17f32e08a42c855476a5d867c2737b7",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="1fa3fde745f9b1ee83435f1c7a1e269416c6b6edf798cab801fa4e37283d1bb1f2ef064abb2de3f3488d4a28eadab549da883aae9563f7231ded259405f75701",
            signingPublicKeyHex="09dc9a6c151df265b4dbce84457fea3366aa95edc8a7a23b8da039e2db288d60",
            addressFieldHex="bc49ef1a996a510c0d794564bfa1ba96f25bb3f099d8aab5c39d91a3",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_198_bytes_long_nonhashed_ascii_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex=f"{'6869' * 99}",
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=True,
            isAscii=True,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="6659bb68075cbb5d5b5ab0c6290f87931f8c0dddd4b6bea2ecbdb9b8519109a389f0408eeb917894c15db16019052f26da540fd29752d0f61285f78299770805",
            signingPublicKeyHex="7cc18df2fbd3ee1b16b76843b18446679ab95dbcd07b7833b66a9407c0709e37",
            addressFieldHex="ba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="f9f204bdbf55b4151edcf69ab3da7763b4b3b73f0b6ecc7ec9fc77765f21d22c115750ca3b7e4dcffcd813232ac7db428091ba10253100097f0cb1508e434802",
            signingPublicKeyHex="450d42914a4b8c738fde9b83d8648c244633b9ee9f9ace3a9809f13f1fc6404d",
            addressFieldHex="e287fcd9cdeaa13934aeb66515f7933169160ff15f2fcf21c323199d",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_99_bytes_long_nonhashed_hex_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex=f"{'de' * 99}",
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=True,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="4fadaf3541df071455d13d99da061b7b5056f19f88051c99ff59e7902ff15389eca1614c6e0faf9c29131c086b8fbb16d87e7ec7d19936c898fcbfdfb5d93602",
            signingPublicKeyHex="7cc18df2fbd3ee1b16b76843b18446679ab95dbcd07b7833b66a9407c0709e37",
            addressFieldHex="ba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="b2ca42c0a2748acc5197ea1447dba7e249fea8044ac16d55122e911862a4b86a524121cc927f90edcb966db4e8dcdfd4bed2fc4aad5de084f7064b24288d8205",
            signingPublicKeyHex="450d42914a4b8c738fde9b83d8648c244633b9ee9f9ace3a9809f13f1fc6404d",
            addressFieldHex="e287fcd9cdeaa13934aeb66515f7933169160ff15f2fcf21c323199d",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_1000_bytes_long_hashed_ascii_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex=f"{'6869' * 500}",
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=True,
            isAscii=True,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="87be8e7be2407ecb8324adb40d63cb4e7126378d0fa87f13e09226da896e11115b15275368ede14cdb42ea13b076dadc7f0eccf49d745312e2366cfb5105b906",
            signingPublicKeyHex="7cc18df2fbd3ee1b16b76843b18446679ab95dbcd07b7833b66a9407c0709e37",
            addressFieldHex="ba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="db19ffd33511d2ce738cfec1b2b4310dbac3738126b4486929bfe21599a7b7c5ee2665a87dea47c01fd23e4a61749ff4dd56e856cdcfd72f7eeada95f600f405",
            signingPublicKeyHex="450d42914a4b8c738fde9b83d8648c244633b9ee9f9ace3a9809f13f1fc6404d",
            addressFieldHex="e287fcd9cdeaa13934aeb66515f7933169160ff15f2fcf21c323199d",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_349_bytes_long_hashed_hex_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex=f"{'fa' * 349}",
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=True,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="6fcc42c954ecaa143c8fab436a5cc1d0beb4f46c29c7e554d3593d5c4343b27e83a66b3df011c3197e88032a2e879730c67db71ed0f2d9cd3e9a0978990d3a02",
            signingPublicKeyHex="7cc18df2fbd3ee1b16b76843b18446679ab95dbcd07b7833b66a9407c0709e37",
            addressFieldHex="ba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="6fc0bd038d914ec575b8be5ca8b3b4af805bd718b776bffcf89d1fec4a0f2cbc0227783945dffcfeecb18807ad5f8d8b36fe7e5d1115700022667a075609060c",
            signingPublicKeyHex="450d42914a4b8c738fde9b83d8648c244633b9ee9f9ace3a9809f13f1fc6404d",
            addressFieldHex="e287fcd9cdeaa13934aeb66515f7933169160ff15f2fcf21c323199d",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_short_nonhashed_hex_message_with_base_address_in_address_field",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/5/0",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.ADDRESS,
            addressDesc=AddressParams(
                netDesc=Mainnet,
                addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
                spendingValue="m/1852'/1815'/0'/0/1",
                stakingValue="m/1852'/1815'/0'/2/0",
            ),
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="92586e24a1a43b538720ea3915be0f6536f0894e4ea88713c01f948673865b6d2189a0306bbefc124954e578f8aa1d0f131b1d3e7af7827d1b4488d6fa0f6b07",
            signingPublicKeyHex="650eb87ddfffe7babd505f2d66c2db28b1c05ac54f9121589107acd6eb20cc2c",
            addressFieldHex="015a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="7f707820ce121e0c3f045273f97310f3ea16abc918a7252f70774e93875247539c17ed62f9bdcc8c93887508d9206cd134307a223ed1360ca9bd36347dbeb20e",
            signingPublicKeyHex="d485fbcd9bb1efe65672d27d3325178b58b155eb7f1e498ab19a0b59f770a53f",
            addressFieldHex="019dbd71e1951a09cede32a2411b34f55a476f85540aecdfba4d9c6563db219ee5ce9a74f98fdadc2de13efced5a154ef8d4d41929d5bf9ff6",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_short_nonhashed_hex_message_with_reward_address_in_address_field",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/5/0",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.ADDRESS,
            addressDesc=AddressParams(
                netDesc=Mainnet,
                addrType=AddressType.REWARD_KEY,
                spendingValue="",
                stakingValue="m/1852'/1815'/0'/2/0",
            ),
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="95044039aafdfedbd7a16b323475076e4960b78eb8e1864671f05e822ec975c219163ae7830103825777abe6e1bf854a302a96538ed129ff6131e29e8562b003",
            signingPublicKeyHex="650eb87ddfffe7babd505f2d66c2db28b1c05ac54f9121589107acd6eb20cc2c",
            addressFieldHex="e11d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="830f70c62bc643505d477ada996f3ddb37eb9dfcd129888bf3b616f9451c60c123c471c9782906f8dcb0865d58b741f8578a414085a984de556689b977e10f08",
            signingPublicKeyHex="d485fbcd9bb1efe65672d27d3325178b58b155eb7f1e498ab19a0b59f770a53f",
            addressFieldHex="e1db219ee5ce9a74f98fdadc2de13efced5a154ef8d4d41929d5bf9ff6",
        ),
    ),
    # --- Long non-hashed messages (multi-chunk, tests dynamic allocation) ---
    SignMsgTestCase(
        name="Sign_msg_257_bytes_long_nonhashed_ascii_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex=("68" * 257),  # 257 bytes of 'h' — not a multiple of 250
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=False,
            isAscii=True,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="f6e89b2b1b860ccdfd54b544ca25c7b758af40827d58f281e732b65247d067a869a0e07408b064ff90070eefe5b116e8f5aae20f454ddea539e78c762d60a804",
            signingPublicKeyHex="7cc18df2fbd3ee1b16b76843b18446679ab95dbcd07b7833b66a9407c0709e37",
            addressFieldHex="ba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="d345aad1e2b42578627038986cd7fe17ad94b0bdccc15deddcc3335494ca736732ed97db6f8597cc8f7ead7d355eb1462b914114881e04518bdefe8b06285a04",
            signingPublicKeyHex="450d42914a4b8c738fde9b83d8648c244633b9ee9f9ace3a9809f13f1fc6404d",
            addressFieldHex="e287fcd9cdeaa13934aeb66515f7933169160ff15f2fcf21c323199d",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_1000_bytes_long_nonhashed_ascii_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex=("6869" * 500),  # 1000 bytes of "hi" repeated
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=False,
            isAscii=True,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="b04b4f9d13449717d737c9dff7fb99a1dee6564800b3271b9fabc04e38caa16ba2531d091e103ea072c7bb29127e62a390b70dd1515251c121c89be157ffeb02",
            signingPublicKeyHex="7cc18df2fbd3ee1b16b76843b18446679ab95dbcd07b7833b66a9407c0709e37",
            addressFieldHex="ba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="7bf39c3024fb3724d45ab018e166873ad0f79f2aa0522c33d55ef1724af63e016ea7fed113e7f5fcafd81d0278a2a1fff83c683bacc7ebc27256c8e9f48c5e08",
            signingPublicKeyHex="450d42914a4b8c738fde9b83d8648c244633b9ee9f9ace3a9809f13f1fc6404d",
            addressFieldHex="e287fcd9cdeaa13934aeb66515f7933169160ff15f2fcf21c323199d",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_257_bytes_long_nonhashed_hex_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex=("de" * 257),  # 257 bytes of 0xDE — not a multiple of 250
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="c901e4058077a7453059fc62acda90ca068e9df86b066b57b306382434ea76e26c2e24b80104f5865c7fd058db6c80358ddd6b17588326f495f5d35de76e8a06",
            signingPublicKeyHex="7cc18df2fbd3ee1b16b76843b18446679ab95dbcd07b7833b66a9407c0709e37",
            addressFieldHex="ba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="604349e2b4752890d2544d560b90c70ab585ff09c91af4906c3c8410ffd0764ee2e37fba675df93475df31241aa10589279172cdd1bc466cd02ac31d2a69f20f",
            signingPublicKeyHex="450d42914a4b8c738fde9b83d8648c244633b9ee9f9ace3a9809f13f1fc6404d",
            addressFieldHex="e287fcd9cdeaa13934aeb66515f7933169160ff15f2fcf21c323199d",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_1000_bytes_long_nonhashed_hex_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex=("fa" * 1000),  # 1000 bytes of 0xFA
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="88214f57e37508a608227e7cf83ca81e3b762d9d3bf39c83506f96f7f99622a0ae9920ac10da9ee61d11d40716bb43e4adae1b2558960c86ecfc2e60b32b4f0e",
            signingPublicKeyHex="7cc18df2fbd3ee1b16b76843b18446679ab95dbcd07b7833b66a9407c0709e37",
            addressFieldHex="ba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="244dd90981561af0785d5f69e9484768de91e171104de628c79f03227b897f4623d5cd0793890e2b5f456fdc0a6acd10a758cfdf822c6d9092704520ff764b06",
            signingPublicKeyHex="450d42914a4b8c738fde9b83d8648c244633b9ee9f9ace3a9809f13f1fc6404d",
            addressFieldHex="e287fcd9cdeaa13934aeb66515f7933169160ff15f2fcf21c323199d",
        ),
    ),
    # --- Multisig DRep key path ---
    SignMsgTestCase(
        name="Sign_msg_with_multisig_drep_key_path",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1854'/1815'/0'/3/0",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="e003148240de3d14ca94ccc6604411142145cf028476f4e8213f8dbc2567cdc59ad7f9eb8ebf585404058f32a35316b37bbbd3fedda277b5f615e42ab8a00404",
            signingPublicKeyHex="2ead271505af50a1302dadc18d69452f2d7f1edf691265c3c9b004f1872068a6",
            addressFieldHex="68eb1a3b7d7d467b6d128ce5b36a2f64e8abccc1d7c6b6048de545af",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="44d8837eec4e2c8392d67faef946516e1f85c9b71c958bb11b0e35a5246bf4a94eeb72a999c1fb9d086285cb115765f49e4b8fefd3536d3f0368e0d6c4a1c400",
            signingPublicKeyHex="b7e837b7b4a8f1afe3bd2e180dddeabdf5b49207d16a06c8a3401a8b9da5ce7b",
            addressFieldHex="6b4f6eae3468a43104e37424d34846331a1ac3950759ad5168a08c28",
        ),
    ),
    # --- Test with unusual BIP44 path (WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH) ---
    SignMsgTestCase(
        name="Sign_msg_unusual_path_with_high_address_index",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/0/1000001",  # Address index > MAX_REASONABLE_ADDRESS (1000000)
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        expected_warnings=(WarningBit.WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH,),
        unit_test_expect=SignMsgExpectedResult(
            signatureHex="bc88d1fedb2d72f011996ba8c1b1e2b7c6e7acf4483290b702fc2b92f9a7e5af6973922323cee9fb5832d2d5454b13e6776b3dcccf257a311e3929f3cdf36205",
            signingPublicKeyHex="aa86984ca4b78a1d529ad8dc8800912b909197ae0db0563b98a4d0cb08567df7",
            addressFieldHex="6e699a204426b822f14a38dcee4e991ef2bc6d59b677eecede5e2221",
        ),
        ragger_expect=SignMsgExpectedResult(
            signatureHex="ccdfc21f193246c27b97c180909d8d7e6725a4f121e1165f5e8b1f25c593c4a20bb1ad0b8a3650caf50459b85a979f741aae6147e0ebf81c7393ee894677cf03",
            signingPublicKeyHex="f06134b1e7116c337143303a37d243b7fd647f485ddf0919db7e4885d4308220",
            addressFieldHex="e473db41b41b832bdfa106c8c2ee44060d622b7a4511c38928bee8ce",
        ),
    ),
]

signMsgDenyTestCases = [
    # ========== Address Field Type Validation ==========
    SignMsgDenyTestCase(
        name="Sign_msg_deny_nonexistent_address_field_type",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        invalid_address_field_type=0x03,
        expected_swo=StatusWord.SWO_SIGN_MSG_INVALID_ADDRESS_FIELD_TYPE,
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_invalid_address_field_type_zero",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        invalid_address_field_type=0x00,
        expected_swo=StatusWord.SWO_SIGN_MSG_INVALID_ADDRESS_FIELD_TYPE,
    ),
    # ========== Message Length Boundary Violations ==========
    SignMsgDenyTestCase(
        name="Sign_msg_deny_msg_length_exceeds_uint16_max",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        invalid_msg_length=0x10000,  # 65536, exceeds UINT16_MAX
        expected_swo=StatusWord.SWO_INSUFFICIENT_MEMORY,
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_nonascii_msg_causing_ui_hex_buffer_overflow",
        msgData=MessageData(
            messageHex="de"
            * 32768,  # 32768 bytes -> 65536 hex chars + 1 null + 2 safety = overflow
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        expected_swo=StatusWord.SWO_INSUFFICIENT_MEMORY,
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_ascii_msg_causing_ui_ascii_buffer_overflow",
        msgData=MessageData(
            messageHex="41" * 65534,  # 65534 bytes -> 65534 + 2 safety bytes = overflow
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=True,
            isAscii=True,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        expected_swo=StatusWord.SWO_INSUFFICIENT_MEMORY,
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_nonhashed_msg_causing_sig_structure_overflow",
        msgData=MessageData(
            messageHex="de"
            * 65280,  # Large enough to cause sig_structure overflow (UINT16_MAX - overhead)
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,  # Non-hashed payload uses raw message in sig_structure
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        expected_swo=StatusWord.SWO_INSUFFICIENT_MEMORY,
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_ascii_nonhashed_msg_causing_sig_structure_overflow",
        msgData=MessageData(
            messageHex="41"
            * 65280,  # 65280 bytes 'A'; SIG_STRUCTURE_OVERHEAD + 65280 = 65536 > UINT16_MAX
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,  # Non-hashed: raw message used as Sig_structure payload
            isAscii=True,  # ASCII flag skips hex-display overflow check; hits sig_structure check
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        expected_swo=StatusWord.SWO_INSUFFICIENT_MEMORY,
    ),
    # ========== INIT APDU Truncation (Parsing Failures) ==========
    # Note: Truncate only in the payload data, after CLA/INS/P1/P2/Lc header is complete
    SignMsgDenyTestCase(
        name="Sign_msg_deny_init_truncated_before_msg_length",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        truncate_init_apdu_at=7,  # CLA/INS/P1/P2/Lc(5) + 2 bytes partial msgLength = 7 total
        expected_swo=StatusWord.SWO_SIGN_MSG_PARSING_FAIL_MSG_LENGTH,
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_init_truncated_before_signing_path",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        truncate_init_apdu_at=9,  # After 4-byte msgLength, before BIP44 path
        expected_swo=StatusWord.SWO_SIGN_MSG_PARSING_FAIL_SIGNING_PATH,
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_init_truncated_before_hash_payload_flag",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        truncate_init_apdu_at=30,  # After path (5 header + 4 msgLen + 1+5*4 path = 30), before hashPayload
        expected_swo=StatusWord.SWO_SIGN_MSG_PARSING_FAIL_HASH_PAYLOAD,
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_init_truncated_before_is_ascii_flag",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        truncate_init_apdu_at=31,  # After hashPayload, before isAscii
        expected_swo=StatusWord.SWO_SIGN_MSG_PARSING_FAIL_IS_ASCII,
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_init_truncated_before_address_field_type",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        truncate_init_apdu_at=32,  # After isAscii, before addressFieldType
        expected_swo=StatusWord.SWO_SIGN_MSG_PARSING_FAIL_ADDRESS_FIELD_TYPE,
    ),
    # ========== Chunk Size Validation ==========
    SignMsgDenyTestCase(
        name="Sign_msg_deny_chunk_size_exceeds_remaining_bytes",
        msgData=MessageData(
            messageHex="de" * 10,  # 10 bytes total
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        invalid_chunk_size=11,  # Claim 11 bytes when only 10 remain
        expected_swo=StatusWord.SWO_SIGN_MSG_INVALID_CHUNK_SIZE,
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_chunk_size_smaller_than_expected_for_nonfinal_chunk",
        msgData=MessageData(
            messageHex="de" * 300,  # 300 bytes (needs 2 chunks: 250 + 50)
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        invalid_chunk_size=249,  # First chunk should be exactly 250, not 249
        expected_swo=StatusWord.SWO_SIGN_MSG_INVALID_CHUNK_SIZE,
    ),
    # ========== ASCII Validation ==========
    SignMsgDenyTestCase(
        name="Sign_msg_deny_nonascii_byte_in_message_marked_as_ascii",
        msgData=MessageData(
            messageHex="68656c6c6fff",  # "hello" + 0xFF (non-ASCII)
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=True,  # Marked as ASCII but contains non-ASCII byte
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        expected_swo=StatusWord.SWO_SIGN_MSG_INVALID_ASCII,
    ),
    # ========== State Sequencing ==========
    SignMsgDenyTestCase(
        name="Sign_msg_deny_chunk_without_init",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        send_chunk_without_init=True,
        expected_swo=StatusWord.SWO_COMMAND_NOT_ALLOWED,
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_confirm_before_all_chunks_received",
        msgData=MessageData(
            messageHex="de" * 300,  # 300 bytes (needs 2 chunks but we skip them)
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        send_confirm_without_chunks=True,
        expected_swo=StatusWord.SWO_COMMAND_NOT_ALLOWED,
    ),
    # ========== CONFIRM Payload Validation ==========
    SignMsgDenyTestCase(
        name="Sign_msg_deny_confirm_with_nonempty_payload",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        send_confirm_with_payload=True,
        expected_swo=StatusWord.SWO_SIGN_MSG_CONFIRM_MUST_BE_EMPTY,
    ),
    # ========== Security Policy Validation ==========
    SignMsgDenyTestCase(
        name="Sign_msg_deny_invalid_witness_path_wrong_coin_type",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/0'/0'/0/0",  # Coin type 0 (Bitcoin) instead of 1815 (Cardano) -> PATH_INVALID
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_invalid_witness_path_wrong_length",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'",  # Length 3 (account level) instead of 5 -> valid for account but not allowed for message signing
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_invalid_address_type_pointer_in_address_mode",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/5/0",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.ADDRESS,
            addressDesc=AddressParams(
                netDesc=Mainnet,
                addrType=AddressType.POINTER_KEY,  # POINTER_KEY: parsing will fail due to missing blockchain pointer data
                spendingValue="m/1852'/1815'/0'/0/1",
                stakingValue="",
            ),
        ),
        expected_swo=StatusWord.SWO_SIGN_MSG_PARSING_FAIL_ADDRESS_PARAMS,  # Fails during parsing, not policy
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_invalid_address_type_byron_in_address_mode",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/5/0",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.ADDRESS,
            addressDesc=AddressParams(
                netDesc=Mainnet,
                addrType=AddressType.BYRON,  # BYRON not allowed by policyForSignMsg
                spendingValue="m/44'/1815'/0'/0/1",
                stakingValue="",
            ),
        ),
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignMsgDenyTestCase(
        name="Sign_msg_deny_invalid_address_type_payment_script_in_address_mode",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/5/0",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.ADDRESS,
            addressDesc=AddressParams(
                netDesc=Mainnet,
                addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,  # Payment script: parsing will fail due to missing script hash
                spendingValue="",  # Scripts don't have paths
                stakingValue="m/1852'/1815'/0'/2/0",
            ),
        ),
        expected_swo=StatusWord.SWO_SIGN_MSG_PARSING_FAIL_ADDRESS_PARAMS,  # Fails during parsing, not policy
    ),
]
