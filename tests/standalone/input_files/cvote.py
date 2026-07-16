# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for CIP-36 Vote check
"""

from dataclasses import dataclass

from tests.application_client.command_builder import (
    CIP36Vote,
    CVoteExpectedResult,
    CVoteTestCase,
)
from tests.application_client.security_warnings import WarningBit
from tests.application_client.status_words import StatusWord


@dataclass(kw_only=True, frozen=True)
class CVoteDenyTestCase:
    """Raw-payload deny test for the sign_cvote handler error paths.

    init_payload_hex is the APDU body for the INIT step (no 5-byte header).
    If invalid_witness_path is set, a valid INIT is sent first and then the
    CONFIRM step is sent with that path, expecting a security-policy denial.
    If send_chunk_before_init is True, a CHUNK APDU is sent without a prior
    INIT, expecting SWO_COMMAND_NOT_ALLOWED.
    """

    name: str
    expected_swo: StatusWord
    init_payload_hex: str | None = None
    invalid_witness_path: str | None = None
    send_chunk_before_init: bool = False


# pylint: disable=line-too-long
cvoteTestCases = [
    CVoteTestCase(
        name="Should_correctly_sign_a_CIP36_votecast_fragment",
        cVote=CIP36Vote(
            voteCastDataHex="36ad42885189a0ac3438cdb57bc8ac7f6542e05a59d1f2e4d1d38194c9d4ac7b000203f6639bdbc9235103825a9f025eae5cff3bd9c9dcc0f5a4b286909744746c8b6fb0018773d3b4308344d2e90599cd03749658561787eab714b542a5ccaf078846f6639bdbc9235103825a9f025eae5cff3bd9c9dcc0f5a4b286909744746c8b6fc8f58976fc0e951ba284a24f3fc190d914ae53aebcc523e7a4a330c8655b4908f6639bdbc9235103825a9f025eae5cff3bd9c9dcc0f5a4b286909744746c8b6fb0018773d3b4308344d2e90599cd03749658561787eab714b542a5ccaf078846021c76d0a50054ef7205cb95c1fd3f928f224fab8a8d70feaf4f5db90630c3845a06df2f11c881e396318bd8f9e9f135c2477e923c3decfd6be5466d6166fb3c702edd0d1d0a201fb8c51a91d01328da257971ca78cc566d4b518cb2cd261f96644067a7359a745fe239db8e73059883aece4d506be71c1262b137e295ce5f8a0aac22c1d8d343e5c8b5be652573b85cba8f4dcb46cfa4aafd8d59974e2eb65f480cf85ab522e23203c4f2faa9f95ebc0cd75b04f04fef5d4001d349d1307bb5570af4a91d8af4a489297a3f5255c1e12948787271275c50386ab2ef3980d882228e5f3c82d386e6a4ccf7663df5f6bbd9cbbadd6b2fea2668a8bf5603be29546152902a35fc44aae80d9dcd85fad6cde5b47a6bdc6257c5937f8de877d5ca0356ee9f12a061e03b99ab9dfea56295485cb5ce38cd37f56c396949f58b0627f455d26e4c5ff0bc61ab0ff05ffa07880d0e5c540bc45b527e8e85bb1da469935e0d3ada75d7d41d785d67d1d0732d7d6cbb12b23bfc21dfb4bbe3d933eaa1e5190a85d6e028706ab18d262375dd22a7c1a0e7efa11851ea29b4c92739aaabfee40353453ece16bda2f4a2c2f86e6b37f6de92dc45dba2eb811413c4af2c89f5fc0859718d7cd9888cd8d813da2e93726484ea5ce5be8ecf1e1490b874bd897ccd0cbc33db0a1751f813683724b7f5cf750f2497953607d1e82fb5d1429cbfd7a40ccbdba04fb648203c91e0809e497e80e9fad7895b844ba6da6ac690c7ce49c10e00000000000000000100ff00000000000000036d2ac8ddbf6eaac95401f91baca7f068e3c237386d7c9a271f5187ed90915587",
            witnessPath="m/1694'/1815'/0'/0/1",
        ),
        expected_warnings=[WarningBit.WARNING_BIT_CVOTE_WITNESS_NOT_FULLY_VERIFIABLE],
        unit_test_expect=CVoteExpectedResult(
            votecastHashHex="f51473df863be3e0383ce5a8da79c7ff51b3d98dadbbefbf9f042e8601901269",
            witnessSignatureHex="cbc615a8aa970cfffc6d122289f5379109cde5395cdc41c0c16b053283e3ac844e773ddca9c7df30e26910dcac54afc566126f42efc10150385f2639fcaa6102",
        ),
        ragger_expect=CVoteExpectedResult(
            votecastHashHex="f51473df863be3e0383ce5a8da79c7ff51b3d98dadbbefbf9f042e8601901269",
            witnessSignatureHex="ed8bc7b082a43750e216ea1bfbdd74b836b582caa4671845092595b66e6e6e824d1c7c99dd1dc13741d967a0f8013f4c7b42f05f147583edc36373f3b4e1c00d",
        ),
    )
]

# pylint: disable=line-too-long
cvoteDenyTestCases: list[CVoteDenyTestCase] = [
    CVoteDenyTestCase(
        name="cvote_deny_zero_remaining_bytes",
        # 4-byte length field is zero — app rejects before reading any chunk data.
        init_payload_hex="00000000",
        expected_swo=StatusWord.SWO_WRONG_DATA_LENGTH,
    ),
    CVoteDenyTestCase(
        name="cvote_deny_init_no_chunk_data",
        # Total length claims 100 bytes but no chunk follows — mismatch with
        # expected first-chunk size of min(100, 250) = 100.
        init_payload_hex="00000064",
        expected_swo=StatusWord.SWO_WRONG_DATA_LENGTH,
    ),
    CVoteDenyTestCase(
        name="cvote_deny_init_chunk_exceeds_declared_length",
        # Total length is 2 bytes but 3 bytes of data follow — chunk_size > total.
        init_payload_hex="00000002" + "aabbcc",
        expected_swo=StatusWord.SWO_WRONG_DATA_LENGTH,
    ),
    CVoteDenyTestCase(
        name="cvote_deny_chunk_before_init",
        # Attempt to send a CHUNK APDU before INIT has been performed.
        send_chunk_before_init=True,
        expected_swo=StatusWord.SWO_COMMAND_NOT_ALLOWED,
    ),
    CVoteDenyTestCase(
        name="cvote_deny_invalid_witness_path",
        # Valid INIT followed by CONFIRM with a non-cvote key path
        # (m/44'/1815'/0'/0/0 is a payment path, not PATH_CVOTE_KEY).
        invalid_witness_path="m/44'/1815'/0'/0/0",
        expected_swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
]
