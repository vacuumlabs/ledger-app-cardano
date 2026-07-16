# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
Minimal command builder used by the modernized test flows.

Provides chunks for the new handler_sign_tx protocol, the operational certificate
flow, and utility helpers shared by the standalone tests that still rely on this
module.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import IntEnum

from ragger.bip import pack_derivation_path

# ---------------------------------------------------------------------------
# Network / address protocol types (formerly app_def.py)
# ---------------------------------------------------------------------------


class ProtocolMagics(IntEnum):
    MAINNET = 0x2D964A09  # 764824073
    TESTNET = 0x2A  # 42, For integration tests
    TESTNET_LEGACY = 0x4170CB17  # 1097911063
    TESTNET_PREPROD = 1
    TESTNET_PREVIEW = 2
    FAKE = 47


class NetworkIds(IntEnum):
    TESTNET = 0x00
    MAINNET = 0x01
    FAKE = 0x03


class AddressType(IntEnum):
    BASE_PAYMENT_KEY_STAKE_KEY = 0x00
    BASE_PAYMENT_SCRIPT_STAKE_KEY = 0x01
    BASE_PAYMENT_KEY_STAKE_SCRIPT = 0x02
    BASE_PAYMENT_SCRIPT_STAKE_SCRIPT = 0x03
    POINTER_KEY = 0x04
    POINTER_SCRIPT = 0x05
    ENTERPRISE_KEY = 0x06
    ENTERPRISE_SCRIPT = 0x07
    BYRON = 0x08
    REWARD_KEY = 0x0E
    REWARD_SCRIPT = 0x0F


class StakingDataSourceType(IntEnum):
    NONE = 0x11
    KEY_PATH = 0x22
    KEY_HASH = 0x33
    BLOCKCHAIN_POINTER = 0x44
    SCRIPT_HASH = 0x55


@dataclass
class NetworkDesc:
    networkId: NetworkIds | int
    protocol: ProtocolMagics | int


class P1Type:
    P1_UNUSED = 0x00
    P1_TX_INIT = 0x10
    P1_TX_CHUNK = 0x11
    P1_TX_CONFIRM = 0x12
    P1_TX_AUX_DATA = 0x13
    P1_TX_SIGN_WITNESS = 0x0F
    P1_ADDRESS_RETURN = 0x01
    P1_ADDRESS_DISPLAY = 0x02
    P1_NATIVE_SCRIPT_INIT = 0x00
    P1_NATIVE_SCRIPT_START_COMPLEX = 0x01
    P1_NATIVE_SCRIPT_ADD_SIMPLE = 0x02
    P1_NATIVE_SCRIPT_FINISH = 0x03
    P1_CVOTE_INIT = 0x50
    P1_CVOTE_CHUNK = 0x51
    P1_CVOTE_CONFIRM = 0x52
    P1_SIGN_MSG_INIT = 0x01
    P1_SIGN_MSG_CHUNK = 0x02
    P1_SIGN_MSG_CONFIRM = 0x03


@dataclass
class AddressParams:
    """Protocol-level address parameters used for serialization."""

    addrType: AddressType
    netDesc: NetworkDesc
    spendingValue: str = ""
    stakingValue: str = ""


Mainnet = NetworkDesc(NetworkIds.MAINNET, ProtocolMagics.MAINNET)
Testnet = NetworkDesc(NetworkIds.TESTNET, ProtocolMagics.TESTNET)
Testnet_legacy = NetworkDesc(NetworkIds.TESTNET, ProtocolMagics.TESTNET_LEGACY)
FakeNet = NetworkDesc(NetworkIds.FAKE, ProtocolMagics.FAKE)


# ---------------------------------------------------------------------------
# Sign TX protocol types
# ---------------------------------------------------------------------------

MAX_SIGN_TX_CHUNK_SIZE = 250


class TransactionSigningMode(IntEnum):
    ORDINARY = 0x03
    POOL_REGISTRATION_OWNER = 0x04
    POOL_REGISTRATION_OPERATOR = 0x05
    MULTISIG = 0x06
    PLUTUS = 0x07
    UNRESTRICTED = 0x09
    AUTO = 0x08


class TxAuxiliaryDataType(IntEnum):
    ARBITRARY_HASH = 0x00
    CIP36_REGISTRATION = 0x01


class CredentialParamsType(IntEnum):
    KEY_HASH = 0x00
    SCRIPT_HASH = 0x01
    KEY_PATH = 0x02


class TxOutputFormat(IntEnum):
    ARRAY_LEGACY = 0x00
    MAP_BABBAGE = 0x01


class TxOutputDestinationType(IntEnum):
    THIRD_PARTY = 0x01
    DEVICE_OWNED = 0x02


class PoolKeyType(IntEnum):
    DEVICE_OWNED = 0x01
    THIRD_PARTY = 0x02


class VoteOption(IntEnum):
    NO = 0x00
    YES = 0x01
    ABSTAIN = 0x02


class VoterType(IntEnum):
    COMMITTEE_KEY_HASH = 0
    COMMITTEE_KEY_PATH = 100
    COMMITTEE_SCRIPT_HASH = 1
    DREP_KEY_HASH = 2
    DREP_KEY_PATH = 102
    DREP_SCRIPT_HASH = 3
    STAKE_POOL_KEY_HASH = 4
    STAKE_POOL_KEY_PATH = 104


class CertificateType(IntEnum):
    STAKE_REGISTRATION = 0
    STAKE_DEREGISTRATION = 1
    STAKE_DELEGATION = 2
    STAKE_POOL_REGISTRATION = 3
    STAKE_POOL_RETIREMENT = 4
    STAKE_REGISTRATION_CONWAY = 7
    STAKE_DEREGISTRATION_CONWAY = 8
    VOTE_DELEGATION = 9
    STAKE_POOL_AND_DREP_DELEGATION = 10
    ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL = 11
    ACCOUNT_REGISTRATION_DELEGATION_TO_DREP = 12
    ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP = 13
    AUTHORIZE_COMMITTEE_HOT = 14
    RESIGN_COMMITTEE_COLD = 15
    DREP_REGISTRATION = 16
    DREP_DEREGISTRATION = 17
    DREP_UPDATE = 18


class CIP36VoteRegistrationFormat(IntEnum):
    CIP_15 = 1
    CIP_36 = 2


class CIP36VoteDelegationType(IntEnum):
    KEY = 1
    PATH = 2


class DRepParamsType(IntEnum):
    KEY_HASH = 0
    SCRIPT_HASH = 1
    ABSTAIN = 2
    NO_CONFIDENCE = 3
    KEY_PATH = 100


class TxRequiredSignerType(IntEnum):
    PATH = 0
    HASH = 1


class DatumType(IntEnum):
    HASH = 0
    INLINE = 1


class RelayType(IntEnum):
    SINGLE_HOST_IP_ADDR = 0
    SINGLE_HOST_HOSTNAME = 1
    MULTI_HOST = 2


@dataclass
class TxInput:
    txHashHex: str
    path: str | None = None
    outputIndex: int = 0


@dataclass
class Token:
    assetNameHex: str
    amount: int


@dataclass
class AssetGroup:
    policyIdHex: str
    tokens: list[Token]


@dataclass
class ThirdPartyAddressParams:
    addressHex: str


@dataclass
class TxOutputDestination:
    type: TxOutputDestinationType
    params: ThirdPartyAddressParams | AddressParams


@dataclass
class Datum:
    type: DatumType
    datumHex: str


@dataclass
class TxOutputAlonzo:
    destination: TxOutputDestination
    amount: int
    format: TxOutputFormat = TxOutputFormat.ARRAY_LEGACY
    tokenBundle: list[AssetGroup] = field(default_factory=list)
    datum: Datum | None = None


@dataclass
class TxOutputBabbage:
    destination: TxOutputDestination
    amount: int
    format: TxOutputFormat = TxOutputFormat.MAP_BABBAGE
    tokenBundle: list[AssetGroup] = field(default_factory=list)
    datum: Datum | None = None
    referenceScriptHex: str | None = None


TxOutput = TxOutputAlonzo | TxOutputBabbage


@dataclass
class TxAuxiliaryDataHash:
    hashHex: str


@dataclass
class CIP36VoteDelegation:
    type: CIP36VoteDelegationType
    votingKeyPath: str
    weight: int


@dataclass
class TxAuxiliaryDataCIP36:
    format: CIP36VoteRegistrationFormat
    stakingPath: str
    paymentDestination: TxOutputDestination
    nonce: int
    voteKey: str | None = None
    votingPurpose: int | None = None
    delegations: list[CIP36VoteDelegation] = field(default_factory=list)


@dataclass
class TxAuxiliaryData:
    type: TxAuxiliaryDataType
    params: TxAuxiliaryDataHash | TxAuxiliaryDataCIP36


@dataclass
class RequiredSigner:
    type: TxRequiredSignerType
    pathOrHashHex: str  # BIP44 path (for PATH type) or 28-byte key hash hex (for HASH type)


@dataclass
class CredentialParams:
    type: CredentialParamsType
    keyValue: str | None = None  # keyPath, keyHash or scriptHash


@dataclass
class Withdrawal:
    stakeCredential: CredentialParams
    amount: int


@dataclass
class DRepParams:
    type: DRepParamsType
    keyValue: str | None = None  # keyPath, keyHash or scriptHash


@dataclass
class GovActionId:
    txHashHex: str
    govActionIndex: int


@dataclass
class AnchorParams:
    url: str
    hashHex: str


@dataclass
class VotingProcedure:
    vote: VoteOption
    anchor: AnchorParams | None = None


@dataclass
class Voter:
    type: VoterType
    keyValue: str  # keyPath, keyHash or scriptHash


@dataclass
class Vote:
    govActionId: GovActionId
    votingProcedure: VotingProcedure


@dataclass
class VoterVotes:
    voter: Voter
    votes: list[Vote]


@dataclass
class StakeRegistrationParams:
    stakeCredential: CredentialParams


@dataclass
class StakeRegistrationConwayParams:
    stakeCredential: CredentialParams
    deposit: int


@dataclass
class StakeDelegationParams:
    stakeCredential: CredentialParams
    poolKeyHash: str


@dataclass
class VoteDelegationParams:
    stakeCredential: CredentialParams
    dRep: DRepParams


@dataclass
class AccountRegistrationDelegationToStakePoolParams:
    stakeCredential: CredentialParams
    poolKeyHash: str
    coin: int


@dataclass
class AccountRegistrationDelegationToDRepParams:
    stakeCredential: CredentialParams
    dRep: DRepParams
    coin: int


@dataclass
class AccountRegistrationDelegationToStakePoolAndDRepParams:
    stakeCredential: CredentialParams
    poolKeyHash: str
    dRep: DRepParams
    coin: int


@dataclass
class StakePoolAndDRepDelegationParams:
    stakeCredential: CredentialParams
    poolKeyHash: str
    dRep: DRepParams


@dataclass
class AuthorizeCommitteeParams:
    coldCredential: CredentialParams
    hotCredential: CredentialParams


@dataclass
class ResignCommitteeParams:
    coldCredential: CredentialParams
    anchor: AnchorParams | None = None


@dataclass
class DRepRegistrationParams:
    dRepCredential: CredentialParams
    deposit: int
    anchor: AnchorParams | None = None


@dataclass
class DRepUpdateParams:
    dRepCredential: CredentialParams
    anchor: AnchorParams | None = None


@dataclass
class PoolRetirementParams:
    poolCredential: CredentialParams
    retirementEpoch: int


@dataclass
class Margin:
    numerator: int
    denominator: int


@dataclass
class PoolMetadataParams:
    metadataUrl: str
    metadataHashHex: str


@dataclass
class PoolKey:  # same for PoolRewardAccount and PoolOwner
    type: PoolKeyType
    key: str  # hex string or path


@dataclass
class SingleHostIpAddrRelayParams:
    portNumber: int | None = None
    ipv4: str | None = None
    ipv6: str | None = None


@dataclass
class SingleHostHostnameRelayParams:
    portNumber: int
    dnsName: str | None


@dataclass
class MultiHostRelayParams:
    dnsName: str | None


@dataclass
class Relay:
    type: RelayType
    params: SingleHostIpAddrRelayParams | SingleHostHostnameRelayParams | MultiHostRelayParams


@dataclass
class PoolRegistrationParams:
    poolKey: PoolKey
    vrfKeyHashHex: str
    pledge: int
    cost: int
    margin: Margin
    rewardAccount: PoolKey
    poolOwners: list[PoolKey]
    relays: list[Relay]
    metadata: PoolMetadataParams | None = None


@dataclass
class Certificate:
    type: CertificateType
    params: (
        StakeRegistrationParams
        | StakeRegistrationConwayParams
        | StakeDelegationParams
        | VoteDelegationParams
        | StakePoolAndDRepDelegationParams
        | AccountRegistrationDelegationToStakePoolParams
        | AccountRegistrationDelegationToDRepParams
        | AccountRegistrationDelegationToStakePoolAndDRepParams
        | AuthorizeCommitteeParams
        | ResignCommitteeParams
        | DRepRegistrationParams
        | DRepUpdateParams
        | PoolRegistrationParams
        | PoolRetirementParams
    )


@dataclass(kw_only=True)
class Transaction:
    network: NetworkDesc
    inputs: list[TxInput]
    outputs: list[TxOutput]
    fee: int = 42
    ttl: int | None = 10
    certificates: list[Certificate] = field(default_factory=list)
    withdrawals: list[Withdrawal] = field(default_factory=list)
    mint: list[AssetGroup] = field(default_factory=list)
    collateralInputs: list[TxInput] = field(default_factory=list)
    requiredSigners: list[RequiredSigner] = field(default_factory=list)
    referenceInputs: list[TxInput] = field(default_factory=list)
    votingProcedures: list[VoterVotes] = field(default_factory=list)
    auxiliaryData: TxAuxiliaryData | None = None
    validityIntervalStart: int | None = None
    scriptDataHash: str | None = None
    includeNetworkId: bool | None = None
    collateralOutput: TxOutput | None = None
    totalCollateral: int | None = None
    treasury: int | None = None
    donation: int | None = None


CLA: int = 0xD7

FLAG_INCLUDED_NO: int = 0x01
FLAG_INCLUDED_YES: int = 0x02
SETTINGS_DISABLED: int = 0x00
SETTINGS_ENABLED: int = 0x01
MAX_UINT8: int = 0xFF
MAX_UINT16: int = 0xFFFF
MAX_CIP8_MSG_CHUNK_SIZE = 250
MAX_CIP36_PAYLOAD_SIZE = 250


# ---------------------------------------------------------------------------
# OpCert protocol types
# ---------------------------------------------------------------------------


@dataclass
class OperationalCertificate:
    kesPublicKeyHex: str
    kesPeriod: int
    issueCounter: int
    path: str


@dataclass(kw_only=True)
class OpCertExpectedResult:
    signatureHex: str


@dataclass(kw_only=True)
class OpCertTestCase:
    name: str
    opCert: OperationalCertificate
    expected_warnings: list = field(default_factory=list)
    unit_test_expect: OpCertExpectedResult | None = None
    ragger_expect: OpCertExpectedResult | None = None


# ---------------------------------------------------------------------------
# CIP-36 CVote protocol types
# ---------------------------------------------------------------------------


@dataclass(kw_only=True)
class CIP36Vote:
    voteCastDataHex: str
    witnessPath: str


@dataclass(kw_only=True)
class CVoteExpectedResult:
    votecastHashHex: str
    witnessSignatureHex: str


@dataclass(kw_only=True)
class CVoteTestCase:
    name: str
    cVote: CIP36Vote
    expected_warnings: list
    unit_test_expect: CVoteExpectedResult | None = None
    ragger_expect: CVoteExpectedResult | None = None


# ---------------------------------------------------------------------------
# Native script protocol types
# ---------------------------------------------------------------------------


class NativeScriptType(IntEnum):
    PUBKEY_DEVICE_OWNED = 0x00
    PUBKEY_THIRD_PARTY = 0xF0
    ALL = 0x01
    ANY = 0x02
    N_OF_K = 0x03
    INVALID_BEFORE = 0x04
    INVALID_HEREAFTER = 0x05


class NativeScriptHashDisplayFormat(IntEnum):
    BECH32 = 0x01
    POLICY_ID = 0x02


@dataclass
class NativeScriptParamsPubkey:
    key: str


@dataclass
class NativeScriptParamsScripts:
    scripts: list[NativeScript] = field(default_factory=list)


@dataclass
class NativeScriptParamsNofK:
    requiredCount: int
    scripts: list[NativeScript] = field(default_factory=list)


@dataclass
class NativeScriptParamsInvalid:
    slot: int


NativeScriptParams = NativeScriptParamsPubkey | NativeScriptParamsScripts | NativeScriptParamsNofK | NativeScriptParamsInvalid


@dataclass
class NativeScript:
    type: NativeScriptType
    params: NativeScriptParams


# ---------------------------------------------------------------------------
# Sign Message protocol types
# ---------------------------------------------------------------------------


class MessageAddressFieldType(IntEnum):
    ADDRESS = 0x01
    KEY_HASH = 0x02


@dataclass
class MessageData:
    """CIP-8 message signing"""

    messageHex: str
    signingPath: str
    hashPayload: bool
    isAscii: bool
    addressFieldType: MessageAddressFieldType
    addressDesc: AddressParams | None = None


# Mirrors `src/apdu/dispatcher.h::command_e`.
# These are plain integer namespaces rather than IntEnums because APDU
# constants intentionally reuse numeric values across different commands.
class InsType:
    INS_NONE = -1
    INS_GET_VERSION = 0x00
    INS_GET_APP_NAME = 0x04
    INS_GET_SERIAL = 0x01
    INS_GET_PUBLIC_KEY = 0x10
    INS_DERIVE_ADDRESS = 0x11
    INS_DERIVE_NATIVE_SCRIPT_HASH = 0x12
    INS_SIGN_TX = 0x21
    INS_SIGN_OPCERT = 0x22
    INS_SIGN_CVOTE = 0x23
    INS_SIGN_MSG = 0x24
    INS_DEBUG_SET_SETTINGS = 0xF0  # Debug-only command


# Matches `src/apdu/dispatcher.h::p1_e`.
# Matches `src/apdu/dispatcher.h::p2_e`.
class P2Type:
    P2_UNUSED = 0x00
    # CVote auxiliary data P2 values (0x3x range)
    P2_AUX_DATA_INIT = 0x36
    P2_AUX_DATA_DELEGATION = 0x37


class CVoteCredentialType(IntEnum):
    # Canonical names match `src/cvote/cvote_types.h`.
    CVOTE_CREDENTIAL_KEY = 0
    CVOTE_CREDENTIAL_KEY_PATH = 2


def _credential_path_from_credential(credential: CredentialParams) -> str | None:
    if credential.type.name == "KEY_PATH":
        return credential.keyValue
    return None


def _pool_key_path(pool_key: PoolKey) -> str | None:
    if pool_key.type == PoolKeyType.DEVICE_OWNED:
        return pool_key.key
    return None


def _credential_paths_from_certificate(certificate: Certificate) -> list[str]:
    """Extract witness paths from a certificate (ledgerjs-compatible)."""
    paths: list[str] = []
    params = certificate.params

    if certificate.type == CertificateType.STAKE_REGISTRATION:
        return paths

    if certificate.type in (
        CertificateType.STAKE_REGISTRATION_CONWAY,
        CertificateType.STAKE_DEREGISTRATION,
        CertificateType.STAKE_DEREGISTRATION_CONWAY,
        CertificateType.STAKE_DELEGATION,
        CertificateType.VOTE_DELEGATION,
        CertificateType.STAKE_POOL_AND_DREP_DELEGATION,
        CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL,
        CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_DREP,
        CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP,
    ):
        assert isinstance(
            params,
            (
                StakeRegistrationParams,
                StakeRegistrationConwayParams,
                StakeDelegationParams,
                VoteDelegationParams,
                StakePoolAndDRepDelegationParams,
                AccountRegistrationDelegationToStakePoolParams,
                AccountRegistrationDelegationToDRepParams,
                AccountRegistrationDelegationToStakePoolAndDRepParams,
            ),
        )
        path = _credential_path_from_credential(params.stakeCredential)
        if path:
            paths.append(path)
        return paths

    if certificate.type in (
        CertificateType.AUTHORIZE_COMMITTEE_HOT,
        CertificateType.RESIGN_COMMITTEE_COLD,
    ):
        assert isinstance(params, (AuthorizeCommitteeParams, ResignCommitteeParams))
        path = _credential_path_from_credential(params.coldCredential)
        if path:
            paths.append(path)
        return paths

    if certificate.type in (
        CertificateType.DREP_REGISTRATION,
        CertificateType.DREP_DEREGISTRATION,
        CertificateType.DREP_UPDATE,
    ):
        assert isinstance(params, (DRepRegistrationParams, DRepUpdateParams))
        path = _credential_path_from_credential(params.dRepCredential)
        if path:
            paths.append(path)
        return paths

    if certificate.type == CertificateType.STAKE_POOL_REGISTRATION:
        assert isinstance(params, PoolRegistrationParams)
        pool_key_path = _pool_key_path(params.poolKey)
        if pool_key_path:
            paths.append(pool_key_path)
        for owner in params.poolOwners:
            owner_path = _pool_key_path(owner)
            if owner_path:
                paths.append(owner_path)
        return paths

    if certificate.type == CertificateType.STAKE_POOL_RETIREMENT:
        assert isinstance(params, PoolRetirementParams)
        path = _credential_path_from_credential(params.poolCredential)
        if path:
            paths.append(path)
        return paths

    return paths


def gather_witness_paths(tx: Transaction, signing_mode: int, additional_witness_paths: Sequence[str]) -> list[str]:
    """Return unique witness paths present in a transaction."""

    witness_paths: list[str] = []

    if signing_mode == TransactionSigningMode.MULTISIG:
        for additional_path in additional_witness_paths:
            if additional_path not in witness_paths:
                witness_paths.append(additional_path)
        return witness_paths

    for tx_input in tx.inputs:
        if tx_input.path and tx_input.path not in witness_paths:
            witness_paths.append(tx_input.path)

    for certificate in tx.certificates:
        cert_paths = _credential_paths_from_certificate(certificate)
        for cert_path in cert_paths:
            if cert_path not in witness_paths:
                witness_paths.append(cert_path)

    for withdrawal in tx.withdrawals:
        path = _credential_path_from_credential(withdrawal.stakeCredential)
        if path and path not in witness_paths:
            witness_paths.append(path)

    for required_signer in tx.requiredSigners:
        if required_signer.type == TxRequiredSignerType.PATH:
            if required_signer.pathOrHashHex not in witness_paths:
                witness_paths.append(required_signer.pathOrHashHex)

    for collateral_input in tx.collateralInputs:
        if collateral_input.path and collateral_input.path not in witness_paths:
            witness_paths.append(collateral_input.path)

    for voter_votes in tx.votingProcedures:
        if voter_votes.voter.type in (
            VoterType.COMMITTEE_KEY_PATH,
            VoterType.DREP_KEY_PATH,
            VoterType.STAKE_POOL_KEY_PATH,
        ):
            if voter_votes.voter.keyValue not in witness_paths:
                witness_paths.append(voter_votes.voter.keyValue)

    for additional_path in additional_witness_paths:
        if additional_path not in witness_paths:
            witness_paths.append(additional_path)

    return witness_paths


@dataclass(frozen=True)
class TxInitParams:
    options: int
    network_id: int
    protocol_magic: int
    signing_mode: int
    num_inputs: int
    num_outputs: int
    include_ttl: bool
    num_certificates: int
    num_withdrawals: int
    include_aux_data_hash: bool
    aux_data_type: int | None
    aux_data_hash_hex: str | None
    include_validity_interval_start: bool
    num_mint_asset_groups: int
    include_script_data_hash: bool
    num_collateral_inputs: int
    num_required_signers: int
    include_network_id: bool
    include_collateral_output: bool
    include_total_collateral: bool
    num_reference_inputs: int
    num_voters: int
    include_treasury: bool
    include_donation: bool
    num_witnesses: int
    raw_tx_total_length: int  # Size of raw transaction buffer (calculated by client)


class CommandBuilder:
    def serialize(
        self,
        ins: int,
        p1: int = P1Type.P1_UNUSED,
        p2: int = P2Type.P2_UNUSED,
        cdata: bytes = b"",
    ) -> bytes:
        if len(cdata) > MAX_UINT8:
            raise ValueError(f"Extended-length APDUs are not supported: payload length {len(cdata)}")

        header = bytes(
            [
                CLA,
                ins,
                p1,
                p2,
                len(cdata),
            ]
        )
        return header + cdata

    def get_version(self) -> bytes:
        return self.serialize(InsType.INS_GET_VERSION)

    def get_app_name(self) -> bytes:
        return self.serialize(InsType.INS_GET_APP_NAME)

    def get_serial(self) -> bytes:
        return self.serialize(InsType.INS_GET_SERIAL)

    def _serialize_voter(self, voter: Voter) -> bytes:
        voter_type = VoterType(voter.type)
        voter_data = bytearray()
        voter_data.append(int(voter_type))

        if voter_type in (
            VoterType.COMMITTEE_KEY_PATH,
            VoterType.DREP_KEY_PATH,
            VoterType.STAKE_POOL_KEY_PATH,
        ):
            voter_data.extend(pack_derivation_path(voter.keyValue))
        else:
            voter_data.extend(bytes.fromhex(voter.keyValue))

        return bytes(voter_data)

    def _serialize_address_params(self, params: AddressParams) -> bytes:
        """Serialize address parameters (shared by derive_address and sign_msg_init)"""
        data = b""
        data += params.addrType.to_bytes(1, "big")
        if params.addrType == AddressType.BYRON:
            data += params.netDesc.protocol.to_bytes(4, "big")
        else:
            data += params.netDesc.networkId.to_bytes(1, "big")

        if not params.spendingValue.startswith("m/"):
            data += bytes.fromhex(params.spendingValue)
        else:
            data += pack_derivation_path(params.spendingValue)

        if params.addrType in (
            AddressType.BYRON,
            AddressType.ENTERPRISE_KEY,
            AddressType.ENTERPRISE_SCRIPT,
        ):
            staking = StakingDataSourceType.NONE
        elif params.addrType in (
            AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT,
            AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT,
            AddressType.REWARD_SCRIPT,
        ):
            staking = StakingDataSourceType.SCRIPT_HASH
        elif params.addrType in (
            AddressType.POINTER_KEY,
            AddressType.POINTER_SCRIPT,
        ):
            staking = StakingDataSourceType.BLOCKCHAIN_POINTER
        elif not params.stakingValue.startswith("m/"):
            staking = StakingDataSourceType.KEY_HASH
        else:
            staking = StakingDataSourceType.KEY_PATH
        data += staking.to_bytes(1, "big")

        if staking == StakingDataSourceType.KEY_PATH:
            data += pack_derivation_path(params.stakingValue)
        elif staking in (
            StakingDataSourceType.KEY_HASH,
            StakingDataSourceType.SCRIPT_HASH,
            StakingDataSourceType.BLOCKCHAIN_POINTER,
        ):
            data += bytes.fromhex(params.stakingValue)
        elif staking != StakingDataSourceType.NONE:
            raise NotImplementedError("Not implemented yet")
        return data

    def derive_address(self, p1: int, params: AddressParams) -> bytes:
        data = self._serialize_address_params(params)
        return self.serialize(InsType.INS_DERIVE_ADDRESS, p1, P2Type.P2_UNUSED, data)

    def get_pubkey_path(self, path: str) -> bytes:
        data = pack_derivation_path(path)
        return self.serialize(InsType.INS_GET_PUBLIC_KEY, P1Type.P1_UNUSED, P2Type.P2_UNUSED, data)

    def sign_opcert(self, test_case: OpCertTestCase) -> bytes:
        data = bytearray()
        data.extend(bytes.fromhex(test_case.opCert.kesPublicKeyHex))
        data.extend(test_case.opCert.kesPeriod.to_bytes(8, "big"))
        data.extend(test_case.opCert.issueCounter.to_bytes(8, "big"))
        data.extend(pack_derivation_path(test_case.opCert.path))
        return self.serialize(InsType.INS_SIGN_OPCERT, P1Type.P1_UNUSED, P2Type.P2_UNUSED, bytes(data))

    def sign_cvote_init(self, testCase: CVoteTestCase) -> bytes:
        """APDU Builder for CIP36 Vote - INIT step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Full length of voteCastDataHex (4B)
        #    voteCastDataHex (first chunk, up to 250 B)
        data = b""
        payload_hex = testCase.cVote.voteCastDataHex
        # 2 hex chars per byte
        data_size = int(len(payload_hex) / 2)
        chunk_size = min(MAX_CIP36_PAYLOAD_SIZE * 2, len(payload_hex))
        data += data_size.to_bytes(4, "big")
        data += bytes.fromhex(payload_hex[:chunk_size])
        return self.serialize(InsType.INS_SIGN_CVOTE, P1Type.P1_CVOTE_INIT, P2Type.P2_UNUSED, data)

    def sign_cvote_chunk(self, testCase: CVoteTestCase) -> list[bytes]:
        """APDU Builder for CIP36 Vote - CHUNK step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Response APDU
        """

        # Serialization format:
        #    voteCastDataHex (following data, up to MAX_CIP36_PAYLOAD_SIZE B each)
        chunks = []
        payload = testCase.cVote.voteCastDataHex[MAX_CIP36_PAYLOAD_SIZE * 2 :]
        max_payload_size = MAX_CIP36_PAYLOAD_SIZE * 2  # 2 hex chars per byte
        while len(payload) > 0:
            chunks.append(
                self.serialize(
                    InsType.INS_SIGN_CVOTE,
                    P1Type.P1_CVOTE_CHUNK,
                    P2Type.P2_UNUSED,
                    bytes.fromhex(payload[:max_payload_size]),
                )
            )
            payload = payload[max_payload_size:]

        return chunks

    def sign_cvote_confirm(self, testCase: CVoteTestCase) -> bytes:
        """APDU Builder for CIP36 Vote - CONFIRM step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Witness path (1B for length + [0-5] x 4B)
        data = pack_derivation_path(testCase.cVote.witnessPath)
        return self.serialize(InsType.INS_SIGN_CVOTE, P1Type.P1_CVOTE_CONFIRM, P2Type.P2_UNUSED, data)

    def sign_tx_init(self, params: TxInitParams) -> bytes:
        data = bytearray()
        data.extend(params.options.to_bytes(8, "big"))
        data.append(params.network_id)
        data.extend(params.protocol_magic.to_bytes(4, "big"))
        data.append(params.signing_mode)
        data.extend(params.num_inputs.to_bytes(2, "big"))
        data.extend(params.num_outputs.to_bytes(2, "big"))
        data.append(FLAG_INCLUDED_YES if params.include_ttl else FLAG_INCLUDED_NO)
        data.extend(params.num_certificates.to_bytes(2, "big"))
        data.extend(params.num_withdrawals.to_bytes(2, "big"))
        data.append(FLAG_INCLUDED_YES if params.include_aux_data_hash else FLAG_INCLUDED_NO)
        if params.include_aux_data_hash:
            if params.aux_data_type is None:
                raise ValueError("Auxiliary data type is required when include_aux_data_hash is set")
            data.append(params.aux_data_type)
            if params.aux_data_hash_hex is None:
                if params.aux_data_type == TxAuxiliaryDataType.ARBITRARY_HASH:
                    raise ValueError("Auxiliary data hash is required for arbitrary-hash aux data")
            else:
                data.extend(bytes.fromhex(params.aux_data_hash_hex))
        data.append(FLAG_INCLUDED_YES if params.include_validity_interval_start else FLAG_INCLUDED_NO)
        data.extend(params.num_mint_asset_groups.to_bytes(2, "big"))
        data.append(FLAG_INCLUDED_YES if params.include_script_data_hash else FLAG_INCLUDED_NO)
        data.extend(params.num_collateral_inputs.to_bytes(2, "big"))
        data.extend(params.num_required_signers.to_bytes(2, "big"))
        data.append(FLAG_INCLUDED_YES if params.include_network_id else FLAG_INCLUDED_NO)
        data.append(FLAG_INCLUDED_YES if params.include_collateral_output else FLAG_INCLUDED_NO)
        data.append(FLAG_INCLUDED_YES if params.include_total_collateral else FLAG_INCLUDED_NO)
        data.extend(params.num_reference_inputs.to_bytes(2, "big"))
        data.extend(params.num_voters.to_bytes(2, "big"))
        data.append(FLAG_INCLUDED_YES if params.include_treasury else FLAG_INCLUDED_NO)
        data.append(FLAG_INCLUDED_YES if params.include_donation else FLAG_INCLUDED_NO)
        data.extend(params.num_witnesses.to_bytes(2, "big"))
        data.extend(params.raw_tx_total_length.to_bytes(2, "big"))
        return self.serialize(InsType.INS_SIGN_TX, P1Type.P1_TX_INIT, P2Type.P2_UNUSED, bytes(data))

    def derive_script_add_simple(self, script: NativeScript) -> bytes:
        data = b""
        script_type = 0 if script.type == NativeScriptType.PUBKEY_THIRD_PARTY else script.type
        data += script_type.to_bytes(1, "big")
        if script.type in (
            NativeScriptType.PUBKEY_DEVICE_OWNED,
            NativeScriptType.PUBKEY_THIRD_PARTY,
        ):
            assert isinstance(script.params, NativeScriptParamsPubkey)
            # Serialize extended credential format
            if script.params.key.startswith("m/"):
                # KEY_PATH credential
                data += CredentialParamsType.KEY_PATH.to_bytes(1, "big")
                data += pack_derivation_path(script.params.key)
            else:
                # KEY_HASH credential
                data += CredentialParamsType.KEY_HASH.to_bytes(1, "big")
                data += bytes.fromhex(script.params.key)
        elif script.type in (
            NativeScriptType.INVALID_BEFORE,
            NativeScriptType.INVALID_HEREAFTER,
        ):
            assert isinstance(script.params, NativeScriptParamsInvalid)
            data += script.params.slot.to_bytes(8, "big")
        return self.serialize(
            InsType.INS_DERIVE_NATIVE_SCRIPT_HASH,
            P1Type.P1_NATIVE_SCRIPT_ADD_SIMPLE,
            P2Type.P2_UNUSED,
            data,
        )

    def derive_script_init(self) -> bytes:
        return self.serialize(
            InsType.INS_DERIVE_NATIVE_SCRIPT_HASH,
            P1Type.P1_NATIVE_SCRIPT_INIT,
            P2Type.P2_UNUSED,
            b"",
        )

    def derive_script_add_complex(self, script: NativeScript) -> bytes:
        data = b""
        data += script.type.to_bytes(1, "big")
        if script.type in (NativeScriptType.ALL, NativeScriptType.ANY):
            assert isinstance(script.params, NativeScriptParamsScripts)
            data += len(script.params.scripts).to_bytes(4, "big")
        elif script.type == NativeScriptType.N_OF_K:
            assert isinstance(script.params, NativeScriptParamsNofK)
            data += len(script.params.scripts).to_bytes(4, "big")
            data += script.params.requiredCount.to_bytes(4, "big")
        return self.serialize(
            InsType.INS_DERIVE_NATIVE_SCRIPT_HASH,
            P1Type.P1_NATIVE_SCRIPT_START_COMPLEX,
            P2Type.P2_UNUSED,
            data,
        )

    def derive_script_finish(self, disp: NativeScriptHashDisplayFormat) -> bytes:
        data = disp.to_bytes(1, "big")
        return self.serialize(
            InsType.INS_DERIVE_NATIVE_SCRIPT_HASH,
            P1Type.P1_NATIVE_SCRIPT_FINISH,
            P2Type.P2_UNUSED,
            data,
        )

    def build_tx_init_params(
        self,
        tx: Transaction,
        signing_mode: int,
        witness_paths: list[str],
        options: int = 0,
    ) -> TxInitParams:
        include_aux_data_hash = tx.auxiliaryData is not None
        aux_data_type = None
        aux_data_hash_hex = None
        if include_aux_data_hash and tx.auxiliaryData is not None:
            if tx.auxiliaryData.type == TxAuxiliaryDataType.ARBITRARY_HASH:
                aux_data_type = TxAuxiliaryDataType.ARBITRARY_HASH
                aux_params = tx.auxiliaryData.params
                if isinstance(aux_params, TxAuxiliaryDataHash):
                    aux_data_hash_hex = aux_params.hashHex
            elif tx.auxiliaryData.type == TxAuxiliaryDataType.CIP36_REGISTRATION:
                aux_data_type = TxAuxiliaryDataType.CIP36_REGISTRATION

        # Calculate raw transaction buffer size
        raw_tx_data = self.serialize_transaction_unpacked_raw(tx)
        raw_tx_total_length = len(raw_tx_data)

        return TxInitParams(
            options=options,
            network_id=tx.network.networkId,
            protocol_magic=tx.network.protocol,
            signing_mode=signing_mode,
            num_inputs=len(tx.inputs),
            num_outputs=len(tx.outputs),
            include_ttl=tx.ttl is not None,
            num_certificates=len(tx.certificates),
            num_withdrawals=len(tx.withdrawals),
            include_aux_data_hash=include_aux_data_hash,
            aux_data_type=aux_data_type,
            aux_data_hash_hex=aux_data_hash_hex,
            include_validity_interval_start=tx.validityIntervalStart is not None,
            num_mint_asset_groups=len(tx.mint),
            include_script_data_hash=tx.scriptDataHash is not None,
            num_collateral_inputs=len(tx.collateralInputs),
            num_required_signers=len(tx.requiredSigners),
            include_network_id=bool(tx.includeNetworkId),
            include_collateral_output=tx.collateralOutput is not None,
            include_total_collateral=tx.totalCollateral is not None,
            num_reference_inputs=len(tx.referenceInputs),
            num_voters=len(tx.votingProcedures),
            include_treasury=tx.treasury is not None,
            include_donation=tx.donation is not None,
            num_witnesses=len(witness_paths),
            raw_tx_total_length=raw_tx_total_length,
        )

    def sign_tx_aux_data_init(self, aux_params: TxAuxiliaryDataCIP36) -> bytes:
        data = bytearray()
        data.append(aux_params.format)
        data.extend(len(aux_params.delegations).to_bytes(2, "big"))
        data.extend(self._serialize_cvote_key_or_path(aux_params.stakingPath))
        data.extend(self._serialize_output_destination(aux_params.paymentDestination))
        data.extend(aux_params.nonce.to_bytes(8, "big"))

        if aux_params.format == CIP36VoteRegistrationFormat.CIP_36:
            voting_purpose = aux_params.votingPurpose if aux_params.votingPurpose is not None else 0
            data.extend(voting_purpose.to_bytes(8, "big"))
            if len(aux_params.delegations) == 0:
                if aux_params.voteKey is None:
                    raise ValueError("CIP-36 vote key is required when delegations are empty")
                data.extend(self._serialize_cvote_key_or_path(aux_params.voteKey))
        else:
            if aux_params.voteKey is None:
                raise ValueError("CIP-15 vote key is required")
            data.extend(self._serialize_cvote_key_or_path(aux_params.voteKey))

        return self.serialize(
            InsType.INS_SIGN_TX,
            P1Type.P1_TX_AUX_DATA,
            P2Type.P2_AUX_DATA_INIT,
            bytes(data),
        )

    def sign_tx_aux_data_delegation(self, delegation: CIP36VoteDelegation) -> bytes:
        data = bytearray()
        data.extend(self._serialize_cvote_key_or_path(delegation.votingKeyPath))
        data.extend(delegation.weight.to_bytes(4, "big"))
        return self.serialize(
            InsType.INS_SIGN_TX,
            P1Type.P1_TX_AUX_DATA,
            P2Type.P2_AUX_DATA_DELEGATION,
            bytes(data),
        )

    def sign_tx_witness(self, path: str) -> bytes:
        data = pack_derivation_path(path)
        return self.serialize(InsType.INS_SIGN_TX, P1Type.P1_TX_SIGN_WITNESS, P2Type.P2_UNUSED, data)

    def debug_set_settings(self, expert_mode: bool, silent_export: bool, blind_signing: bool) -> bytes:
        """Build debug settings APDU (only works with DEBUG builds).

        Args:
            expert_mode: True to enable expert mode, False to disable
            silent_export: True to enable silent pubkey export, False to disable
            blind_signing: True to enable blind signing, False to disable

        Returns:
            Serialized APDU command
        """
        data = bytearray()
        data.append(SETTINGS_ENABLED if expert_mode else SETTINGS_DISABLED)
        data.append(SETTINGS_ENABLED if silent_export else SETTINGS_DISABLED)
        data.append(SETTINGS_ENABLED if blind_signing else SETTINGS_DISABLED)
        return self.serialize(
            InsType.INS_DEBUG_SET_SETTINGS,
            P1Type.P1_UNUSED,
            P2Type.P2_UNUSED,
            bytes(data),
        )

    def serialize_transaction_chunks(self, tx: Transaction) -> list[bytes]:
        if MAX_SIGN_TX_CHUNK_SIZE <= 0:
            raise ValueError("MAX_SIGN_TX_CHUNK_SIZE must be positive")
        tx_data = self.serialize_transaction_unpacked_raw(tx)
        if not tx_data:
            raise ValueError("Serialized transaction must not be empty")
        chunks: list[bytes] = []
        offset = 0
        while offset < len(tx_data):
            chunk_size = min(MAX_SIGN_TX_CHUNK_SIZE, len(tx_data) - offset)
            chunk_data = tx_data[offset : offset + chunk_size]
            offset += chunk_size
            more = offset < len(tx_data)
            p1 = P1Type.P1_TX_CHUNK if more else P1Type.P1_TX_CONFIRM
            chunk_apdu = self.serialize(InsType.INS_SIGN_TX, p1, P2Type.P2_UNUSED, chunk_data)
            chunks.append(chunk_apdu)
        return chunks

    def serialize_transaction_unpacked_raw(self, tx: Transaction) -> bytes:
        data = bytearray()
        for tx_input in tx.inputs:
            data.extend(bytes.fromhex(tx_input.txHashHex))
            data.extend(tx_input.outputIndex.to_bytes(4, "big"))

        for tx_output in tx.outputs:
            output_data = self._serialize_output(tx_output)
            data.extend(len(output_data).to_bytes(2, "big"))
            data.extend(output_data)

        data.extend(tx.fee.to_bytes(8, "big"))

        if tx.ttl is not None:
            data.extend(tx.ttl.to_bytes(8, "big"))

        for certificate in tx.certificates:
            data.extend(self._serialize_certificate(certificate))

        for withdrawal in tx.withdrawals:
            data.extend(withdrawal.amount.to_bytes(8, "big"))
            data.extend(self._serialize_credential_inline(withdrawal.stakeCredential))

        if tx.validityIntervalStart is not None:
            data.extend(tx.validityIntervalStart.to_bytes(8, "big"))

        for mint_asset_group in tx.mint:
            data.extend(bytes.fromhex(mint_asset_group.policyIdHex))
            data.extend(len(mint_asset_group.tokens).to_bytes(2, "big"))
            for token in mint_asset_group.tokens:
                asset_name_bytes = bytes.fromhex(token.assetNameHex)
                data.append(len(asset_name_bytes))
                data.extend(asset_name_bytes)
                data.extend(token.amount.to_bytes(8, "big", signed=True))

        if tx.scriptDataHash is not None:
            data.extend(bytes.fromhex(tx.scriptDataHash))

        for collateral_input in tx.collateralInputs:
            data.extend(bytes.fromhex(collateral_input.txHashHex))
            data.extend(collateral_input.outputIndex.to_bytes(4, "big"))

        for required_signer in tx.requiredSigners:
            data.append(int(required_signer.type))
            if required_signer.type == TxRequiredSignerType.PATH:
                data.extend(pack_derivation_path(required_signer.pathOrHashHex))
            else:
                data.extend(bytes.fromhex(required_signer.pathOrHashHex))

        if tx.collateralOutput is not None:
            collateral_data = self._serialize_output(tx.collateralOutput)
            data.extend(len(collateral_data).to_bytes(2, "big"))
            data.extend(collateral_data)

        if tx.totalCollateral is not None:
            data.extend(tx.totalCollateral.to_bytes(8, "big"))

        for reference_input in tx.referenceInputs:
            data.extend(bytes.fromhex(reference_input.txHashHex))
            data.extend(reference_input.outputIndex.to_bytes(4, "big"))

        for voter_votes in tx.votingProcedures:
            data.extend(self._serialize_voter(voter_votes.voter))

            # Serialize number of votes for this voter
            data.extend(len(voter_votes.votes).to_bytes(2, "big"))

            # Serialize each vote
            for vote in voter_votes.votes:
                # gov_action_id: tx_hash + index
                data.extend(bytes.fromhex(vote.govActionId.txHashHex))
                data.extend(vote.govActionId.govActionIndex.to_bytes(4, "big"))

                # voting_procedure: vote option
                data.append(vote.votingProcedure.vote)

                # anchor inclusion flag
                data.extend(self._serialize_anchor(vote.votingProcedure.anchor))

        if tx.treasury is not None:
            data.extend(tx.treasury.to_bytes(8, "big"))

        if tx.donation is not None:
            data.extend(tx.donation.to_bytes(8, "big"))

        return bytes(data)

    def _serialize_output(self, tx_output: TxOutput) -> bytearray:
        output_data = bytearray()
        output_data.extend(self._serialize_output_destination(tx_output.destination))

        output_data.extend(tx_output.amount.to_bytes(8, "big"))
        output_data.append(tx_output.format)

        has_datum = tx_output.datum is not None
        output_data.append(FLAG_INCLUDED_YES if has_datum else FLAG_INCLUDED_NO)
        has_ref_script = isinstance(tx_output, TxOutputBabbage) and tx_output.referenceScriptHex is not None
        output_data.append(FLAG_INCLUDED_YES if has_ref_script else FLAG_INCLUDED_NO)

        num_asset_groups = len(tx_output.tokenBundle)
        output_data.extend(num_asset_groups.to_bytes(2, "big"))

        if num_asset_groups > 0:
            for asset_group in tx_output.tokenBundle:
                output_data.extend(bytes.fromhex(asset_group.policyIdHex))
                output_data.extend(len(asset_group.tokens).to_bytes(2, "big"))
                for token in asset_group.tokens:
                    asset_name_bytes = bytes.fromhex(token.assetNameHex)
                    output_data.append(len(asset_name_bytes))
                    output_data.extend(asset_name_bytes)
                    output_data.extend(token.amount.to_bytes(8, "big"))

        if has_datum and tx_output.datum is not None:
            datum_type = tx_output.datum.type
            if datum_type == DatumType.HASH:
                output_data.append(int(DatumType.HASH))
                output_data.extend(bytes.fromhex(tx_output.datum.datumHex))
            elif datum_type == DatumType.INLINE:
                output_data.append(int(DatumType.INLINE))
                datum_bytes = bytes.fromhex(tx_output.datum.datumHex)
                output_data.extend(len(datum_bytes).to_bytes(2, "big"))
                output_data.extend(datum_bytes)
        if has_ref_script and isinstance(tx_output, TxOutputBabbage) and tx_output.referenceScriptHex is not None:
            script_bytes = bytes.fromhex(tx_output.referenceScriptHex)
            output_data.extend(len(script_bytes).to_bytes(2, "big"))
            output_data.extend(script_bytes)

        return output_data

    def _serialize_output_destination(self, tx_output_destination: TxOutputDestination) -> bytes:
        destination_data = bytearray()
        destination_data.append(tx_output_destination.type)

        if tx_output_destination.type == TxOutputDestinationType.THIRD_PARTY:
            assert isinstance(tx_output_destination.params, ThirdPartyAddressParams)
            address_bytes = bytes.fromhex(tx_output_destination.params.addressHex)
            destination_data.extend(len(address_bytes).to_bytes(2, "big"))
            destination_data.extend(address_bytes)
            return bytes(destination_data)

        assert isinstance(tx_output_destination.params, AddressParams)
        address_params = tx_output_destination.params
        destination_data.extend(self._serialize_address_params(address_params))
        return bytes(destination_data)

    def _serialize_cvote_key_or_path(self, key_or_path: str) -> bytes:
        data = bytearray()
        if key_or_path.startswith("m/"):
            data.append(CVoteCredentialType.CVOTE_CREDENTIAL_KEY_PATH)
            data.extend(pack_derivation_path(key_or_path))
        else:
            data.append(CVoteCredentialType.CVOTE_CREDENTIAL_KEY)
            data.extend(bytes.fromhex(key_or_path))
        return bytes(data)

    def _serialize_credential_inline(self, credential: CredentialParams) -> bytes:
        data = bytearray()
        if credential.keyValue is None:
            raise ValueError("Credential keyValue must be set")
        if credential.type == CredentialParamsType.KEY_PATH:
            data.append(CredentialParamsType.KEY_PATH)
            data.extend(pack_derivation_path(credential.keyValue))
        elif credential.type == CredentialParamsType.KEY_HASH:
            data.append(CredentialParamsType.KEY_HASH)
            data.extend(bytes.fromhex(credential.keyValue))
        elif credential.type == CredentialParamsType.SCRIPT_HASH:
            data.append(CredentialParamsType.SCRIPT_HASH)
            data.extend(bytes.fromhex(credential.keyValue))
        else:
            raise ValueError(f"Unsupported credential type: {credential.type}")
        return bytes(data)

    def _serialize_drep(self, drep: DRepParams) -> bytes:
        result = bytearray()
        result.append(int(drep.type))
        if drep.keyValue is not None:
            if drep.keyValue.startswith("m/"):
                result.extend(pack_derivation_path(drep.keyValue))
            else:
                result.extend(bytes.fromhex(drep.keyValue))
        return bytes(result)

    def _serialize_anchor(self, anchor: AnchorParams | None) -> bytes:
        result = bytearray()
        if anchor is None:
            result.append(FLAG_INCLUDED_NO)
            return bytes(result)

        result.append(FLAG_INCLUDED_YES)
        url_bytes = anchor.url.encode("utf-8")
        if len(url_bytes) > MAX_UINT16:
            raise ValueError("Anchor URL exceeds maximum encodable length")
        result.extend(len(url_bytes).to_bytes(2, "big"))
        result.extend(url_bytes)
        hash_bytes = bytes.fromhex(anchor.hashHex)
        result.extend(hash_bytes)
        return bytes(result)

    def _pool_key_to_credential(self, pool_key: PoolKey) -> CredentialParams:
        if pool_key.type == PoolKeyType.DEVICE_OWNED:
            return CredentialParams(type=CredentialParamsType.KEY_PATH, keyValue=pool_key.key)
        if pool_key.type == PoolKeyType.THIRD_PARTY:
            return CredentialParams(type=CredentialParamsType.KEY_HASH, keyValue=pool_key.key.lower())
        raise ValueError(f"Unsupported pool key type: {pool_key.type}")

    def _serialize_pool_key_reference(self, pool_key: PoolKey) -> bytes:
        return self._serialize_credential_inline(self._pool_key_to_credential(pool_key))

    def _serialize_relay(self, relay: Relay) -> bytes:
        data = bytearray()
        data.append(int(relay.type))
        if relay.type == RelayType.SINGLE_HOST_IP_ADDR:
            params = relay.params
            assert isinstance(params, SingleHostIpAddrRelayParams)
            if params.portNumber is None:
                data.append(FLAG_INCLUDED_NO)
            else:
                data.append(FLAG_INCLUDED_YES)
                data.extend(params.portNumber.to_bytes(2, "big"))
            if not params.ipv4:
                data.append(FLAG_INCLUDED_NO)
            else:
                data.append(FLAG_INCLUDED_YES)
                data.extend(ipaddress.IPv4Address(params.ipv4).packed)
            if not params.ipv6:
                data.append(FLAG_INCLUDED_NO)
            else:
                data.append(FLAG_INCLUDED_YES)
                data.extend(ipaddress.IPv6Address(params.ipv6).packed)
        elif relay.type == RelayType.SINGLE_HOST_HOSTNAME:
            params = relay.params
            assert isinstance(params, SingleHostHostnameRelayParams)
            if params.portNumber is None:
                data.append(FLAG_INCLUDED_NO)
            else:
                data.append(FLAG_INCLUDED_YES)
                data.extend(params.portNumber.to_bytes(2, "big"))
            if params.dnsName is None:
                data.append(FLAG_INCLUDED_NO)
                return bytes(data)
            data.append(FLAG_INCLUDED_YES)
            dns_bytes = params.dnsName.encode("utf-8")
            if len(dns_bytes) > MAX_UINT8:
                raise ValueError("Relay DNS name exceeds maximum length")
            data.append(len(dns_bytes))
            data.extend(dns_bytes)
        elif relay.type == RelayType.MULTI_HOST:
            params = relay.params
            assert isinstance(params, MultiHostRelayParams)
            if params.dnsName is None:
                data.append(FLAG_INCLUDED_NO)
                return bytes(data)
            data.append(FLAG_INCLUDED_YES)
            dns_bytes = params.dnsName.encode("utf-8")
            if len(dns_bytes) > MAX_UINT8:
                raise ValueError("Relay DNS name exceeds maximum length")
            data.append(len(dns_bytes))
            data.extend(dns_bytes)
        else:
            raise ValueError(f"Unsupported relay type: {relay.type}")
        return bytes(data)

    def _serialize_pool_metadata(self, metadata: PoolMetadataParams) -> bytes:
        """Serialize pool metadata URL and hash (presence flag is in pool registration header)."""
        data = bytearray()
        url_bytes = metadata.metadataUrl.encode("utf-8")
        if len(url_bytes) > MAX_UINT16:
            raise ValueError("Pool metadata URL exceeds maximum encodable length")
        data.extend(len(url_bytes).to_bytes(2, "big"))
        data.extend(url_bytes)
        hash_bytes = bytes.fromhex(metadata.metadataHashHex.lower())
        data.extend(hash_bytes)
        return bytes(data)

    def _serialize_pool_registration(self, params: PoolRegistrationParams) -> bytes:
        data = bytearray()
        data.extend(self._serialize_pool_key_reference(params.poolKey))
        vrf_bytes = bytes.fromhex(params.vrfKeyHashHex.lower())
        if len(vrf_bytes) != 32:
            raise ValueError("VRF key hash must be 32 bytes")
        data.extend(vrf_bytes)
        data.extend(params.pledge.to_bytes(8, "big"))
        data.extend(params.cost.to_bytes(8, "big"))
        data.extend(params.margin.numerator.to_bytes(8, "big"))
        data.extend(params.margin.denominator.to_bytes(8, "big"))
        data.extend(self._serialize_pool_key_reference(params.rewardAccount))
        data.extend(len(params.poolOwners).to_bytes(2, "big"))
        data.extend(len(params.relays).to_bytes(2, "big"))
        data.append(FLAG_INCLUDED_YES if params.metadata is not None else FLAG_INCLUDED_NO)
        for owner in params.poolOwners:
            credential = self._pool_key_to_credential(owner)
            data.extend(self._serialize_credential_inline(credential))
        for relay in params.relays:
            data.extend(self._serialize_relay(relay))
        if params.metadata is not None:
            data.extend(self._serialize_pool_metadata(params.metadata))
        return bytes(data)

    def _serialize_certificate(self, certificate: Certificate) -> bytes:
        result = bytearray()
        result.append(int(certificate.type))

        cert_type = certificate.type
        params = certificate.params

        if cert_type in (
            CertificateType.STAKE_REGISTRATION,
            CertificateType.STAKE_DEREGISTRATION,
        ):
            assert isinstance(params, StakeRegistrationParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
        elif cert_type in (
            CertificateType.STAKE_REGISTRATION_CONWAY,
            CertificateType.STAKE_DEREGISTRATION_CONWAY,
        ):
            assert isinstance(params, StakeRegistrationConwayParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
            result.extend(params.deposit.to_bytes(8, "big"))
        elif cert_type == CertificateType.STAKE_DELEGATION:
            assert isinstance(params, StakeDelegationParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
            result.extend(bytes.fromhex(params.poolKeyHash))
        elif cert_type == CertificateType.VOTE_DELEGATION:
            assert isinstance(params, VoteDelegationParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
            result.extend(self._serialize_drep(params.dRep))
        elif cert_type == CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL:
            assert isinstance(params, AccountRegistrationDelegationToStakePoolParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
            result.extend(bytes.fromhex(params.poolKeyHash))
            result.extend(params.coin.to_bytes(8, "big"))
        elif cert_type == CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_DREP:
            assert isinstance(params, AccountRegistrationDelegationToDRepParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
            result.extend(self._serialize_drep(params.dRep))
            result.extend(params.coin.to_bytes(8, "big"))
        elif cert_type == CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP:
            assert isinstance(params, AccountRegistrationDelegationToStakePoolAndDRepParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
            result.extend(bytes.fromhex(params.poolKeyHash))
            result.extend(self._serialize_drep(params.dRep))
            result.extend(params.coin.to_bytes(8, "big"))
        elif cert_type == CertificateType.STAKE_POOL_AND_DREP_DELEGATION:
            assert isinstance(params, StakePoolAndDRepDelegationParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
            result.extend(bytes.fromhex(params.poolKeyHash))
            result.extend(self._serialize_drep(params.dRep))
        elif cert_type == CertificateType.AUTHORIZE_COMMITTEE_HOT:
            assert isinstance(params, AuthorizeCommitteeParams)
            result.extend(self._serialize_credential_inline(params.coldCredential))
            result.extend(self._serialize_credential_inline(params.hotCredential))
        elif cert_type == CertificateType.RESIGN_COMMITTEE_COLD:
            assert isinstance(params, ResignCommitteeParams)
            result.extend(self._serialize_credential_inline(params.coldCredential))
            result.extend(self._serialize_anchor(params.anchor))
        elif cert_type == CertificateType.DREP_REGISTRATION:
            assert isinstance(params, DRepRegistrationParams)
            result.extend(self._serialize_credential_inline(params.dRepCredential))
            result.extend(params.deposit.to_bytes(8, "big"))
            result.extend(self._serialize_anchor(params.anchor))
        elif cert_type == CertificateType.DREP_DEREGISTRATION:
            assert isinstance(params, DRepRegistrationParams)
            result.extend(self._serialize_credential_inline(params.dRepCredential))
            result.extend(params.deposit.to_bytes(8, "big"))
        elif cert_type == CertificateType.DREP_UPDATE:
            assert isinstance(params, DRepUpdateParams)
            result.extend(self._serialize_credential_inline(params.dRepCredential))
            result.extend(self._serialize_anchor(params.anchor))
        elif cert_type == CertificateType.STAKE_POOL_REGISTRATION:
            assert isinstance(params, PoolRegistrationParams)
            pool_registration_payload = self._serialize_pool_registration(params)
            if len(pool_registration_payload) > MAX_UINT16:
                raise ValueError("Pool registration payload exceeds maximum encodable length")
            result.extend(len(pool_registration_payload).to_bytes(2, "big"))
            result.extend(pool_registration_payload)
        elif cert_type == CertificateType.STAKE_POOL_RETIREMENT:
            assert isinstance(params, PoolRetirementParams)
            result.extend(self._serialize_credential_inline(params.poolCredential))
            result.extend(params.retirementEpoch.to_bytes(8, "big"))
        else:
            raise ValueError(f"Unsupported certificate type: {cert_type}")

        return bytes(result)

    def sign_msg_init(self, testCase) -> bytes:
        """APDU Builder for CIP-8 Message Signing - INIT step

        Args:
            testCase: SignMsgTestCase with message data

        Returns:
            Serial data APDU
        """
        data = bytearray()

        # Message length (4 bytes BE)
        messageBytes = bytes.fromhex(testCase.msgData.messageHex)
        data.extend(len(messageBytes).to_bytes(4, "big"))

        # Signing path
        data.extend(pack_derivation_path(testCase.msgData.signingPath))

        # Hash payload flag (1 byte)
        data.append(FLAG_INCLUDED_YES if testCase.msgData.hashPayload else FLAG_INCLUDED_NO)

        # Is ASCII flag (1 byte)
        data.append(FLAG_INCLUDED_YES if testCase.msgData.isAscii else FLAG_INCLUDED_NO)

        # Address field type (1 byte)
        data.append(int(testCase.msgData.addressFieldType))

        # Address params (if type is ADDRESS)
        if testCase.msgData.addressFieldType == MessageAddressFieldType.ADDRESS:
            data.extend(self._serialize_address_params(testCase.msgData.addressDesc))

        return self.serialize(InsType.INS_SIGN_MSG, P1Type.P1_SIGN_MSG_INIT, P2Type.P2_UNUSED, bytes(data))

    def build_sign_msg_chunk_payloads(self, testCase) -> list[bytes]:
        messageBytes = bytes.fromhex(testCase.msgData.messageHex)
        chunk_sizes: list[int] = []
        remaining_bytes = len(messageBytes)

        # Both hashed and non-hashed messages use the same chunking:
        # each chunk is min(remaining, MAX_CIP8_MSG_CHUNK_SIZE)
        while remaining_bytes > 0:
            next_chunk = min(remaining_bytes, MAX_CIP8_MSG_CHUNK_SIZE)
            chunk_sizes.append(next_chunk)
            remaining_bytes -= next_chunk

        offset = 0
        payloads: list[bytes] = []
        for size in chunk_sizes:
            chunk_data = messageBytes[offset : offset + size]
            payloads.append(len(chunk_data).to_bytes(4, "big") + chunk_data)
            offset += size

        return payloads

    def sign_msg_chunks(self, testCase) -> list[bytes]:
        """APDU Builder for CIP-8 Message Signing - all CHUNK APDUs"""
        payloads = self.build_sign_msg_chunk_payloads(testCase)
        apdus: list[bytes] = []
        for payload in payloads:
            apdus.append(
                self.serialize(
                    InsType.INS_SIGN_MSG,
                    P1Type.P1_SIGN_MSG_CHUNK,
                    P2Type.P2_UNUSED,
                    payload,
                )
            )
        return apdus

    def sign_msg_confirm(self) -> bytes:
        """APDU Builder for CIP-8 Message Signing - CONFIRM step

        Returns:
            Serial data APDU (empty payload)
        """
        return self.serialize(InsType.INS_SIGN_MSG, P1Type.P1_SIGN_MSG_CONFIRM, P2Type.P2_UNUSED, b"")
