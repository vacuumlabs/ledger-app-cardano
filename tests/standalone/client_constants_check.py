# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E402

from __future__ import annotations

import sys
from pathlib import Path
import re
from typing import Mapping, Any

ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = ROOT / "tests"
for extra_path in (ROOT, TESTS_ROOT):
    str_extra = str(extra_path)
    if str_extra not in sys.path:
        sys.path.insert(0, str_extra)

from tests.application_client.command_builder import (
    AddressType,
    NetworkIds,
    ProtocolMagics,
    StakingDataSourceType,
)
from tests.application_client.command_builder import (
    CertificateType,
    CLA,
    CredentialParamsType,
    CVoteCredentialType,
    DatumType,
    DRepParamsType,
    InsType,
    MAX_CIP36_PAYLOAD_SIZE,
    MAX_CIP8_MSG_CHUNK_SIZE,
    MAX_SIGN_TX_CHUNK_SIZE,
    MessageAddressFieldType,
    NativeScriptHashDisplayFormat,
    P1Type,
    P2Type,
    RelayType,
    TransactionSigningMode,
    TxAuxiliaryDataType,
    TxOutputDestinationType,
    TxOutputFormat,
    TxRequiredSignerType,
    VoteOption,
    VoterType,
)
from tests.application_client.response_unpacker import (
    unpack_get_pubkey_response,
    unpack_get_serial_response,
    unpack_get_version_response,
    unpack_sign_cip36_confirm_response,
    unpack_sign_message_response,
)
from tests.application_client.security_warnings import WarningBit
from tests.application_client.status_words import StatusWord
from tests.standalone.settings import (
    DEFAULT_SETTING_VALUES,
    SETTINGS_ORDER,
    SettingID,
    SettingValue,
)


def _parse_defines(path: Path) -> Mapping[str, int]:
    defines: dict[str, int] = {}
    for line in path.read_text().splitlines():
        match = re.match(
            r"#define\s+(\w+)\s+\(?\s*(0x[0-9A-Fa-f]+|\d+)(?:[uUlL]*)\s*\)?", line
        )
        if match:
            defines[match.group(1)] = int(match.group(2), 0)
    return defines


def _parse_enum(path: Path) -> Mapping[str, int]:
    values: dict[str, int] = {}
    for line in path.read_text().splitlines():
        for match in re.finditer(r"(\w+)\s*=\s*(-?(?:0x[0-9A-Fa-f]+|\d+))", line):
            values[match.group(1)] = int(match.group(2), 0)
    return values


def _parse_sequential_enum(path: Path, enum_name: str) -> Mapping[str, int]:
    """Parse a C enum that uses implicit sequential values (no explicit = N assignments)."""
    text = path.read_text()
    # Extract the body of the named enum
    pattern = re.compile(
        r"typedef\s+enum\s*\{([^}]*)\}\s*" + re.escape(enum_name) + r"\s*;",
        re.DOTALL,
    )
    match = pattern.search(text)
    if not match:
        raise AssertionError(f"Enum {enum_name} not found in {path}")
    body = match.group(1)
    values: dict[str, int] = {}
    counter = 0
    for line in body.splitlines():
        line = line.split("//")[0].strip().rstrip(",").strip()
        if not line:
            continue
        if "=" in line:
            name, _, rhs = line.partition("=")
            name = name.strip()
            rhs = rhs.strip()
            counter = int(rhs, 0)
        else:
            name = line.strip()
        if re.match(r"^\w+$", name):
            values[name] = counter
            counter += 1
    return values


def _parse_anonymous_sequential_enum(
    text: str, sentinel_name: str
) -> Mapping[str, int]:
    pattern = re.compile(
        r"enum\s*\{([^}]*)\s*" + re.escape(sentinel_name) + r"\s*\};",
        re.DOTALL,
    )
    match = pattern.search(text)
    if not match:
        raise AssertionError(f"Anonymous enum ending with {sentinel_name} not found")
    body = match.group(1)
    values: dict[str, int] = {}
    counter = 0
    for raw_entry in body.split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        if "=" in entry:
            name, _, rhs = entry.partition("=")
            name = name.strip()
            rhs = rhs.strip()
            counter = int(rhs, 0)
        else:
            name = entry
        values[name] = counter
        counter += 1
    return values


def _security_warnings_header_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "src"
        / "securityPolicy"
        / "securityWarnings.h"
    )


def _dispatcher_header_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "apdu" / "dispatcher.h"


def _handler_sign_tx_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "handler" / "sign_tx.h"


def _handler_sign_msg_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "handler" / "sign_msg.h"


def _cvote_types_header_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "cvote" / "cvote_types.h"


def _cardano_settings_header_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "cardano_settings.h"


def _app_main_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "app_main.c"


def _menu_c_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "ui" / "menu.c"


def _cardano_swo_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "cardano_swo.h"


def _cardano_constants_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "cardano_constants.h"


def _address_utils_shelley_header_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "src"
        / "addressUtils"
        / "addressUtilsShelley.h"
    )


def _tx_header_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "transaction" / "tx.h"


def _tx_credential_types_header_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "src"
        / "transaction"
        / "tx_credential_types.h"
    )


def _tx_output_types_header_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "src"
        / "transaction"
        / "tx_output_types.h"
    )


def _tx_certificate_types_header_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "src"
        / "transaction"
        / "tx_certificate_types.h"
    )


def _message_signing_header_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "src"
        / "messageSigning"
        / "messageSigning.h"
    )


def _derive_native_script_hash_header_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "src"
        / "handler"
        / "derive_native_script_hash.h"
    )


def _globals_header_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "globals.h"


def _key_derivation_header_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "src"
        / "keyDerivation"
        / "keyDerivation.h"
    )


def _get_version_header_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "handler" / "get_version.h"


def _get_serial_c_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "handler" / "get_serial.c"


def _vote_cast_hash_builder_header_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "src"
        / "cvote"
        / "vote_cast_hash_builder.h"
    )


def _response_unpacker_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "tests"
        / "application_client"
        / "response_unpacker.py"
    )


def _assert_dispatcher_enum_prefix(
    prefix: str, enum_cls: type[Any], dispatcher_values: Mapping[str, int]
) -> None:
    for name, value in dispatcher_values.items():
        if not name.startswith(prefix):
            continue
        if not hasattr(enum_cls, name):
            raise AssertionError(f"{name} missing from {enum_cls.__name__}")
        attr_value = getattr(enum_cls, name)
        if int(attr_value) != value:
            raise AssertionError(f"{name} mismatch: {int(attr_value)} != {value}")


def _assert_exact_enum_mapping(
    enum_cls: type[Any], expected_values: Mapping[str, int]
) -> None:
    python_values = {
        name: int(value)
        for name, value in vars(enum_cls).items()
        if not name.startswith("_") and isinstance(value, int)
    }
    if python_values != dict(expected_values):
        raise AssertionError(
            f"{enum_cls.__name__} mismatch: {python_values} != {dict(expected_values)}"
        )


def _assert_enum_subset(
    enum_cls: type[Any], expected_values: Mapping[str, int]
) -> None:
    for name, expected_value in expected_values.items():
        if not hasattr(enum_cls, name):
            raise AssertionError(f"{enum_cls.__name__}.{name} missing")
        actual_value = int(getattr(enum_cls, name))
        if actual_value != expected_value:
            raise AssertionError(
                f"{enum_cls.__name__}.{name} mismatch: {actual_value} != {expected_value}"
            )


def _assert_raises_value_error(callback: Any, expected_message_fragment: str) -> None:
    try:
        callback()
    except ValueError as error:
        if expected_message_fragment not in str(error):
            raise AssertionError(
                f"Unexpected ValueError message: {error!s}; expected fragment {expected_message_fragment!r}"
            ) from error
        return
    raise AssertionError("Expected ValueError was not raised")


def assert_ins_constants_match() -> None:
    dispatcher_values = _parse_enum(_dispatcher_header_path())
    _assert_dispatcher_enum_prefix("INS_", InsType, dispatcher_values)


def assert_p1_p2_constants_match() -> None:
    dispatcher_values = _parse_enum(_dispatcher_header_path())
    _assert_dispatcher_enum_prefix("P1_", P1Type, dispatcher_values)
    _assert_dispatcher_enum_prefix("P2_", P2Type, dispatcher_values)


def assert_cla_constant_match() -> None:
    defines = _parse_defines(_dispatcher_header_path())
    if defines.get("CLA") != CLA:
        raise AssertionError(f"CLA mismatch: {defines.get('CLA')} != {CLA}")


def assert_cvote_credential_constants_match() -> None:
    cvote_values = _parse_enum(_cvote_types_header_path())
    _assert_dispatcher_enum_prefix(
        "CVOTE_CREDENTIAL_", CVoteCredentialType, cvote_values
    )


def assert_max_sign_tx_chunk_size_match() -> None:
    defines = _parse_defines(_handler_sign_tx_path())
    if defines.get("MAX_SIGN_TX_CHUNK_SIZE") != MAX_SIGN_TX_CHUNK_SIZE:
        raise AssertionError("MAX_SIGN_TX_CHUNK_SIZE mismatch")


def assert_max_sign_msg_chunk_size_match() -> None:
    defines = _parse_defines(_handler_sign_msg_path())
    if defines.get("MAX_CIP8_MSG_CHUNK_SIZE") != MAX_CIP8_MSG_CHUNK_SIZE:
        raise AssertionError("MAX_CIP8_MSG_CHUNK_SIZE mismatch")


def assert_warning_bit_constants_match() -> None:
    c_values = _parse_sequential_enum(_security_warnings_header_path(), "warning_bit_e")
    for member in WarningBit:
        name = member.name
        if name not in c_values:
            raise AssertionError(f"WarningBit.{name} missing from C enum warning_bit_e")
        if member.value != c_values[name]:
            raise AssertionError(
                f"WarningBit.{name} value mismatch: Python {member.value} != C {c_values[name]}"
            )
    # Also check there are no extra C entries (excluding the sentinel WARNING_BIT_COUNT)
    for c_name, c_value in c_values.items():
        if c_name == "WARNING_BIT_COUNT":
            continue
        if not hasattr(WarningBit, c_name):
            raise AssertionError(
                f"C enum member {c_name}={c_value} missing from Python WarningBit"
            )


def assert_setting_value_constants_match() -> None:
    defines = _parse_enum(_cardano_settings_header_path())
    if defines.get("SETTINGS_NO") != SettingValue.DISABLED:
        raise AssertionError(
            f"SETTINGS_NO mismatch: {defines.get('SETTINGS_NO')} != {SettingValue.DISABLED}"
        )
    if defines.get("SETTINGS_YES") != SettingValue.ENABLED:
        raise AssertionError(
            f"SETTINGS_YES mismatch: {defines.get('SETTINGS_YES')} != {SettingValue.ENABLED}"
        )


def assert_default_setting_values_match() -> None:
    text = _app_main_path().read_text()
    expected_assignments = {
        "expert_mode_enabled": DEFAULT_SETTING_VALUES[SettingID.EXPERT_MODE],
        "silent_pubkey_export_enabled": DEFAULT_SETTING_VALUES[
            SettingID.SILENT_PUBKEY_EXPORT
        ],
        "blind_signing_enabled": DEFAULT_SETTING_VALUES[SettingID.BLIND_SIGNING],
    }
    for field_name, python_value in expected_assignments.items():
        match = re.search(rf"storage\.{field_name}\s*=\s*(SETTINGS_\w+)\s*;", text)
        if not match:
            raise AssertionError(
                f"Default assignment for {field_name} not found in app_main.c"
            )
        c_value_name = match.group(1)
        if c_value_name == "SETTINGS_NO":
            c_value = SettingValue.DISABLED
        elif c_value_name == "SETTINGS_YES":
            c_value = SettingValue.ENABLED
        else:
            raise AssertionError(
                f"Unexpected setting default {c_value_name} for {field_name}"
            )
        if c_value != python_value:
            raise AssertionError(
                f"{field_name} default mismatch: Python {python_value} != C {c_value}"
            )


def assert_settings_menu_constants_match() -> None:
    text = _menu_c_path().read_text()

    expected_settings = [
        (
            SettingID.SILENT_PUBKEY_EXPORT,
            "SILENT_PUBKEY_EXPORT",
            "silent_pubkey_export_enabled",
        ),
        (
            SettingID.EXPERT_MODE,
            "EXPERT_MODE",
            "expert_mode_enabled",
        ),
        (
            SettingID.BLIND_SIGNING,
            "BLIND_SIGNING",
            "blind_signing_enabled",
        ),
    ]

    expected_order = [setting_id for setting_id, _, _ in expected_settings]
    if SETTINGS_ORDER != expected_order:
        raise AssertionError(
            f"SETTINGS_ORDER mismatch: {SETTINGS_ORDER} != {expected_order}"
        )

    id_enum_values = _parse_anonymous_sequential_enum(text, "SETTINGS_SWITCHES_NB")
    expected_id_values = {
        f"{setting_name}_ID": index
        for index, (_, setting_name, _) in enumerate(expected_settings)
    }
    actual_id_values = {
        name: value for name, value in id_enum_values.items() if name.endswith("_ID")
    }
    if actual_id_values != expected_id_values:
        raise AssertionError(
            f"Settings ID enum mismatch: {actual_id_values} != {expected_id_values}"
        )

    token_enum_match = re.search(
        r"enum\s*\{\s*([^}]*)\s*\};\s*\n\s*enum\s*\{\s*[^}]*SETTINGS_SWITCHES_NB",
        text,
        re.DOTALL,
    )
    if not token_enum_match:
        raise AssertionError("Could not find settings token enum in menu.c")

    token_enum_entries = [
        entry.strip() for entry in token_enum_match.group(1).split(",") if entry.strip()
    ]
    expected_token_entries = [
        "SILENT_PUBKEY_EXPORT_TOKEN = FIRST_USER_TOKEN",
        "EXPERT_MODE_TOKEN",
        "BLIND_SIGNING_TOKEN",
    ]
    if token_enum_entries != expected_token_entries:
        raise AssertionError(
            f"Settings token enum mismatch: {token_enum_entries} != {expected_token_entries}"
        )

    for index, (_, setting_name, storage_field_name) in enumerate(expected_settings):
        callback_pattern = re.compile(
            rf"case\s+{setting_name}_TOKEN:\s*"
            rf".*?flip_bool_setting\(N_storage\.{storage_field_name}\)"
            rf".*?switches\[{setting_name}_ID\]\.initState"
            rf".*?nvm_write\(\(void\*\)\s*&N_storage\.{storage_field_name},\s*&switch_value,\s*1\);",
            re.DOTALL,
        )
        if not callback_pattern.search(text):
            raise AssertionError(f"Callback wiring mismatch for {setting_name}")

        # Accept either direct NVM access or the validated accessor function
        setting_value_fn = (
            storage_field_name.removesuffix("_enabled") + "_setting_value()"
        )
        init_value_pattern = (
            rf"(?:N_storage\.{storage_field_name}|{re.escape(setting_value_fn)})"
        )
        init_pattern = re.compile(
            rf"switches\[{setting_name}_ID\]\.initState\s*=\s*\(nbgl_state_t\)\s*{init_value_pattern};"
            rf".*?switches\[{setting_name}_ID\]\.token\s*=\s*{setting_name}_TOKEN;",
            re.DOTALL,
        )
        if not init_pattern.search(text):
            raise AssertionError(f"UI initialization mismatch for {setting_name}")

        if SETTINGS_ORDER[index] is not expected_order[index]:
            raise AssertionError(
                f"SETTINGS_ORDER index {index} mismatch for {setting_name}"
            )


def assert_app_status_words_match() -> None:
    c_values = _parse_enum(_cardano_swo_path())
    c_values = {
        name: value
        for name, value in c_values.items()
        if name.startswith("SWO_") and name != "SWO_OK"
    }
    python_values = {name: int(getattr(StatusWord, name)) for name in c_values}
    missing_names = [name for name in c_values if not hasattr(StatusWord, name)]
    if missing_names:
        raise AssertionError(
            f"StatusWord missing app-defined statuses: {missing_names}"
        )
    if python_values != c_values:
        raise AssertionError(
            f"StatusWord app-defined mismatch: {python_values} != {c_values}"
        )


def assert_app_definition_constants_match() -> None:
    c_defines = _parse_defines(_cardano_constants_path())
    # TESTNET/FAKE are Python-side helper network descriptors that are not mirrored
    # by dedicated C named constants; pin them here to avoid silent client drift.
    _assert_exact_enum_mapping(
        NetworkIds,
        {
            "TESTNET": c_defines["TESTNET_NETWORK_ID"],
            "MAINNET": c_defines["MAINNET_NETWORK_ID"],
            "FAKE": 0x03,
        },
    )
    _assert_exact_enum_mapping(
        ProtocolMagics,
        {
            "MAINNET": c_defines["MAINNET_PROTOCOL_MAGIC"],
            "TESTNET": 42,
            "TESTNET_LEGACY": c_defines["TESTNET_PROTOCOL_MAGIC_LEGACY"],
            "TESTNET_PREPROD": c_defines["TESTNET_PROTOCOL_MAGIC_PREPROD"],
            "TESTNET_PREVIEW": c_defines["TESTNET_PROTOCOL_MAGIC_PREVIEW"],
            "FAKE": 47,
        },
    )

    address_values = _parse_enum(_address_utils_shelley_header_path())
    _assert_exact_enum_mapping(
        AddressType,
        {
            name: address_values[name]
            for name in (
                "BASE_PAYMENT_KEY_STAKE_KEY",
                "BASE_PAYMENT_SCRIPT_STAKE_KEY",
                "BASE_PAYMENT_KEY_STAKE_SCRIPT",
                "BASE_PAYMENT_SCRIPT_STAKE_SCRIPT",
                "POINTER_KEY",
                "POINTER_SCRIPT",
                "ENTERPRISE_KEY",
                "ENTERPRISE_SCRIPT",
                "BYRON",
                "REWARD_KEY",
                "REWARD_SCRIPT",
            )
        },
    )
    _assert_exact_enum_mapping(
        StakingDataSourceType,
        {
            "NONE": address_values["STAKING_PART_NONE"],
            "KEY_PATH": address_values["STAKING_PART_KEY_PATH"],
            "KEY_HASH": address_values["STAKING_PART_KEY_HASH"],
            "BLOCKCHAIN_POINTER": address_values["STAKING_PART_BLOCKCHAIN_POINTER"],
            "SCRIPT_HASH": address_values["STAKING_PART_SCRIPT_HASH"],
        },
    )


def assert_sign_tx_related_constants_match() -> None:
    tx_values = _parse_enum(_tx_header_path())
    credential_values = _parse_enum(_tx_credential_types_header_path())
    output_values = _parse_enum(_tx_output_types_header_path())
    certificate_values = _parse_enum(_tx_certificate_types_header_path())

    _assert_exact_enum_mapping(
        TransactionSigningMode,
        {
            "ORDINARY": tx_values["SIGN_TX_SIGNINGMODE_ORDINARY"],
            "POOL_REGISTRATION_OWNER": tx_values[
                "SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER"
            ],
            "POOL_REGISTRATION_OPERATOR": tx_values[
                "SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR"
            ],
            "MULTISIG": tx_values["SIGN_TX_SIGNINGMODE_MULTISIG"],
            "PLUTUS": tx_values["SIGN_TX_SIGNINGMODE_PLUTUS"],
            "UNRESTRICTED": tx_values["SIGN_TX_SIGNINGMODE_UNRESTRICTED"],
            "AUTO": tx_values["SIGN_TX_SIGNINGMODE_AUTO"],
        },
    )
    _assert_exact_enum_mapping(
        TxAuxiliaryDataType,
        {
            "ARBITRARY_HASH": tx_values["AUX_DATA_TYPE_ARBITRARY_HASH"],
            "CIP36_REGISTRATION": tx_values["AUX_DATA_TYPE_CVOTE_REGISTRATION"],
        },
    )
    _assert_exact_enum_mapping(
        CredentialParamsType,
        {
            "KEY_HASH": credential_values["EXT_CREDENTIAL_KEY_HASH"],
            "SCRIPT_HASH": credential_values["EXT_CREDENTIAL_SCRIPT_HASH"],
            "KEY_PATH": credential_values["EXT_CREDENTIAL_KEY_PATH"],
        },
    )
    _assert_exact_enum_mapping(
        TxOutputFormat,
        {
            "ARRAY_LEGACY": output_values["ARRAY_LEGACY"],
            "MAP_BABBAGE": output_values["MAP_BABBAGE"],
        },
    )
    _assert_exact_enum_mapping(
        TxOutputDestinationType,
        {
            "THIRD_PARTY": output_values["DESTINATION_THIRD_PARTY"],
            "DEVICE_OWNED": output_values["DESTINATION_DEVICE_OWNED"],
        },
    )
    _assert_exact_enum_mapping(
        VoteOption,
        {
            "NO": certificate_values["VOTE_NO"],
            "YES": certificate_values["VOTE_YES"],
            "ABSTAIN": certificate_values["VOTE_ABSTAIN"],
        },
    )
    _assert_exact_enum_mapping(
        VoterType,
        {
            "COMMITTEE_KEY_HASH": certificate_values["VOTER_COMMITTEE_HOT_KEY_HASH"],
            "COMMITTEE_KEY_PATH": certificate_values["VOTER_COMMITTEE_HOT_KEY_HASH"]
            + 100,
            "COMMITTEE_SCRIPT_HASH": certificate_values[
                "VOTER_COMMITTEE_HOT_SCRIPT_HASH"
            ],
            "DREP_KEY_HASH": certificate_values["VOTER_DREP_KEY_HASH"],
            "DREP_KEY_PATH": certificate_values["VOTER_DREP_KEY_HASH"] + 100,
            "DREP_SCRIPT_HASH": certificate_values["VOTER_DREP_SCRIPT_HASH"],
            "STAKE_POOL_KEY_HASH": certificate_values["VOTER_STAKE_POOL_KEY_HASH"],
            "STAKE_POOL_KEY_PATH": certificate_values["VOTER_STAKE_POOL_KEY_HASH"]
            + 100,
        },
    )
    _assert_exact_enum_mapping(
        CertificateType,
        {
            "STAKE_REGISTRATION": certificate_values["CERTIFICATE_STAKE_REGISTRATION"],
            "STAKE_DEREGISTRATION": certificate_values[
                "CERTIFICATE_STAKE_DEREGISTRATION"
            ],
            "STAKE_DELEGATION": certificate_values["CERTIFICATE_STAKE_DELEGATION"],
            "STAKE_POOL_REGISTRATION": certificate_values[
                "CERTIFICATE_STAKE_POOL_REGISTRATION"
            ],
            "STAKE_POOL_RETIREMENT": certificate_values[
                "CERTIFICATE_STAKE_POOL_RETIREMENT"
            ],
            "STAKE_REGISTRATION_CONWAY": certificate_values[
                "CERTIFICATE_STAKE_REGISTRATION_CONWAY"
            ],
            "STAKE_DEREGISTRATION_CONWAY": certificate_values[
                "CERTIFICATE_STAKE_DEREGISTRATION_CONWAY"
            ],
            "VOTE_DELEGATION": certificate_values["CERTIFICATE_VOTE_DELEGATION"],
            "STAKE_POOL_AND_DREP_DELEGATION": certificate_values[
                "CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION"
            ],
            "ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL": certificate_values[
                "CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL"
            ],
            "ACCOUNT_REGISTRATION_DELEGATION_TO_DREP": certificate_values[
                "CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP"
            ],
            "ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP": certificate_values[
                "CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP"
            ],
            "AUTHORIZE_COMMITTEE_HOT": certificate_values[
                "CERTIFICATE_AUTHORIZE_COMMITTEE_HOT"
            ],
            "RESIGN_COMMITTEE_COLD": certificate_values[
                "CERTIFICATE_RESIGN_COMMITTEE_COLD"
            ],
            "DREP_REGISTRATION": certificate_values["CERTIFICATE_DREP_REGISTRATION"],
            "DREP_DEREGISTRATION": certificate_values[
                "CERTIFICATE_DREP_DEREGISTRATION"
            ],
            "DREP_UPDATE": certificate_values["CERTIFICATE_DREP_UPDATE"],
        },
    )
    _assert_exact_enum_mapping(
        DRepParamsType,
        {
            "KEY_HASH": credential_values["DREP_KEY_HASH"],
            "SCRIPT_HASH": credential_values["DREP_SCRIPT_HASH"],
            "ABSTAIN": credential_values["DREP_ABSTAIN"],
            "NO_CONFIDENCE": credential_values["DREP_NO_CONFIDENCE"],
            "KEY_PATH": credential_values["DREP_KEY_HASH"] + 100,
        },
    )
    _assert_exact_enum_mapping(
        TxRequiredSignerType,
        {
            "PATH": tx_values["REQUIRED_SIGNER_WITH_PATH"],
            "HASH": tx_values["REQUIRED_SIGNER_WITH_HASH"],
        },
    )
    _assert_exact_enum_mapping(
        DatumType,
        {
            "HASH": output_values["DATUM_HASH"],
            "INLINE": output_values["DATUM_INLINE"],
        },
    )
    _assert_exact_enum_mapping(
        RelayType,
        {
            "SINGLE_HOST_IP_ADDR": certificate_values["RELAY_SINGLE_HOST_IP"],
            "SINGLE_HOST_HOSTNAME": certificate_values["RELAY_SINGLE_HOST_NAME"],
            "MULTI_HOST": certificate_values["RELAY_MULTIPLE_HOST_NAME"],
        },
    )


def assert_sign_msg_and_native_script_constants_match() -> None:
    globals_defines = _parse_defines(_globals_header_path())
    sign_msg_defines = _parse_defines(_handler_sign_msg_path())
    message_signing_values = _parse_enum(_message_signing_header_path())
    native_script_display_values = _parse_enum(_derive_native_script_hash_header_path())

    if sign_msg_defines["MAX_CIP8_MSG_CHUNK_SIZE"] != MAX_CIP8_MSG_CHUNK_SIZE:
        raise AssertionError(
            f"MAX_CIP8_MSG_CHUNK_SIZE mismatch: {MAX_CIP8_MSG_CHUNK_SIZE}"
            f" != {sign_msg_defines['MAX_CIP8_MSG_CHUNK_SIZE']}"
        )

    _assert_exact_enum_mapping(
        NativeScriptHashDisplayFormat,
        {
            "BECH32": native_script_display_values["DISPLAY_NATIVE_SCRIPT_HASH_BECH32"],
            "POLICY_ID": native_script_display_values[
                "DISPLAY_NATIVE_SCRIPT_HASH_POLICY_ID"
            ],
        },
    )

    _assert_exact_enum_mapping(
        MessageAddressFieldType,
        {
            "ADDRESS": message_signing_values["CIP8_ADDRESS_FIELD_ADDRESS"],
            "KEY_HASH": message_signing_values["CIP8_ADDRESS_FIELD_KEYHASH"],
        },
    )

    if MAX_CIP36_PAYLOAD_SIZE != globals_defines["MAX_VOTECAST_CHUNK_SIZE"]:
        raise AssertionError(
            f"MAX_CIP36_PAYLOAD_SIZE mismatch: {MAX_CIP36_PAYLOAD_SIZE} != {globals_defines['MAX_VOTECAST_CHUNK_SIZE']}"
        )


def assert_response_unpacker_constants_match() -> None:
    c_defines = {
        **_parse_defines(_cardano_constants_path()),
        **_parse_defines(_key_derivation_header_path()),
        **_parse_defines(_get_version_header_path()),
        **_parse_defines(_globals_header_path()),
        **_parse_defines(_vote_cast_hash_builder_header_path()),
        **_parse_defines(_address_utils_shelley_header_path()),
    }
    response_unpacker_text = _response_unpacker_path().read_text()

    expected_literals = {
        "SERIAL_LENGTH": 7,
        "PUBLIC_KEY_LENGTH": c_defines["PUBLIC_KEY_LENGTH"],
        "CHAIN_CODE_LENGTH": c_defines["CHAIN_CODE_LENGTH"],
        "SIGNATURE_LENGTH": c_defines["ED25519_SIGNATURE_LENGTH"],
        "TX_HASH_LENGTH": c_defines["TX_HASH_LENGTH"],
        "SCRIPT_HASH_LENGTH": c_defines["SCRIPT_HASH_LENGTH"],
        "MAX_ADDRESS_FIELD_LENGTH": c_defines["MAX_ADDRESS_LENGTH"],
        "HASH_LENGTH": c_defines["VOTECAST_HASH_LENGTH"],
    }
    serial_match = re.search(
        r"#define\s+SERIAL_LENGTH\s+(\d+)", _get_serial_c_path().read_text()
    )
    if not serial_match:
        raise AssertionError("SERIAL_LENGTH not found in get_serial.c")
    expected_literals["SERIAL_LENGTH"] = int(serial_match.group(1))

    for literal_name, expected_value in expected_literals.items():
        matches = re.findall(rf"\b{literal_name}\b\s*=\s*(\d+)", response_unpacker_text)
        if not matches:
            raise AssertionError(f"{literal_name} not found in response_unpacker.py")
        for value_str in matches:
            if int(value_str) != expected_value:
                raise AssertionError(
                    f"{literal_name} mismatch in response_unpacker.py: {value_str} != {expected_value}"
                )

    version_response = bytes([1, 2, 3, 4])
    if unpack_get_version_response(version_response) != (1, 2, 3, 4):
        raise AssertionError(
            "unpack_get_version_response failed to parse a valid response"
        )
    _assert_raises_value_error(
        lambda: unpack_get_version_response(version_response[:-1]),
        "Invalid version response length",
    )

    serial_length = expected_literals["SERIAL_LENGTH"]
    valid_serial = b"S" * serial_length
    if unpack_get_serial_response(valid_serial) != valid_serial:
        raise AssertionError("unpack_get_serial_response failed to return valid bytes")
    _assert_raises_value_error(
        lambda: unpack_get_serial_response(valid_serial + b"\x00"),
        "Invalid serial response length",
    )

    valid_pubkey_response = (
        b"P" * expected_literals["PUBLIC_KEY_LENGTH"]
        + b"C" * expected_literals["CHAIN_CODE_LENGTH"]
    )
    if unpack_get_pubkey_response(valid_pubkey_response) != (
        b"P" * expected_literals["PUBLIC_KEY_LENGTH"],
        b"C" * expected_literals["CHAIN_CODE_LENGTH"],
    ):
        raise AssertionError(
            "unpack_get_pubkey_response failed to parse a valid response"
        )
    _assert_raises_value_error(
        lambda: unpack_get_pubkey_response(valid_pubkey_response + b"\x00"),
        "Invalid pubkey response length",
    )

    signature_length = expected_literals["SIGNATURE_LENGTH"]
    public_key_length = expected_literals["PUBLIC_KEY_LENGTH"]
    max_address_field_length = expected_literals["MAX_ADDRESS_FIELD_LENGTH"]
    valid_address_field = b"abc"
    valid_sign_message_response = (
        b"S" * signature_length
        + b"P" * public_key_length
        + len(valid_address_field).to_bytes(4, "big")
        + valid_address_field
    )
    if unpack_sign_message_response(valid_sign_message_response) != (
        b"S" * signature_length,
        b"P" * public_key_length,
        valid_address_field,
    ):
        raise AssertionError(
            "unpack_sign_message_response failed to parse a valid response"
        )
    _assert_raises_value_error(
        lambda: unpack_sign_message_response(valid_sign_message_response + b"\x00"),
        "Trailing bytes in response",
    )
    oversized_address_field_response = (
        b"S" * signature_length
        + b"P" * public_key_length
        + (max_address_field_length + 1).to_bytes(4, "big")
    )
    _assert_raises_value_error(
        lambda: unpack_sign_message_response(oversized_address_field_response),
        "Address field too long",
    )
    truncated_address_field_response = (
        b"S" * signature_length
        + b"P" * public_key_length
        + (5).to_bytes(4, "big")
        + b"abcd"
    )
    _assert_raises_value_error(
        lambda: unpack_sign_message_response(truncated_address_field_response),
        "Address field truncated",
    )

    valid_cip36_confirm_response = (
        b"H" * expected_literals["HASH_LENGTH"] + b"S" * signature_length
    )
    if unpack_sign_cip36_confirm_response(valid_cip36_confirm_response) != (
        b"H" * expected_literals["HASH_LENGTH"],
        b"S" * signature_length,
    ):
        raise AssertionError(
            "unpack_sign_cip36_confirm_response failed to parse a valid response"
        )
    _assert_raises_value_error(
        lambda: unpack_sign_cip36_confirm_response(
            valid_cip36_confirm_response + b"\x00"
        ),
        "Invalid CIP-36 confirm response length",
    )
