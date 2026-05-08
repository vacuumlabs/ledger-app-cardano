# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

import hashlib
import re
from typing import Any, Sequence

from tests.application_client.security_warnings import WarningBit
from tests.unit.generators.common import (
    _ensure_base58_module,
    bool_to_c,
    extract_apdu_payload,
    format_bytes_as_c_array,
    resolve_mnemonic,
    sanitize_c_identifier,
    warning_expr_from_test_case,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_SIGN_TX_DIR


# ======================================================================
# Compiled Regex Patterns (module level for performance)
# ======================================================================

# Match tx_fixture_t declarations
_TX_FIXTURE_PATTERN = re.compile(r"static\s+const\s+tx_fixture_t\s+[A-Z0-9_]+\s*=\s*\{")


def _split_hex_string(hex_str: str, chunk_size: int = 1024) -> list[str]:
    return [hex_str[i : i + chunk_size] for i in range(0, len(hex_str), chunk_size)]


def _compute_blake2b_256(data: bytes) -> str:
    return hashlib.blake2b(data, digest_size=32).hexdigest()


def _sign_with_extended_key(extended_key: bytes, message: bytes) -> bytes:
    from nacl import bindings  # type: ignore

    if len(extended_key) != 64:
        raise ValueError(f"Unexpected extended key length {len(extended_key)}")

    secret_scalar = extended_key[:32]
    prefix = extended_key[32:64]

    r_hash = hashlib.sha512(prefix + message).digest()
    r_scalar = bindings.crypto_core_ed25519_scalar_reduce(r_hash)
    r_point = bindings.crypto_scalarmult_ed25519_base_noclamp(r_scalar)

    public_key = bindings.crypto_scalarmult_ed25519_base_noclamp(secret_scalar)
    k_hash = hashlib.sha512(r_point + public_key + message).digest()
    k_scalar = bindings.crypto_core_ed25519_scalar_reduce(k_hash)

    k_times_a = bindings.crypto_core_ed25519_scalar_mul(k_scalar, secret_scalar)
    s_scalar = bindings.crypto_core_ed25519_scalar_add(r_scalar, k_times_a)

    return r_point + s_scalar


def _derive_witness_signature(witness_path: str, message: bytes) -> bytes:
    try:
        from bip_utils import Bip39SeedGenerator, Bip32Ed25519Kholaw  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            f"Missing dependency for sign-tx signature derivation: {exc}"
        ) from exc

    mnemonic = resolve_mnemonic()
    seed = Bip39SeedGenerator(mnemonic).Generate()
    child = Bip32Ed25519Kholaw.FromSeed(seed).DerivePath(witness_path)
    extended_key = child.PrivateKey().Raw().ToBytes()
    return _sign_with_extended_key(extended_key, message)


def _blind_signing_mode_to_c_enum(blind_signing_mode: Any) -> str:
    blind_signing_mode_name = getattr(blind_signing_mode, "name", "DISABLED")
    return f"BLIND_SIGNING_MODE_{blind_signing_mode_name}"


def _cbor_hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", "").replace("\n", ""))


def _extract_aux_data_hash_from_tx_body(hex_str: str) -> str | None:
    import cbor2  # type: ignore

    try:
        parsed = cbor2.loads(_cbor_hex_to_bytes(hex_str))
    except Exception as exc:
        raise ValueError(
            "Failed to parse txBodyHex while extracting auxiliary data hash"
        ) from exc

    if not isinstance(parsed, dict):
        return None

    aux_hash = parsed.get(7)
    if isinstance(aux_hash, (bytes, bytearray)) and len(aux_hash) == 32:
        return aux_hash.hex()
    return None


def _count_fixture_structs(header_text: str) -> int:
    return len(_TX_FIXTURE_PATTERN.findall(header_text))


_HARDENED_BIP32 = 0x80000000
_PURPOSE_BYRON = 44
_PURPOSE_SHELLEY = 1852
_PURPOSE_POOL_COLD_KEY = 1853
_PURPOSE_MULTISIG = 1854
_PURPOSE_MINT = 1855
_PURPOSE_CVOTE_KEY = 1694
_ADA_COIN_TYPE = 1815
_MAX_REASONABLE_ACCOUNT = 100
_MAX_REASONABLE_ADDRESS = 1_000_000
_MAX_REASONABLE_COLD_KEY_INDEX = 1_000_000
_MAX_REASONABLE_MINT_POLICY_INDEX = 1_000_000
_CARDANO_CHAIN_EXTERNAL = 0
_CARDANO_CHAIN_INTERNAL = 1
_CARDANO_CHAIN_STAKING_KEY = 2
_CARDANO_CHAIN_DREP_KEY = 3
_CARDANO_CHAIN_COMMITTEE_COLD_KEY = 4
_CARDANO_CHAIN_COMMITTEE_HOT_KEY = 5


def _parse_bip32_path(path: str) -> list[int]:
    if not path.startswith("m"):
        raise ValueError(f"Unexpected BIP32 path prefix: {path}")

    if path == "m":
        return []

    path_parts = path.split("/")[1:]
    parsed_path: list[int] = []
    for path_part in path_parts:
        is_hardened = path_part.endswith("'")
        path_index = int(path_part[:-1] if is_hardened else path_part)
        parsed_path.append(path_index | _HARDENED_BIP32 if is_hardened else path_index)
    return parsed_path


def _is_hardened(path_word: int) -> bool:
    return (path_word & _HARDENED_BIP32) != 0


def _unharden(path_word: int) -> int:
    return path_word & ~_HARDENED_BIP32


def _has_reasonable_account(path_words: list[int]) -> bool:
    if len(path_words) <= 2:
        return False
    account = path_words[2]
    return _is_hardened(account) and _unharden(account) <= _MAX_REASONABLE_ACCOUNT


def _has_reasonable_address(path_words: list[int]) -> bool:
    return len(path_words) > 4 and path_words[4] <= _MAX_REASONABLE_ADDRESS


def _is_reasonable_witness_path(path: str) -> bool:
    path_words = _parse_bip32_path(path)
    if len(path_words) < 2:
        return False

    purpose = path_words[0]
    coin_type = path_words[1]
    if coin_type != (_ADA_COIN_TYPE | _HARDENED_BIP32):
        return False

    if purpose in (
        _PURPOSE_BYRON | _HARDENED_BIP32,
        _PURPOSE_SHELLEY | _HARDENED_BIP32,
    ):
        if len(path_words) == 3:
            return _has_reasonable_account(path_words)
        if len(path_words) == 5 and path_words[3] in (
            _CARDANO_CHAIN_EXTERNAL,
            _CARDANO_CHAIN_INTERNAL,
            _CARDANO_CHAIN_STAKING_KEY,
        ):
            return _has_reasonable_account(path_words) and _has_reasonable_address(
                path_words
            )
        if len(path_words) == 5 and path_words[3] in (
            _CARDANO_CHAIN_DREP_KEY,
            _CARDANO_CHAIN_COMMITTEE_COLD_KEY,
            _CARDANO_CHAIN_COMMITTEE_HOT_KEY,
        ):
            return (
                _has_reasonable_account(path_words)
                and _has_reasonable_address(path_words)
                and path_words[4] == 0
            )
        return False

    if purpose == (_PURPOSE_MULTISIG | _HARDENED_BIP32):
        if len(path_words) == 3:
            return _has_reasonable_account(path_words)
        if len(path_words) == 5 and path_words[3] in (
            _CARDANO_CHAIN_EXTERNAL,
            _CARDANO_CHAIN_INTERNAL,
            _CARDANO_CHAIN_STAKING_KEY,
        ):
            return _has_reasonable_account(path_words) and _has_reasonable_address(
                path_words
            )
        if len(path_words) == 5 and path_words[3] in (
            _CARDANO_CHAIN_DREP_KEY,
            _CARDANO_CHAIN_COMMITTEE_COLD_KEY,
            _CARDANO_CHAIN_COMMITTEE_HOT_KEY,
        ):
            return (
                _has_reasonable_account(path_words)
                and _has_reasonable_address(path_words)
                and path_words[4] == 0
            )
        return False

    if purpose == (_PURPOSE_MINT | _HARDENED_BIP32):
        return (
            len(path_words) == 3
            and _is_hardened(path_words[2])
            and _unharden(path_words[2]) <= _MAX_REASONABLE_MINT_POLICY_INDEX
        )

    if purpose == (_PURPOSE_POOL_COLD_KEY | _HARDENED_BIP32):
        return (
            len(path_words) == 4
            and path_words[2] == _HARDENED_BIP32
            and _is_hardened(path_words[3])
            and _unharden(path_words[3]) <= _MAX_REASONABLE_COLD_KEY_INDEX
        )

    if purpose == (_PURPOSE_CVOTE_KEY | _HARDENED_BIP32):
        if len(path_words) == 3:
            return _has_reasonable_account(path_words)
        return (
            len(path_words) == 5
            and path_words[3] == 0
            and _has_reasonable_account(path_words)
            and _has_reasonable_address(path_words)
        )

    return False


def _warning_expr_from_witness_path(witness_path: str) -> str:
    if _is_reasonable_witness_path(witness_path):
        return "0"
    return f"((warning_bits_t)1 << {WarningBit.WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH.name})"


def _generate_fixtures_for_era(
    era_key: str,
    tests: Sequence[Any],
    aux_data_classes: dict[str, Any],
) -> None:
    from tests.application_client.command_builder import (
        CommandBuilder,
        gather_witness_paths,
    )  # type: ignore

    TxAuxiliaryDataCIP36 = aux_data_classes["TxAuxiliaryDataCIP36"]
    TxAuxiliaryDataType = aux_data_classes["TxAuxiliaryDataType"]
    TxAuxiliaryDataHash = aux_data_classes["TxAuxiliaryDataHash"]

    print(f"Generating C fixtures for {era_key.upper()} era ({len(tests)} tests)...")
    print()

    header_lines = [
        "//",
        "// Generator: fixture_generators/sign_tx_generators.py",
        f"// Source: tests/standalone/input_files/signTx.py ({era_key} era tests)",
        "//",
        "// To regenerate:",
        "//   cd tests/unit",
        "//   python3 generators/generate_unit_tests_from_ragger.py",
        "//",
        "// Each fixture includes source traceability comments showing:",
        "//   - Source file and era",
        "//   - Original Ragger test name",
        "//",
        f"// Total tests in this era: {len(tests)}",
        "",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        '#include "test_fixture_types.h"',
        "",
        "// ======================================================================",
        "// Fixtures",
        "// ======================================================================",
        "",
        "#if defined(__clang__)",
        "#pragma clang diagnostic push",
        '#pragma clang diagnostic ignored "-Woverlength-strings"',
        "#elif defined(__GNUC__)",
        "#pragma GCC diagnostic push",
        '#pragma GCC diagnostic ignored "-Woverlength-strings"',
        "#endif",
        "",
    ]

    for test_index, test_case in enumerate(tests):
        print(f"  [{test_index + 1}/{len(tests)}] {test_case.name}...")

        tx = test_case.tx
        builder = CommandBuilder()
        raw_tx_bytes = builder.serialize_transaction_unpacked_raw(tx)

        unit_test_expect = getattr(test_case, "unit_test_expect", None)
        if unit_test_expect is None:
            raise ValueError(
                f"Test case '{test_case.name}' is missing unit_test_expect. "
                "Every happy-path sign-tx fixture must supply the expected CBOR-encoded transaction body hex."
            )
        expected_cbor_hex = unit_test_expect.txBodyHex
        cbor_bytes = _cbor_hex_to_bytes(expected_cbor_hex)
        expected_hash_hex = _compute_blake2b_256(cbor_bytes)
        body_aux_data_hash = _extract_aux_data_hash_from_tx_body(expected_cbor_hex)

        safe_name = sanitize_c_identifier(test_case.name)
        fixture_prefix = f"FIXTURE_{era_key.upper()}_{safe_name}"

        include_aux_data_hash = tx.auxiliaryData is not None
        aux_data_type = 0
        aux_data_hash_hex = body_aux_data_hash
        aux_data_init_payload = b""
        aux_data_delegation_payloads: list[bytes] = []
        if include_aux_data_hash:
            if tx.auxiliaryData.type == TxAuxiliaryDataType.ARBITRARY_HASH:
                aux_data_type = int(TxAuxiliaryDataType.ARBITRARY_HASH)
                aux_params = tx.auxiliaryData.params
                if isinstance(aux_params, TxAuxiliaryDataHash):
                    aux_data_hash_hex = aux_params.hashHex
                else:
                    include_aux_data_hash = False
            elif tx.auxiliaryData.type == TxAuxiliaryDataType.CIP36_REGISTRATION:
                aux_data_type = int(TxAuxiliaryDataType.CIP36_REGISTRATION)
                aux_params = tx.auxiliaryData.params
                if isinstance(aux_params, TxAuxiliaryDataCIP36):
                    aux_data_init_apdu = builder.sign_tx_aux_data_init(aux_params)
                    aux_data_init_payload = extract_apdu_payload(aux_data_init_apdu)
                    for delegation in aux_params.delegations:
                        reg_apdu = builder.sign_tx_aux_data_delegation(delegation)
                        aux_data_delegation_payloads.append(
                            extract_apdu_payload(reg_apdu)
                        )
                else:
                    include_aux_data_hash = False

        include_script_data_hash = getattr(tx, "scriptDataHash", None) is not None

        options_value = (
            "TX_OPTIONS_TAG_CBOR_SETS" if "d90102" in expected_cbor_hex.lower() else "0"
        )
        network_id_value = int(test_case.tx.network.networkId)
        protocol_magic_value = int(test_case.tx.network.protocol)

        header_lines.append(f"// Test {test_index}: {test_case.name}")
        header_lines.append(
            f"// Source: tests/standalone/input_files/signTx.py > {era_key} era tests"
        )
        header_lines.append("//")

        array_lines = format_bytes_as_c_array(
            raw_tx_bytes,
            f"{fixture_prefix}_RAW_TX",
        ).split("\n")
        header_lines.extend(array_lines)
        header_lines.append("")
        if include_aux_data_hash and aux_data_type == int(
            TxAuxiliaryDataType.CIP36_REGISTRATION
        ):
            init_payload_name = f"{fixture_prefix}_AUX_DATA_INIT_PAYLOAD"
            init_payload_lines = format_bytes_as_c_array(
                aux_data_init_payload,
                init_payload_name,
            ).split("\n")
            header_lines.extend(init_payload_lines)
            header_lines.append("")

            delegations_name = f"{fixture_prefix}_AUX_DATA_DELEGATIONS"
            if aux_data_delegation_payloads:
                delegation_entries = []
                for reg_index, payload in enumerate(aux_data_delegation_payloads):
                    entry_name = f"{fixture_prefix}_AUX_DATA_DELEGATION_{reg_index}"
                    reg_lines = format_bytes_as_c_array(payload, entry_name).split("\n")
                    header_lines.extend(reg_lines)
                    header_lines.append("")
                    delegation_entries.append(
                        f"    {{ .payload = {entry_name}, .payload_len = sizeof({entry_name}) }},"
                    )
                header_lines.append(
                    f"static const aux_data_payload_t {delegations_name}[] = {{"
                )
                header_lines.extend(delegation_entries)
                header_lines.append("};")
            header_lines.append("")
        witness_paths = gather_witness_paths(
            tx,
            test_case.signingMode,
            getattr(test_case, "additionalWitnessPaths", []),
        )
        witness_declaration_lines = []
        witness_payload_entries = []
        witness_payloads_name = f"{fixture_prefix}_WITNESS_PAYLOADS"
        expected_hash_bytes = bytes.fromhex(expected_hash_hex)
        for witness_index, witness_path in enumerate(witness_paths):
            witness_payload_name = f"{fixture_prefix}_WITNESS_{witness_index}_PAYLOAD"
            witness_signature_name = (
                f"{fixture_prefix}_WITNESS_{witness_index}_EXPECTED_SIGNATURE"
            )
            witness_apdu = builder.sign_tx_witness(witness_path)
            witness_payload = extract_apdu_payload(witness_apdu)
            witness_signature = _derive_witness_signature(
                witness_path,
                expected_hash_bytes,
            )
            witness_lines = format_bytes_as_c_array(
                witness_payload,
                witness_payload_name,
            ).split("\n")
            witness_declaration_lines.extend(witness_lines)
            witness_declaration_lines.append("")
            witness_signature_lines = format_bytes_as_c_array(
                witness_signature,
                witness_signature_name,
            ).split("\n")
            witness_declaration_lines.extend(witness_signature_lines)
            witness_declaration_lines.append("")
            witness_payload_entries.append(
                "    { .payload = "
                f"{witness_payload_name}, .payload_len = sizeof({witness_payload_name}), "
                f".expected_warning_bits = {_warning_expr_from_witness_path(witness_path)}, "
                f".expected_signature = {witness_signature_name} }},"
            )
        if witness_payload_entries:
            witness_declaration_lines.append(
                f"static const witness_payload_t {witness_payloads_name}[] = {{"
            )
            witness_declaration_lines.extend(witness_payload_entries)
            witness_declaration_lines.append("};")
            witness_declaration_lines.append("")

        header_lines.extend(witness_declaration_lines)
        header_lines.append(f"static const tx_fixture_t {fixture_prefix} = {{")
        header_lines.append(f'    .name = "{test_case.name}",')
        header_lines.append(f"    .raw_tx = {fixture_prefix}_RAW_TX,")
        header_lines.append(f"    .raw_tx_len = sizeof({fixture_prefix}_RAW_TX),")
        tx_body_chunks = _split_hex_string(expected_cbor_hex, chunk_size=1024)
        if len(tx_body_chunks) == 1:
            header_lines.append(f'    .tx_body_cbor_hex = "{tx_body_chunks[0]}",')
        else:
            header_lines.append(f'    .tx_body_cbor_hex = "{tx_body_chunks[0]}"')
            for chunk in tx_body_chunks[1:-1]:
                header_lines.append(f'                         "{chunk}"')
            header_lines.append(f'                         "{tx_body_chunks[-1]}",')
        header_lines.append(f'    .expected_hash_hex = "{expected_hash_hex}",')
        header_lines.append(f"    .signing_mode = {int(test_case.signingMode)},")
        header_lines.append(f"    .network_id = {network_id_value},")
        header_lines.append(f"    .protocol_magic = {protocol_magic_value},")
        header_lines.append(f"    .num_inputs = {len(tx.inputs)},")
        header_lines.append(f"    .num_outputs = {len(tx.outputs)},")
        header_lines.append(f"    .num_witnesses = {len(witness_paths)},")
        if witness_payload_entries:
            header_lines.append(f"    .witness_payloads = {witness_payloads_name},")
            header_lines.append(
                f"    .witness_payload_count = {len(witness_payload_entries)},"
            )
        else:
            header_lines.append("    .witness_payloads = NULL,")
            header_lines.append("    .witness_payload_count = 0,")
        header_lines.append(
            f"    .num_certificates = {len(tx.certificates) if tx.certificates else 0},"
        )
        header_lines.append(
            f"    .num_withdrawals = {len(tx.withdrawals) if tx.withdrawals else 0},"
        )
        header_lines.append(
            f"    .num_mint_asset_groups = {len(tx.mint) if tx.mint else 0},"
        )
        header_lines.append(f"    .include_ttl = {bool_to_c(tx.ttl is not None)},")
        header_lines.append(
            f"    .include_validity_interval_start = "
            f"{bool_to_c(tx.validityIntervalStart is not None)},"
        )
        header_lines.append(
            f"    .include_aux_data_hash = {bool_to_c(include_aux_data_hash)},"
        )
        header_lines.append(f"    .aux_data_type = {aux_data_type},")
        if include_aux_data_hash and aux_data_type == int(
            TxAuxiliaryDataType.CIP36_REGISTRATION
        ):
            header_lines.append(f"    .aux_data_init_payload = {init_payload_name},")
            header_lines.append(
                f"    .aux_data_init_payload_len = sizeof({init_payload_name}),"
            )
            if aux_data_delegation_payloads:
                header_lines.append(f"    .aux_data_delegations = {delegations_name},")
                header_lines.append(
                    f"    .aux_data_delegation_count = {len(aux_data_delegation_payloads)},"
                )
            else:
                header_lines.append("    .aux_data_delegations = NULL,")
                header_lines.append("    .aux_data_delegation_count = 0,")
        else:
            header_lines.append("    .aux_data_init_payload = NULL,")
            header_lines.append("    .aux_data_init_payload_len = 0,")
            header_lines.append("    .aux_data_delegations = NULL,")
            header_lines.append("    .aux_data_delegation_count = 0,")
        header_lines.append(
            f"    .include_script_data_hash = {bool_to_c(include_script_data_hash)},"
        )
        header_lines.append(
            f"    .num_collateral_inputs = "
            f"{len(tx.collateralInputs) if hasattr(tx, 'collateralInputs') and tx.collateralInputs else 0},"
        )
        header_lines.append(
            f"    .num_required_signers = "
            f"{len(tx.requiredSigners) if hasattr(tx, 'requiredSigners') and tx.requiredSigners else 0},"
        )
        header_lines.append(
            f"    .include_network_id = "
            f"{bool_to_c(getattr(tx, 'includeNetworkId', False))},"
        )
        header_lines.append(
            f"    .include_collateral_output = "
            f"{bool_to_c(getattr(tx, 'collateralOutput', None) is not None)},"
        )
        header_lines.append(
            f"    .include_total_collateral = "
            f"{bool_to_c(getattr(tx, 'totalCollateral', None) is not None)},"
        )
        header_lines.append(
            f"    .num_reference_inputs = "
            f"{len(tx.referenceInputs) if hasattr(tx, 'referenceInputs') and tx.referenceInputs else 0},"
        )
        header_lines.append(
            f"    .num_voters = "
            f"{len(tx.votingProcedures) if hasattr(tx, 'votingProcedures') and tx.votingProcedures else 0},"
        )
        treasury_value = getattr(tx, "treasury", None)
        donation_value = getattr(tx, "donation", None)
        header_lines.append(
            f"    .include_treasury = {bool_to_c(treasury_value is not None)},"
        )
        header_lines.append(
            f"    .treasury = {treasury_value if treasury_value is not None else 0},"
        )
        header_lines.append(
            f"    .include_donation = {bool_to_c(donation_value is not None)},"
        )
        header_lines.append(
            f"    .donation = {donation_value if donation_value is not None else 0},"
        )

        if include_aux_data_hash and aux_data_hash_hex is not None:
            header_lines.append(f'    .aux_data_hash_hex = "{aux_data_hash_hex}",')
        else:
            header_lines.append("    .aux_data_hash_hex = NULL,")
        header_lines.append(f"    .options = {options_value},")
        header_lines.append(
            "    .blind_signing_mode = "
            f"{_blind_signing_mode_to_c_enum(getattr(test_case, 'blind_signing_mode', None))},"
        )

        warning_expr = warning_expr_from_test_case(test_case)
        header_lines.append(f"    .expected_warning_bits = {warning_expr},")

        header_lines.append("};")
        header_lines.append("")

    header_lines.append("#if defined(__clang__)")
    header_lines.append("#pragma clang diagnostic pop")
    header_lines.append("#elif defined(__GNUC__)")
    header_lines.append("#pragma GCC diagnostic pop")
    header_lines.append("#endif")
    header_lines.append("")

    header_content = "\n".join(header_lines)
    output_file = GENERATED_SIGN_TX_DIR / f"test_sign_tx_fixtures_{era_key.lower()}.h"
    write_generated_c_file(output_file, header_content)

    fixture_count = _count_fixture_structs(header_content)
    if fixture_count != len(tests):
        raise ValueError(
            f"Fixture count mismatch for {era_key}: expected {len(tests)}, got {fixture_count}"
        )

    print()
    print(f"Generated: {output_file}")
    print(f"Total fixtures: {len(tests)}")


def _load_sign_tx_tests() -> dict[str, Any]:
    _ensure_base58_module()
    from tests.standalone.input_files.signTx import (  # type: ignore
        testsMary,
        testsShelleyNoCertificates,
        testsShelleyWithCertificates,
        testsAllegra,
        testsByron,
        testsAlonzo,
        testsAlonzoTrezorComparison,
        testsStreaming,
        testsBabbage,
        testsBabbageTrezorComparison,
        testsConwayWithCertificates,
        testsConwayWithoutCertificates,
        testsConwayVotingProcedures,
        testsConwayMultisig,
        testsMultidelegation,
        testsCatalystRegistration,
        testsCVoteRegistrationCIP36,
        testsMultisig,
        poolRegistrationOwnerTestCases,
        poolRegistrationOperatorTestCases,
        TxAuxiliaryDataCIP36,
        TxAuxiliaryDataType,
        TxAuxiliaryDataHash,
    )

    era_tests = {
        "byron": testsByron,
        "shelley": testsShelleyNoCertificates,
        "shelley_certificates": testsShelleyWithCertificates,
        "allegra": testsAllegra,
        "mary": testsMary,
        "alonzo": testsAlonzo + testsAlonzoTrezorComparison + testsMultidelegation,
        "streaming": testsStreaming,
        "babbage": testsBabbage + testsBabbageTrezorComparison,
        "conway": testsConwayWithCertificates,
        "conway_without_certificates": testsConwayWithoutCertificates,
        "conway_voting": testsConwayVotingProcedures,
        "multisig": testsMultisig + testsConwayMultisig,
        "alonzo_catalyst": testsCatalystRegistration,
        "alonzo_cip36": testsCVoteRegistrationCIP36,
        "pool_registration": poolRegistrationOwnerTestCases
        + poolRegistrationOperatorTestCases,
    }

    return {
        "era_tests": era_tests,
        "TxAuxiliaryDataCIP36": TxAuxiliaryDataCIP36,
        "TxAuxiliaryDataType": TxAuxiliaryDataType,
        "TxAuxiliaryDataHash": TxAuxiliaryDataHash,
    }


def generate_tx_fixtures() -> None:
    sign_tx_data = _load_sign_tx_tests()
    era_tests = sign_tx_data["era_tests"]
    aux_data_classes = {
        "TxAuxiliaryDataCIP36": sign_tx_data["TxAuxiliaryDataCIP36"],
        "TxAuxiliaryDataType": sign_tx_data["TxAuxiliaryDataType"],
        "TxAuxiliaryDataHash": sign_tx_data["TxAuxiliaryDataHash"],
    }

    for era_key in sorted(era_tests.keys()):
        tests = era_tests[era_key]
        _generate_fixtures_for_era(era_key, tests, aux_data_classes)
