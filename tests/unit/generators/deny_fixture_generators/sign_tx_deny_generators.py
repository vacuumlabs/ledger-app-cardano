# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from typing import Any

from tests.unit.generators.common import (
    format_display_name,
    hex_string_to_c_string_lines,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_SIGN_TX_DIR

SET_ORDER = [
    "transactionInitDenyTestCases",
    "addressParamsDenyTestCases",
    "certificateDenyTestCases",
    "certificateStakingDenyTestCases",
    "certificateStakePoolRetirementDenyTestCases",
    "withdrawalDenyTestCases",
    "witnessDenyTestCases",
    "singleAccountDenyTestCases",
    "collateralOutputDenyTestCases",
    "testsInvalidTokenBundleOrdering",
    "votingDenyTestCases",
    "requiredSignerDenyTestCases",
    "stakePoolRegistrationPoolIdDenyTestCases",
    "poolRegistrationOwnerDenyTestCases",
    "outputDenyTestCases",
    "testsCVoteRegistrationDenies",
    "invalidCertificates",
    "invalidPoolMetadataTestCases",
    "invalidRelayTestCases",
]

SET_PREFIX = {
    "transactionInitDenyTestCases": "DENY_INIT",
    "addressParamsDenyTestCases": "DENY_ADDRESS",
    "certificateDenyTestCases": "DENY_CERT",
    "certificateStakingDenyTestCases": "DENY_CERT_STAKING",
    "certificateStakePoolRetirementDenyTestCases": "DENY_CERT_POOL_RETIRE",
    "withdrawalDenyTestCases": "DENY_WITHDRAWAL",
    "witnessDenyTestCases": "DENY_WITNESS",
    "singleAccountDenyTestCases": "DENY_SINGLE_ACCOUNT",
    "collateralOutputDenyTestCases": "DENY_COLLATERAL_OUTPUT",
    "testsInvalidTokenBundleOrdering": "DENY_MULTIASSET",
    "votingDenyTestCases": "DENY_VOTING",
    "requiredSignerDenyTestCases": "DENY_REQUIRED_SIGNER",
    "stakePoolRegistrationPoolIdDenyTestCases": "DENY_POOL_ID",
    "poolRegistrationOwnerDenyTestCases": "DENY_POOL_OWNER",
    "outputDenyTestCases": "DENY_OUTPUT",
    "testsCVoteRegistrationDenies": "DENY_CVOTE",
    "invalidCertificates": "DENY_CERT_INVALID",
    "invalidPoolMetadataTestCases": "DENY_POOL_METADATA",
    "invalidRelayTestCases": "DENY_RELAY",
}

GENERATED_DENY_HEADER = GENERATED_SIGN_TX_DIR / "test_sign_tx_fixtures_deny.h"


def _build_deny_fixtures() -> str:
    from tests.application_client.command_builder import (  # type: ignore
        CommandBuilder,
        P1Type,
        P2Type,
        TxAuxiliaryDataCIP36,
        TxAuxiliaryDataType,
        gather_witness_paths,
    )
    from tests.application_client.status_words import StatusWord  # type: ignore
    from tests.standalone.input_files.signTx import (  # type: ignore
        addressParamsDenyTestCases,
        certificateDenyTestCases,
        certificateStakePoolRetirementDenyTestCases,
        certificateStakingDenyTestCases,
        collateralOutputDenyTestCases,
        invalidCertificates,
        invalidPoolMetadataTestCases,
        invalidRelayTestCases,
        outputDenyTestCases,
        poolRegistrationOwnerDenyTestCases,
        requiredSignerDenyTestCases,
        singleAccountDenyTestCases,
        stakePoolRegistrationPoolIdDenyTestCases,
        testsCVoteRegistrationDenies,
        testsInvalidTokenBundleOrdering,
        transactionInitDenyTestCases,
        votingDenyTestCases,
        withdrawalDenyTestCases,
        witnessDenyTestCases,
    )

    fixtures_by_set: dict[str, list[Any]] = {
        "transactionInitDenyTestCases": transactionInitDenyTestCases,
        "addressParamsDenyTestCases": addressParamsDenyTestCases,
        "certificateDenyTestCases": certificateDenyTestCases,
        "certificateStakingDenyTestCases": certificateStakingDenyTestCases,
        "certificateStakePoolRetirementDenyTestCases": certificateStakePoolRetirementDenyTestCases,
        "withdrawalDenyTestCases": withdrawalDenyTestCases,
        "witnessDenyTestCases": witnessDenyTestCases,
        "singleAccountDenyTestCases": singleAccountDenyTestCases,
        "collateralOutputDenyTestCases": collateralOutputDenyTestCases,
        "requiredSignerDenyTestCases": requiredSignerDenyTestCases,
        "testsInvalidTokenBundleOrdering": testsInvalidTokenBundleOrdering,
        "votingDenyTestCases": votingDenyTestCases,
        "stakePoolRegistrationPoolIdDenyTestCases": stakePoolRegistrationPoolIdDenyTestCases,
        "poolRegistrationOwnerDenyTestCases": poolRegistrationOwnerDenyTestCases,
        "outputDenyTestCases": outputDenyTestCases,
        "testsCVoteRegistrationDenies": testsCVoteRegistrationDenies,
        "invalidCertificates": invalidCertificates,
        "invalidPoolMetadataTestCases": invalidPoolMetadataTestCases,
        "invalidRelayTestCases": invalidRelayTestCases,
    }

    @dataclass(frozen=True)
    class ChunkInfo:
        p1: int
        p2: int
        more: bool
        hex_payload: str

    @dataclass(frozen=True)
    class FixtureInfo:
        name: str
        display_name: str
        prefix: str
        sanitized_name: str
        init_hex: str
        chunks: list[ChunkInfo]
        expected_swo: str
        expect_init_failure: bool
        required_expert_mode: bool | None
        source_set: str
        source_file: str

    def build_fixture(test_case: Any, prefix: str, source_set: str) -> FixtureInfo:
        tx = test_case.tx
        signing_mode = test_case.signingMode
        additional_paths = list(test_case.additionalWitnessPaths or [])
        builder = CommandBuilder()
        if prefix == "DENY_WITNESS":
            witness_paths = list(additional_paths)
        else:
            witness_paths = gather_witness_paths(tx, signing_mode, additional_paths)
        init_params = builder.build_tx_init_params(
            tx=tx,
            signing_mode=signing_mode,
            witness_paths=witness_paths,
        )
        init_payload = builder.sign_tx_init(init_params)[5:]
        chunks = [
            ChunkInfo(
                p1=chunk[2],
                p2=chunk[3],
                more=chunk[2] != P1Type.P1_TX_CONFIRM,
                hex_payload=chunk[5:].hex().upper(),
            )
            for chunk in builder.serialize_transaction_chunks(tx)
        ]
        if tx.auxiliaryData is not None and tx.auxiliaryData.type == TxAuxiliaryDataType.CIP36_REGISTRATION:
            aux_params = tx.auxiliaryData.params
            if not isinstance(aux_params, TxAuxiliaryDataCIP36):
                raise ValueError("Expected TxAuxiliaryDataCIP36 params for CIP36 registration")
            aux_chunks: list[ChunkInfo] = []
            aux_init_apdu = builder.sign_tx_aux_data_init(aux_params)
            aux_chunks.append(
                ChunkInfo(
                    p1=aux_init_apdu[2],
                    p2=aux_init_apdu[3],
                    more=False,
                    hex_payload=aux_init_apdu[5:].hex().upper(),
                )
            )
            for delegation in aux_params.delegations:
                delegation_apdu = builder.sign_tx_aux_data_delegation(delegation)
                aux_chunks.append(
                    ChunkInfo(
                        p1=delegation_apdu[2],
                        p2=delegation_apdu[3],
                        more=False,
                        hex_payload=delegation_apdu[5:].hex().upper(),
                    )
                )
            chunks = aux_chunks + chunks
        for path in witness_paths:
            witness_apdu = builder.sign_tx_witness(path)
            chunks.append(
                ChunkInfo(
                    p1=P1Type.P1_TX_SIGN_WITNESS,
                    p2=P2Type.P2_UNUSED,
                    more=False,
                    hex_payload=witness_apdu[5:].hex().upper(),
                )
            )
        expected_swo = test_case.expected_swo or StatusWord.SWO_SUCCESS
        expected_swo_name = expected_swo.name
        expect_init_failure = prefix == "DENY_INIT"
        if prefix == "DENY_ADDRESS":
            normalized_name = sanitize_c_identifier(test_case.name).upper()
            if "POOL_OPERATOR_SPENDING_CHOICE_NOT_PATH" in normalized_name or "POOL_OWNER_UNCONDITIONALLY" in normalized_name:
                expect_init_failure = True

        display_name = format_display_name(prefix, test_case.name)
        return FixtureInfo(
            name=test_case.name,
            display_name=display_name,
            prefix=prefix,
            sanitized_name=sanitize_c_identifier(test_case.name).upper(),
            init_hex=init_payload.hex().upper(),
            chunks=chunks,
            expected_swo=expected_swo_name,
            expect_init_failure=expect_init_failure,
            required_expert_mode=test_case.required_expert_mode,
            source_set=source_set,
            source_file="tests/standalone/input_files/signTx.py",
        )

    # Map P1/P2 values to symbolic constants from command_builder/dispatcher.h
    P1_CONSTANTS = {
        int(P1Type.P1_TX_INIT): "P1_TX_INIT",
        int(P1Type.P1_TX_CHUNK): "P1_TX_CHUNK",
        int(P1Type.P1_TX_CONFIRM): "P1_TX_CONFIRM",
        int(P1Type.P1_TX_AUX_DATA): "P1_TX_AUX_DATA",
        int(P1Type.P1_TX_SIGN_WITNESS): "P1_TX_SIGN_WITNESS",
    }
    P2_CONSTANTS = {
        int(P2Type.P2_UNUSED): "P2_UNUSED",
        int(P2Type.P2_AUX_DATA_INIT): "P2_AUX_DATA_INIT",
        int(P2Type.P2_AUX_DATA_DELEGATION): "P2_AUX_DATA_DELEGATION",
    }

    def generate_header(fixtures: dict[str, list[FixtureInfo]]) -> str:
        lines = [
            "//",
            "// Generator: deny_fixture_generators/sign_tx_deny_generators.py",
            "// Source: tests/standalone/input_files/signTx.py (deny test cases)",
            "//",
            "// To regenerate:",
            "//   cd tests/unit",
            "//   python3 generators/generate_unit_tests_from_ragger.py",
            "//",
            "// Each fixture includes source traceability comments showing:",
            "//   - Source file and test set name",
            "//   - Original Ragger test name",
            "",
            "#pragma once",
            "",
            "#include <stdint.h>",
            "#include <stdbool.h>",
            '#include "dispatcher.h"  // For P1 constants',
            "",
        ]
        for set_name in SET_ORDER:
            prefix = SET_PREFIX.get(set_name)
            if not prefix or set_name not in fixtures:
                continue
            for fixture in fixtures[set_name]:
                if not fixture.chunks:
                    continue
                lines.append(f"// Source: {fixture.source_file} > {fixture.source_set} > {fixture.name}")
                lines.append(f"static const apdu_segment_t SIGN_TX_SEGMENTS_{prefix}_{fixture.sanitized_name}[] = {{")
                for chunk in fixture.chunks:
                    lines.append("    {")
                    lines.append("        .hex_payload =")
                    lines.extend(
                        hex_string_to_c_string_lines(
                            chunk.hex_payload,
                            append_comma=True,
                        )
                    )
                    p1_constant = P1_CONSTANTS.get(chunk.p1, f"0x{chunk.p1:02X}")
                    p2_constant = P2_CONSTANTS.get(chunk.p2, f"0x{chunk.p2:02X}")
                    lines.append(f"        .p1 = {p1_constant},")
                    lines.append(f"        .p2 = {p2_constant},")
                    lines.append(f"        .more = {'true' if chunk.more else 'false'},")
                    lines.append("    },")
                lines.append("};")
                lines.append("")
            lines.append("")
        lines.append("static const sign_tx_deny_fixture_t SIGN_TX_DENY_FIXTURES[] = {")
        for set_name in SET_ORDER:
            prefix = SET_PREFIX.get(set_name)
            if not prefix or set_name not in fixtures:
                continue
            for fixture in fixtures[set_name]:
                lines.append(f"    // Source: {fixture.source_file} > {fixture.source_set} > {fixture.name}")
                lines.append("    {")
                lines.append(f'        .name = "{fixture.display_name}",')
                lines.append("        .init_hex =")
                lines.extend(
                    hex_string_to_c_string_lines(
                        fixture.init_hex,
                        indent=8,
                        append_comma=True,
                    )
                )
                if fixture.chunks:
                    array_name = f"SIGN_TX_SEGMENTS_{prefix}_{fixture.sanitized_name}"
                    lines.append(f"        .chunks = {array_name},")
                    lines.append(f"        .chunk_count = ARRAY_LEN({array_name}),")
                else:
                    lines.append("        .chunks = NULL,")
                    lines.append("        .chunk_count = 0,")
                lines.append(f"        .expected_swo = {fixture.expected_swo},")
                lines.append(f"        .expect_init_failure = {'true' if fixture.expect_init_failure else 'false'},")
                if fixture.required_expert_mode is not None:
                    lines.append("        .has_required_expert_mode = true,")
                    lines.append(f"        .required_expert_mode = {'true' if fixture.required_expert_mode else 'false'},")
                lines.append("        .skip_reason = NULL,")
                lines.append("    },")
        lines.append("};")
        lines.append("")
        return "\n".join(lines)

    total_count = 0
    fixtures: dict[str, list[FixtureInfo]] = {}
    for set_name, entries in fixtures_by_set.items():
        prefix = SET_PREFIX.get(set_name)
        if not prefix:
            continue
        fixtures.setdefault(set_name, [])
        for entry in entries:
            fixtures[set_name].append(build_fixture(entry, prefix, set_name))
            total_count += 1

    return generate_header(fixtures), total_count


def generate_tx_deny_fixtures() -> int:
    header, count = _build_deny_fixtures()
    write_generated_c_file(GENERATED_DENY_HEADER, header)
    print(f"Generated {GENERATED_DENY_HEADER}")
    return count
