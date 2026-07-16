# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any

from tests.unit.generators.common import (
    extract_apdu_payload,
    format_bytes_as_c_array,
    sanitize_c_identifier,
    warning_expr_from_test_case,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_CVOTE_DIR

FIXTURES_FILE = GENERATED_CVOTE_DIR / "test_cvote_fixtures.h"


def _load_cvote_test_cases() -> list[Any]:
    from tests.standalone.input_files.cvote import cvoteTestCases  # type: ignore

    return cvoteTestCases


def generate_cvote_fixtures() -> int:
    print("Generating cvote fixtures...")

    test_cases = _load_cvote_test_cases()
    if not test_cases:
        raise RuntimeError("No cvote test cases found")
    from tests.application_client.command_builder import CommandBuilder  # type: ignore

    builder = CommandBuilder()

    header_lines = [
        "// Auto-generated CIP-36 VoteCast signing fixtures",
        "// Generated from tests/standalone/input_files/cvote.py",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        '#include "securityWarnings.h"',
        '#include "test_fixture_types.h"',
        "",
        "// ======================================================================",
        "// CIP-36 CVote Test Fixtures",
        "// ======================================================================",
        "",
    ]

    fixture_entries: list[str] = []
    for test_index, test_case in enumerate(test_cases):
        safe_name = sanitize_c_identifier(test_case.name, uppercase=True)
        base_name = f"CVOTE_{test_index:03d}_{safe_name}"

        # INIT APDU
        init_apdu = builder.sign_cvote_init(test_case)
        init_payload = extract_apdu_payload(init_apdu)
        init_array_name = f"{base_name}_INIT_APDU"
        header_lines.extend(format_bytes_as_c_array(init_payload, init_array_name, bytes_per_line=8, return_as_list=True))
        header_lines.append("")

        # CHUNK APDUs
        chunk_apdus: list[bytes] = builder.sign_cvote_chunk(test_case)
        chunk_array_names: list[str] = []
        for chunk_idx, chunk_apdu in enumerate(chunk_apdus):
            chunk_payload = extract_apdu_payload(chunk_apdu)
            chunk_array_name = f"{base_name}_CHUNK_{chunk_idx:03d}_APDU"
            header_lines.extend(
                format_bytes_as_c_array(
                    chunk_payload,
                    chunk_array_name,
                    bytes_per_line=8,
                    return_as_list=True,
                )
            )
            header_lines.append("")
            chunk_array_names.append(chunk_array_name)

        if chunk_array_names:
            chunks_struct_name = f"{base_name}_CHUNKS"
            header_lines.append(f"static const cvote_chunk_t {chunks_struct_name}[] = {{")
            for chunk_array_name in chunk_array_names:
                header_lines.extend(
                    [
                        "    {",
                        f"        .data = {chunk_array_name},",
                        f"        .data_len = sizeof({chunk_array_name}),",
                        "    },",
                    ]
                )
            header_lines.append("};")
            header_lines.append("")

        # CONFIRM APDU (contains witness path)
        confirm_apdu = builder.sign_cvote_confirm(test_case)
        confirm_payload = extract_apdu_payload(confirm_apdu)
        confirm_array_name = f"{base_name}_CONFIRM_APDU"
        header_lines.extend(
            format_bytes_as_c_array(
                confirm_payload,
                confirm_array_name,
                bytes_per_line=8,
                return_as_list=True,
            )
        )
        header_lines.append("")

        expected_votecast_hash_array_name = "NULL"
        expected_votecast_hash_len = "0"
        expected_witness_signature_array_name = "NULL"
        expected_witness_signature_len = "0"
        if getattr(test_case, "unit_test_expect", None) is not None:
            expected_votecast_hash_bytes = bytes.fromhex(test_case.unit_test_expect.votecastHashHex)
            expected_votecast_hash_array_name = f"{base_name}_EXPECTED_VOTECAST_HASH"
            header_lines.extend(
                format_bytes_as_c_array(
                    expected_votecast_hash_bytes,
                    expected_votecast_hash_array_name,
                    bytes_per_line=8,
                    return_as_list=True,
                )
            )
            header_lines.append("")
            expected_votecast_hash_len = f"sizeof({expected_votecast_hash_array_name})"

            expected_witness_signature_bytes = bytes.fromhex(test_case.unit_test_expect.witnessSignatureHex)
            expected_witness_signature_array_name = f"{base_name}_EXPECTED_WITNESS_SIGNATURE"
            header_lines.extend(
                format_bytes_as_c_array(
                    expected_witness_signature_bytes,
                    expected_witness_signature_array_name,
                    bytes_per_line=8,
                    return_as_list=True,
                )
            )
            header_lines.append("")
            expected_witness_signature_len = f"sizeof({expected_witness_signature_array_name})"

        # Fixture entry
        chunks_struct = f"{base_name}_CHUNKS" if chunk_array_names else "NULL"
        chunk_count = f"sizeof({base_name}_CHUNKS) / sizeof(cvote_chunk_t)" if chunk_array_names else "0"
        entry_lines = [
            "{",
            f'    .name = "{test_case.name}",',
            f"    .init_data = {init_array_name},",
            f"    .init_data_len = sizeof({init_array_name}),",
            f"    .chunks = {chunks_struct},",
            f"    .chunk_count = {chunk_count},",
            f"    .confirm_data = {confirm_array_name},",
            f"    .confirm_data_len = sizeof({confirm_array_name}),",
            f"    .expected_warning_bits = {warning_expr_from_test_case(test_case)},",
            f"    .expected_votecast_hash = {expected_votecast_hash_array_name},",
            f"    .expected_votecast_hash_len = {expected_votecast_hash_len},",
            f"    .expected_witness_signature = {expected_witness_signature_array_name},",
            f"    .expected_witness_signature_len = {expected_witness_signature_len},",
            "},",
        ]
        fixture_entries.append("\n".join(entry_lines))

    header_lines.append("static const cvote_fixture_t CVOTE_FIXTURES[] = {")
    header_lines.extend(fixture_entries)
    header_lines.append("};")
    header_lines.append("")

    write_generated_c_file(FIXTURES_FILE, "\n".join(header_lines) + "\n")
    print(f"Written cvote fixtures to {FIXTURES_FILE}")
    return len(test_cases)
