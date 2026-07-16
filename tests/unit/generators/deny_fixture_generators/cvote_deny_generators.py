# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
Generator for CIP-36 cvote deny test fixtures.

Reads CVoteDenyTestCase entries from ragger standalone inputs and produces
a C fixture header with cvote_deny_fixture_t structs that the unit-test
runner can replay.
"""

from typing import Any

from tests.unit.generators.common import (
    format_bytes_as_c_array,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_CVOTE_DIR

GENERATED_DENY_HEADER = GENERATED_CVOTE_DIR / "test_cvote_fixtures_deny.h"

# Bad CONFIRM body: m/44'/1815'/0'/0/0 encoded as BIP44 path.
# count=5 | 0x8000002c | 0x80000717 | 0x80000000 | 0x00000000 | 0x00000000
_BAD_CONFIRM_PAYMENT_PATH_HEX = "058000002c80000717800000000000000000000000"


def _load_cvote_deny_test_cases() -> list[Any]:
    from tests.standalone.input_files.cvote import cvoteDenyTestCases  # type: ignore

    return cvoteDenyTestCases


def _load_valid_init_and_chunks() -> tuple[bytes, list[bytes]]:
    """Return the INIT payload bytes and chunk payload bytes from cvoteTestCases[0].

    This mirrors what test_cvote_deny does in the ragger test:
        valid_tc = cvoteTestCases[0]
        client = CommandSender(backend)
        _cvote_init(client, valid_tc)   # sends INIT + chunks via CommandSender
    """
    from tests.application_client.command_builder import CommandBuilder  # type: ignore
    from tests.standalone.input_files.cvote import cvoteTestCases  # type: ignore

    tc = cvoteTestCases[0]
    cb = CommandBuilder()

    init_apdu = cb.sign_cvote_init(tc)
    init_payload = init_apdu[5:]  # strip 5-byte APDU header

    chunk_payloads: list[bytes] = []
    for chunk_apdu in cb.sign_cvote_chunk(tc):
        chunk_payloads.append(chunk_apdu[5:])

    return init_payload, chunk_payloads


def _phase_enum(test_case: Any) -> str:
    if test_case.send_chunk_before_init:
        return "CVOTE_DENY_PHASE_CHUNK"
    if test_case.invalid_witness_path is not None:
        return "CVOTE_DENY_PHASE_CONFIRM"
    return "CVOTE_DENY_PHASE_INIT"


def _apdu_data_bytes(test_case: Any, valid_init_payload: bytes) -> bytes:
    """Return the primary APDU body bytes for the deny fixture."""
    if test_case.send_chunk_before_init:
        return b""
    if test_case.invalid_witness_path is not None:
        return valid_init_payload
    assert test_case.init_payload_hex is not None
    return bytes.fromhex(test_case.init_payload_hex)


def _confirm_data_bytes(test_case: Any) -> bytes | None:
    """Return the CONFIRM APDU body bytes (only for CONFIRM-phase cases)."""
    if test_case.invalid_witness_path is None:
        return None
    return bytes.fromhex(_BAD_CONFIRM_PAYMENT_PATH_HEX)


def _build_deny_fixtures() -> str:
    deny_test_cases = _load_cvote_deny_test_cases()
    valid_init_payload, valid_chunk_payloads = _load_valid_init_and_chunks()

    header_lines: list[str] = [
        "//",
        "// Generator: deny_fixture_generators/cvote_deny_generators.py",
        "// Source: tests/standalone/input_files/cvote.py",
        "//",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        '#include "test_fixture_types.h"',
        '#include "cardano_swo.h"',
        "",
        "// ======================================================================",
        "// CIP-36 CVote Deny Test Fixtures",
        "// ======================================================================",
        "",
    ]

    # Emit shared chunk arrays for the CONFIRM-phase cases (all share cvoteTestCases[0]).
    if valid_chunk_payloads:
        header_lines.append("// ----------------------------------------------------------------------")
        header_lines.append("// Shared chunk data from cvoteTestCases[0] (used by CONFIRM-phase deny tests)")
        header_lines.append("// This mirrors what _cvote_init() sends in test_cvote_deny ragger test.")
        header_lines.append("// ----------------------------------------------------------------------")
        header_lines.append("")
        for i, chunk_bytes in enumerate(valid_chunk_payloads):
            arr_name = f"CVOTE_DENY_CONFIRM_SHARED_CHUNK_{i:03d}"
            header_lines.extend(format_bytes_as_c_array(chunk_bytes, arr_name, bytes_per_line=16, return_as_list=True))
            header_lines.append("")
        chunk_arr_entries = ", ".join(
            f"{{ .data = CVOTE_DENY_CONFIRM_SHARED_CHUNK_{i:03d}, .data_len = sizeof(CVOTE_DENY_CONFIRM_SHARED_CHUNK_{i:03d}) }}"
            for i in range(len(valid_chunk_payloads))
        )
        header_lines.append(f"static const cvote_chunk_t CVOTE_DENY_CONFIRM_SHARED_CHUNKS[] = {{ {chunk_arr_entries} }};")
        header_lines.append(f"#define CVOTE_DENY_CONFIRM_SHARED_CHUNK_COUNT {len(valid_chunk_payloads)}")
        header_lines.append("")

    # Per-fixture: (safe_name, apdu_arr_name, apdu_bytes, confirm_arr_expr, confirm_len_expr, phase, tc)
    fixture_entries = []

    for idx, tc in enumerate(deny_test_cases):
        safe_name = sanitize_c_identifier(tc.name)
        phase = _phase_enum(tc)
        apdu_bytes = _apdu_data_bytes(tc, valid_init_payload)
        confirm_bytes = _confirm_data_bytes(tc)

        header_lines.append("// ----------------------------------------------------------------------")
        header_lines.append(f"// Deny Test {idx}: {tc.name}")
        header_lines.append(f"// Phase: {phase}  Expected SW: {tc.expected_swo.name}")
        header_lines.append(f"// Source: tests/standalone/input_files/cvote.py > cvoteDenyTestCases > {tc.name}")
        header_lines.append("// ----------------------------------------------------------------------")
        header_lines.append("")

        apdu_arr_name = f"CVOTE_DENY_{idx:03d}_{safe_name}_APDU"
        if apdu_bytes:
            header_lines.extend(format_bytes_as_c_array(apdu_bytes, apdu_arr_name, bytes_per_line=16, return_as_list=True))
        else:
            header_lines.append(f"static const uint8_t {apdu_arr_name}[] = {{0}};  // placeholder (empty body)")
        header_lines.append("")

        confirm_arr_expr = "NULL"
        confirm_len_expr = "0"
        if confirm_bytes is not None:
            confirm_arr_name = f"CVOTE_DENY_{idx:03d}_{safe_name}_CONFIRM"
            header_lines.extend(
                format_bytes_as_c_array(
                    confirm_bytes,
                    confirm_arr_name,
                    bytes_per_line=16,
                    return_as_list=True,
                )
            )
            header_lines.append("")
            confirm_arr_expr = confirm_arr_name
            confirm_len_expr = f"sizeof({confirm_arr_name})"

        fixture_entries.append(
            (
                safe_name,
                apdu_arr_name,
                apdu_bytes,
                confirm_arr_expr,
                confirm_len_expr,
                phase,
                tc,
            )
        )

    header_lines.append("static const cvote_deny_fixture_t CVOTE_DENY_FIXTURES[] = {")
    for (
        _safe_name,
        apdu_arr_name,
        apdu_bytes,
        confirm_arr_expr,
        confirm_len_expr,
        phase,
        tc,
    ) in fixture_entries:
        apdu_len_expr = f"sizeof({apdu_arr_name})" if apdu_bytes else "0"
        is_confirm_phase = phase == "CVOTE_DENY_PHASE_CONFIRM"
        chunks_expr = "CVOTE_DENY_CONFIRM_SHARED_CHUNKS" if is_confirm_phase and valid_chunk_payloads else "NULL"
        chunk_count_expr = "CVOTE_DENY_CONFIRM_SHARED_CHUNK_COUNT" if is_confirm_phase and valid_chunk_payloads else "0"
        header_lines.append(f"// Source: tests/standalone/input_files/cvote.py > cvoteDenyTestCases > {tc.name}")
        header_lines.append("{")
        header_lines.append(f'    .name = "{tc.name}",')
        header_lines.append(f"    .phase = {phase},")
        header_lines.append(f"    .apdu_data = {apdu_arr_name},")
        header_lines.append(f"    .apdu_data_len = {apdu_len_expr},")
        header_lines.append(f"    .chunks = {chunks_expr},")
        header_lines.append(f"    .chunk_count = {chunk_count_expr},")
        header_lines.append(f"    .confirm_data = {confirm_arr_expr},")
        header_lines.append(f"    .confirm_data_len = {confirm_len_expr},")
        header_lines.append(f"    .expected_swo = {tc.expected_swo.name},")
        header_lines.append("},")
    header_lines.append("};")
    header_lines.append("")
    header_lines.append(f"#define CVOTE_DENY_FIXTURES_COUNT {len(fixture_entries)}")
    header_lines.append("")

    return "\n".join(header_lines)


def generate_cvote_deny_fixtures() -> None:
    content = _build_deny_fixtures()
    write_generated_c_file(GENERATED_DENY_HEADER, content)
    print(f"Generated {GENERATED_DENY_HEADER}")
