# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Sequence

from tests.unit.generators.common import (
    _ensure_base58_module,
    extract_apdu_payload,
    format_bytes_as_c_array,
    sanitize_c_identifier,
    warning_expr_from_test_case,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_OPCERT_DIR

FIXTURES_FILE = GENERATED_OPCERT_DIR / "test_opcert_fixtures.h"


def _load_opcert_test_cases() -> Sequence[object]:
    _ensure_base58_module()
    from tests.standalone.input_files.signOpCert import opCertTestCases  # type: ignore

    return opCertTestCases


def generate_opcert_fixtures() -> None:
    print("Generating opcert fixtures...")

    test_cases = _load_opcert_test_cases()
    if not test_cases:
        raise RuntimeError("No opcert test cases found")

    from tests.application_client.command_builder import CommandBuilder  # type: ignore

    builder = CommandBuilder()

    header_lines = [
        "// Auto-generated Operational Certificate fixtures",
        "// Generated from tests/standalone/input_files/signOpCert.py",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        '#include "test_fixture_types.h"',
        "",
    ]

    fixture_entries: list[str] = []
    for _, test_case in enumerate(test_cases):
        safe_name = sanitize_c_identifier(test_case.name, uppercase=True)
        array_name = f"OPCERT_FIXTURE_{safe_name}_PAYLOAD"
        apdu = builder.sign_opcert(test_case)
        payload = extract_apdu_payload(apdu)
        array_lines = format_bytes_as_c_array(payload, array_name).split("\n")
        header_lines.extend(array_lines)
        header_lines.append("")

        expected_signature_array_name = "NULL"
        expected_signature_len = "0"
        if getattr(test_case, "unit_test_expect", None) is not None:
            expected_signature_bytes = bytes.fromhex(test_case.unit_test_expect.signatureHex)
            expected_signature_array_name = f"OPCERT_FIXTURE_{safe_name}_EXPECTED_SIGNATURE"
            expected_signature_lines = format_bytes_as_c_array(expected_signature_bytes, expected_signature_array_name).split(
                "\n"
            )
            header_lines.extend(expected_signature_lines)
            header_lines.append("")
            expected_signature_len = f"sizeof({expected_signature_array_name})"

        entry_lines = [
            "{",
            f'    .name = "{test_case.name}",',
            f"    .payload = {array_name},",
            f"    .payload_len = sizeof({array_name}),",
            f"    .expected_warning_bits = {warning_expr_from_test_case(test_case)},",
            f"    .expected_signature = {expected_signature_array_name},",
            f"    .expected_signature_len = {expected_signature_len},",
            "},",
        ]
        fixture_entries.append("\n".join(entry_lines))

    header_lines.append("static const opcert_fixture_t OPCERT_FIXTURES[] = {")
    header_lines.extend(fixture_entries)
    header_lines.append("};")

    write_generated_c_file(FIXTURES_FILE, "\n".join(header_lines) + "\n")
    print(f"Written opcert fixtures to {FIXTURES_FILE}")
    return len(test_cases)
