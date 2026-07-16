# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from typing import Any

from tests.unit.generators.common import (
    format_bytes_as_c_array,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_PUBKEY_DIR

GENERATED_DENY_HEADER = GENERATED_PUBKEY_DIR / "test_pubkey_fixtures_deny.h"


# ==============================================================================
# Step 1: Load Deny Test Cases from Ragger Tests
# ==============================================================================


def _load_pubkey_deny_test_cases() -> list[Any]:

    from tests.standalone.input_files.pubkey import (  # type: ignore
        denyTestCases,
    )

    return denyTestCases


# ==============================================================================
# Step 2: Serialize Test Case to APDU Command
# ==============================================================================


def _serialize_deny_test_case_to_apdu(test_case: Any) -> bytes:
    path = test_case.path
    parts = path.split("/")[1:]
    data = bytearray()
    data.append(len(parts))
    for part in parts:
        hardened = part.endswith("'")
        value_str = part[:-1] if hardened else part
        value = int(value_str)
        if hardened:
            value |= 0x80000000
        data.extend(value.to_bytes(4, "big"))
    return bytes(data)


# ==============================================================================
# Step 3: Generate C Code for Deny Fixtures
# ==============================================================================


def _generate_fixture_code_for_deny_test_case(
    test_case: Any,
    test_number: int,
) -> list[str]:
    code_lines: list[str] = []

    code_lines.append("// ----------------------------------------------------------------------")
    code_lines.append(f"// Deny Test {test_number}: {test_case.name}")
    code_lines.append(f"// Path: {test_case.path}")
    code_lines.append(f"// Source: tests/standalone/input_files/pubkey.py > deny tests > {test_case.name}")
    code_lines.append("// ----------------------------------------------------------------------")
    code_lines.append("")

    payload_bytes = _serialize_deny_test_case_to_apdu(test_case)

    safe_test_name = sanitize_c_identifier(test_case.name)

    payload_array_name = f"PUBKEY_DENY_{test_number:03d}_{safe_test_name}_APDU"
    payload_array_code = format_bytes_as_c_array(
        payload_bytes,
        payload_array_name,
        bytes_per_line=16,
        return_as_list=True,
    )
    code_lines.extend(payload_array_code)
    code_lines.append("")

    return code_lines


# ==============================================================================
# Step 4: Build Complete C Header File
# ==============================================================================


def _build_deny_fixtures() -> str:
    deny_test_cases = _load_pubkey_deny_test_cases()

    header_lines: list[str] = [
        "//",
        "// Generator: deny_fixture_generators/pubkey_deny_generators.py",
        "// Source: tests/standalone/input_files/pubkey.py",
        "//",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "#include <stdbool.h>",
        '#include "cardano_swo.h"',
        '#include "test_fixture_types.h"',
        "",
        "// ======================================================================",
        "// Public Key Export Deny Test Fixtures",
        "// ======================================================================",
        "",
    ]

    for idx, test_case in enumerate(deny_test_cases):
        header_lines.extend(_generate_fixture_code_for_deny_test_case(test_case, idx))

    def _emit_fixture_array(array_name: str, silent: bool) -> None:
        header_lines.append(f"static const pubkey_fixture_t {array_name}[] = {{")
        for idx, test_case in enumerate(deny_test_cases):
            safe_test_name = sanitize_c_identifier(test_case.name)
            header_lines.append(f"// Source: tests/standalone/input_files/pubkey.py > deny tests > {test_case.name}")
            header_lines.append("{")
            header_lines.append(f'    .name = "{test_case.name}",')
            header_lines.append(f"    .data = PUBKEY_DENY_{idx:03d}_{safe_test_name}_APDU,")
            header_lines.append(f"    .data_len = sizeof(PUBKEY_DENY_{idx:03d}_{safe_test_name}_APDU),")
            header_lines.append("    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,")
            header_lines.append("    .expected_response = NULL,")
            header_lines.append("    .expected_response_len = 0,")
            header_lines.append(f"    .silent_export_enabled = {'true' if silent else 'false'},")
            header_lines.append("    .expected_policy = 0,")
            header_lines.append("},")
        header_lines.append("};")
        header_lines.append("")

    _emit_fixture_array("PUBKEY_DENY_FIXTURES", silent=False)
    _emit_fixture_array("PUBKEY_DENY_SILENT_FIXTURES", silent=True)

    return "\n".join(header_lines)


def generate_pubkey_deny_fixtures() -> None:
    content = _build_deny_fixtures()
    write_generated_c_file(GENERATED_DENY_HEADER, content)
    print(f"Generated {GENERATED_DENY_HEADER}")
