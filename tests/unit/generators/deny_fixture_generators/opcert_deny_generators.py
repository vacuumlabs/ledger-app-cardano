# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from typing import Any

from tests.unit.generators.common import (
    format_bytes_as_c_array,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_OPCERT_DIR

GENERATED_DENY_HEADER = GENERATED_OPCERT_DIR / "test_opcert_fixtures_deny.h"


def _load_opcert_deny_test_cases() -> list[Any]:
    from tests.standalone.input_files.signOpCert import opCertDenyTestCases  # type: ignore

    return opCertDenyTestCases


def _generate_fixture_code(test_case: Any, test_number: int) -> list[str]:
    code_lines: list[str] = []
    code_lines.append("// ----------------------------------------------------------------------")
    code_lines.append(f"// Deny Test {test_number}: {test_case.name}")
    code_lines.append(f"// Expected SW: {test_case.expected_swo.name} (0x{test_case.expected_swo.value:04X})")
    code_lines.append(f"// Source: tests/standalone/input_files/signOpCert.py > opCertDenyTestCases > {test_case.name}")
    code_lines.append("// ----------------------------------------------------------------------")
    code_lines.append("")

    payload_bytes = bytes.fromhex(test_case.payload_hex)
    safe_name = sanitize_c_identifier(test_case.name)
    array_name = f"OPCERT_DENY_{test_number:03d}_{safe_name}_PAYLOAD"
    code_lines.extend(format_bytes_as_c_array(payload_bytes, array_name, bytes_per_line=16, return_as_list=True))
    code_lines.append("")
    return code_lines


def _build_deny_fixtures() -> str:
    deny_test_cases = _load_opcert_deny_test_cases()

    header_lines: list[str] = [
        "//",
        "// Generator: deny_fixture_generators/opcert_deny_generators.py",
        "// Source: tests/standalone/input_files/signOpCert.py",
        "//",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        '#include "test_fixture_types.h"',
        '#include "cardano_swo.h"',
        "",
        "// ======================================================================",
        "// Operational Certificate Deny Test Fixtures",
        "// ======================================================================",
        "",
    ]

    for idx, test_case in enumerate(deny_test_cases):
        header_lines.extend(_generate_fixture_code(test_case, idx))

    header_lines.append("static const opcert_deny_fixture_t OPCERT_DENY_FIXTURES[] = {")
    for idx, test_case in enumerate(deny_test_cases):
        safe_name = sanitize_c_identifier(test_case.name)
        array_name = f"OPCERT_DENY_{idx:03d}_{safe_name}_PAYLOAD"
        header_lines.append(f"// Source: tests/standalone/input_files/signOpCert.py > opCertDenyTestCases > {test_case.name}")
        header_lines.append("{")
        header_lines.append(f'    .name = "{test_case.name}",')
        header_lines.append(f"    .payload = {array_name},")
        header_lines.append(f"    .payload_len = sizeof({array_name}),")
        header_lines.append(f"    .expected_swo = {test_case.expected_swo.name},")
        header_lines.append("},")
    header_lines.append("};")
    header_lines.append("")

    return "\n".join(header_lines)


def generate_opcert_deny_fixtures() -> None:
    content = _build_deny_fixtures()
    write_generated_c_file(GENERATED_DENY_HEADER, content)
    print(f"Generated {GENERATED_DENY_HEADER}")
