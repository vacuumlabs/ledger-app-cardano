# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from typing import Any

from tests.unit.generators.common import (
    extract_apdu_payload,
    format_bytes_as_c_array,
    sanitize_c_identifier,
    warning_expr_from_test_case,
    write_generated_c_file,
)
from tests.unit.generators.paths import GENERATED_SIGN_MSG_DIR

FIXTURES_FILE = GENERATED_SIGN_MSG_DIR / "test_sign_msg_fixtures.h"


# ==============================================================================
# Step 1: Load Test Cases from Ragger Tests
# ==============================================================================


def _load_sign_msg_test_cases() -> list[Any]:
    """
    Load sign message test cases from ragger standalone tests.

    Returns:
        List of SignMsgTestCase objects
    """

    from tests.standalone.input_files.signMsg import signMsgTestCases  # type: ignore

    return signMsgTestCases


# ==============================================================================
# Step 2: Serialize Test Case to APDU Commands
# ==============================================================================


def _serialize_sign_msg_test_case_to_apdus(test_case: Any) -> dict[str, Any]:
    """
    Serialize a sign message test case into APDU payload bytes.

    Args:
        test_case: SignMsgTestCase object from ragger tests

    Returns:
        Dictionary with keys 'init_payload', 'chunk_payloads', 'confirm_payload'
    """

    from tests.application_client.command_builder import CommandBuilder  # type: ignore

    builder = CommandBuilder()

    # Build the INIT and CONFIRM APDUs (the CHUNK payloads are built manually)
    init_apdu = builder.sign_msg_init(test_case)
    confirm_apdu = builder.sign_msg_confirm()

    chunk_payloads = builder.build_sign_msg_chunk_payloads(test_case)

    return {
        "init_payload": extract_apdu_payload(init_apdu),
        "chunk_payloads": chunk_payloads,
        "confirm_payload": extract_apdu_payload(confirm_apdu),
    }


# ==============================================================================
# Step 3: Generate C Code for Fixtures
# ==============================================================================


def _generate_expected_data_section(
    test_case: Any,
    test_number: int,
    safe_test_name: str,
) -> tuple[list[str], str | None]:
    expected = getattr(test_case, "unit_test_expect", None)
    if expected is None:
        return [], None

    base_name = f"SIGN_MSG_{test_number:03d}_{safe_test_name}"
    lines: list[str] = []

    signature_bytes = bytes.fromhex(expected.signatureHex)
    lines.extend(
        format_bytes_as_c_array(
            signature_bytes,
            f"{base_name}_EXPECTED_SIGNATURE",
            bytes_per_line=16,
            return_as_list=True,
        )
    )
    lines.append("")

    public_key_bytes = bytes.fromhex(expected.signingPublicKeyHex)
    lines.extend(
        format_bytes_as_c_array(
            public_key_bytes,
            f"{base_name}_EXPECTED_PUBLIC_KEY",
            bytes_per_line=16,
            return_as_list=True,
        )
    )
    lines.append("")

    address_field_bytes = bytes.fromhex(expected.addressFieldHex)
    lines.extend(
        format_bytes_as_c_array(
            address_field_bytes,
            f"{base_name}_EXPECTED_ADDRESS_FIELD",
            bytes_per_line=16,
            return_as_list=True,
        )
    )
    lines.append("")

    expected_struct_name = f"{base_name}_EXPECTED"
    lines.extend(
        [
            f"static const sign_msg_expected_t {expected_struct_name} = {{",
            f"    .signature = {base_name}_EXPECTED_SIGNATURE,",
            f"    .signature_len = sizeof({base_name}_EXPECTED_SIGNATURE),",
            f"    .public_key = {base_name}_EXPECTED_PUBLIC_KEY,",
            f"    .public_key_len = sizeof({base_name}_EXPECTED_PUBLIC_KEY),",
            f"    .address_field = {base_name}_EXPECTED_ADDRESS_FIELD,",
            f"    .address_field_len = sizeof({base_name}_EXPECTED_ADDRESS_FIELD),",
            "};",
            "",
        ]
    )

    return lines, expected_struct_name


def _generate_fixture_code_for_test_case(
    test_case: Any,
    test_number: int,
    payloads: dict[str, bytes],
) -> tuple[list[str], str | None]:
    """
    Generate C code for a single sign message test fixture.

    Args:
        test_case: SignMsgTestCase from ragger tests
        test_number: Sequential test number (0-based)

    Returns:
        List of C code lines defining the test fixture
    """
    code_lines: list[str] = []

    code_lines.append("// ----------------------------------------------------------------------")
    code_lines.append(f"// Test {test_number}: {test_case.name}")
    code_lines.append("// ----------------------------------------------------------------------")
    code_lines.append("")

    # payloads provided by caller to avoid redundant serialization

    safe_test_name = sanitize_c_identifier(test_case.name)

    code_lines.append(f"// Source: tests/standalone/input_files/signMsg.py > {test_case.name}")

    # INIT payload
    init_array_name = f"SIGN_MSG_{test_number:03d}_{safe_test_name}_INIT_APDU"
    init_array_code = format_bytes_as_c_array(
        payloads["init_payload"],
        init_array_name,
        bytes_per_line=16,
        return_as_list=True,
    )
    code_lines.extend(init_array_code)
    code_lines.append("")

    chunk_payloads = payloads["chunk_payloads"]
    chunk_array_names: list[str] = []
    for chunk_index, chunk_payload in enumerate(chunk_payloads):
        chunk_array_name = f"SIGN_MSG_{test_number:03d}_{safe_test_name}_CHUNK_APDU_{chunk_index:03d}"
        chunk_array_code = format_bytes_as_c_array(
            chunk_payload,
            chunk_array_name,
            bytes_per_line=16,
            return_as_list=True,
        )
        code_lines.extend(chunk_array_code)
        code_lines.append("")
        chunk_array_names.append(chunk_array_name)

    chunk_struct_name = f"SIGN_MSG_{test_number:03d}_{safe_test_name}_CHUNKS"
    if chunk_array_names:
        code_lines.append(f"static const sign_msg_chunk_t {chunk_struct_name}[] = {{")
        for chunk_array_name in chunk_array_names:
            code_lines.append(f"    {{ .data = {chunk_array_name}, .data_len = sizeof({chunk_array_name}), }},")
        code_lines.append("};")
        code_lines.append("")

    # CONFIRM payload (usually empty)
    confirm_array_name = f"SIGN_MSG_{test_number:03d}_{safe_test_name}_CONFIRM_APDU"
    confirm_payload = payloads["confirm_payload"]
    if confirm_payload:
        confirm_array_code = format_bytes_as_c_array(
            confirm_payload,
            confirm_array_name,
            bytes_per_line=16,
            return_as_list=True,
        )
        code_lines.extend(confirm_array_code)
        code_lines.append("")

    expected_section, expected_struct_name = _generate_expected_data_section(test_case, test_number, safe_test_name)
    code_lines.extend(expected_section)

    return code_lines, expected_struct_name


# ==============================================================================
# Step 4: Build Complete C Header File
# ==============================================================================


def _build_fixtures() -> str:
    test_cases = _load_sign_msg_test_cases()

    header_lines: list[str] = [
        "//",
        "// Generator: fixture_generators/sign_msg_generators.py",
        "// Source: tests/standalone/input_files/signMsg.py",
        "//",
        "// To regenerate:",
        "//   cd tests/unit",
        "//   python3 generators/generate_unit_tests_from_ragger.py",
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
        "// CIP-8 Message Signing Test Fixtures",
        "// ======================================================================",
        "",
    ]

    # Generate fixture data arrays
    fixture_payloads: list[dict[str, bytes]] = []
    fixture_expected_structs: list[str | None] = []
    for idx, test_case in enumerate(test_cases):
        payloads = _serialize_sign_msg_test_case_to_apdus(test_case)
        fixture_payloads.append(payloads)
        fixture_lines, expected_struct_name = _generate_fixture_code_for_test_case(
            test_case,
            idx,
            payloads,
        )
        header_lines.extend(fixture_lines)
        fixture_expected_structs.append(expected_struct_name)

    # Generate fixture array
    header_lines.append("static const sign_msg_fixture_t SIGN_MSG_FIXTURES[] = {")
    for idx, test_case in enumerate(test_cases):
        payloads = fixture_payloads[idx]
        safe_test_name = sanitize_c_identifier(test_case.name)
        header_lines.append(f"// Source: tests/standalone/input_files/signMsg.py > {test_case.name}")
        header_lines.append("{")
        header_lines.append(f'    .name = "{test_case.name}",')
        header_lines.append(f"    .init_data = SIGN_MSG_{idx:03d}_{safe_test_name}_INIT_APDU,")
        header_lines.append(f"    .init_data_len = sizeof(SIGN_MSG_{idx:03d}_{safe_test_name}_INIT_APDU),")
        chunk_struct_name = f"SIGN_MSG_{idx:03d}_{safe_test_name}_CHUNKS"
        if payloads["chunk_payloads"]:
            header_lines.append(f"    .chunks = {chunk_struct_name},")
            header_lines.append(f"    .chunk_count = ARRAY_LEN({chunk_struct_name}),")
        else:
            header_lines.append("    .chunks = NULL,")
            header_lines.append("    .chunk_count = 0,")
        if payloads["confirm_payload"]:
            header_lines.append(f"    .confirm_data = SIGN_MSG_{idx:03d}_{safe_test_name}_CONFIRM_APDU,")
            header_lines.append(f"    .confirm_data_len = sizeof(SIGN_MSG_{idx:03d}_{safe_test_name}_CONFIRM_APDU),")
        else:
            header_lines.append("    .confirm_data = NULL,")
            header_lines.append("    .confirm_data_len = 0,")
        header_lines.append("    .check_expected = SWO_SUCCESS,")
        header_lines.append(f"    .expected_warning_bits = {warning_expr_from_test_case(test_case)},")
        expected_struct_name = fixture_expected_structs[idx]
        if expected_struct_name:
            header_lines.append(f"    .expected = &{expected_struct_name},")
        else:
            header_lines.append("    .expected = NULL,")
        header_lines.append("},")
    header_lines.append("};")
    header_lines.append("")

    return "\n".join(header_lines)


def generate_sign_msg_fixtures() -> int:
    content = _build_fixtures()
    write_generated_c_file(FIXTURES_FILE, content)
    print(f"Generated {FIXTURES_FILE}")
    from tests.standalone.input_files.signMsg import signMsgTestCases  # type: ignore

    return len(signMsgTestCases)
