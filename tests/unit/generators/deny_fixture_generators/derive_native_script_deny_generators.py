# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any

from tests.unit.generators.common import (
    _ensure_base58_module,
    sanitize_c_identifier,
    write_generated_c_file,
)
from tests.unit.generators.native_script_codegen import (
    generate_finish_apdu_payload,
    generate_native_script_tree_recursive,
    generate_simple_script_fixture,
)
from tests.unit.generators.paths import GENERATED_NATIVE_SCRIPT_DIR

FIXTURES_FILE = GENERATED_NATIVE_SCRIPT_DIR / "test_derive_native_script_deny_fixtures.h"


def _load_native_script_test_cases() -> list[Any]:
    """
    Load native script test cases from ragger standalone tests.

    These test cases verify that the device properly handles native script
    hash derivation requests.

    Returns:
        List of InvalidScriptTestCase objects from ragger tests
    """
    _ensure_base58_module()

    # Import test cases from ragger standalone input files
    from tests.standalone.input_files.native_script import (  # type: ignore
        InvalidScriptTestCases,
    )

    return InvalidScriptTestCases


def _build_fixtures() -> str:
    """
    Generate complete C file content for native script hash derivation fixtures.

    Tree structure:
    - Each test case is a root of a native script tree
    - Leaf nodes: SIMPLE scripts (PUBKEY, INVALID_BEFORE/HEREAFTER)
    - Internal nodes: COMPLEX scripts (ALL, ANY, N_OF_K) with children

    Returns:
        Complete C file content as string
    """
    # Load test cases from ragger tests
    all_test_cases = _load_native_script_test_cases()

    print(f"  Loaded {len(all_test_cases)} test cases")
    print()

    # Start building header content
    header_lines = [
        "// Auto-generated native script hash derivation test fixtures",
        "// Generated from ragger standalone test cases",
        "//",
        "//",
        "// Tree Structure:",
        "//   - Each test case is a root of a native script tree",
        "//   - Leaf nodes (SIMPLE scripts): PUBKEY_DEVICE_OWNED, PUBKEY_THIRD_PARTY,",
        "//                                   INVALID_BEFORE, INVALID_HEREAFTER",
        "//   - Internal nodes (COMPLEX scripts): ALL, ANY, N_OF_K",
        "//   - Internal nodes contain children (can be leaf or internal nodes)",
        "//",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        '#include "cardano_swo.h"',
        '#include "status_words.h"',
        '#include "test_fixture_types.h"',
        "",
        "#define SCRIPT_HASH_LENGTH 28  // Blake2b-224",
        "#define KEY_HASH_LENGTH 28     // Blake2b-224",
        "",
        "",
        "// ======================================================================",
        "// Native Script Tree Fixtures",
        "// ======================================================================",
        "",
    ]

    # Generate each test case as a script tree
    test_case_root_identifiers = []

    for test_case_index, test_case in enumerate(all_test_cases):
        test_case_name_sanitized = sanitize_c_identifier(test_case.name)
        base_id = f"TC{test_case_index}_{test_case_name_sanitized.upper()}"
        if test_case.unit_test_expect is None or test_case.unit_test_expect.swo is None:
            raise ValueError(f"native_script deny fixture {test_case.name!r} is missing unit_test_expect.swo")

        print(f"  [{test_case_index:2d}] Generating tree for: {test_case.name}")

        header_lines.append("// ======================================================================")
        header_lines.append(f"// Test Case [{test_case_index}]: {test_case.name}")
        header_lines.append("// Source: tests/standalone/input_files/native_script.py > deny tests")
        header_lines.append("// ======================================================================")
        header_lines.append("")

        # Recursively generate script tree
        tree_lines, root_script_id = generate_native_script_tree_recursive(
            test_case.script, base_id, 0, generate_simple_script_fixture
        )
        header_lines.extend(tree_lines)
        header_lines.append("")

        # Generate finish APDU payload
        finish_lines, finish_array_name = generate_finish_apdu_payload(base_id, test_case.displayFormat)
        header_lines.extend(finish_lines)

        # Store root identifier for test case array
        test_case_root_identifiers.append(
            (
                base_id,
                test_case.name,
                root_script_id,
                finish_array_name,
                test_case.unit_test_expect.swo.name,
            )
        )
    # Generate test case array
    header_lines.extend(
        [
            "// ======================================================================",
            "// Test Case Array",
            "// ======================================================================",
            "",
            "static const native_script_test_case_t NATIVE_SCRIPT_FIXTURES[] = {",
        ]
    )

    for (
        _base_id,
        name,
        root_id,
        finish_apdu_array,
        expected_swo,
    ) in test_case_root_identifiers:
        # Add source traceability comment
        header_lines.append(f"    // Source: tests/standalone/input_files/native_script.py > deny tests > {name}")
        header_lines.append("    {")
        header_lines.append(f'        .name = "{name}",')
        header_lines.append(f"        .root_script = (const native_script_t*)&{root_id},")
        header_lines.append(f"        .expected_response = {expected_swo},")
        header_lines.append(f"        .finish_apdu_payload = {finish_apdu_array},")
        header_lines.append(f"        .finish_apdu_payload_length = sizeof({finish_apdu_array}),")
        header_lines.append("    },")

    header_lines.extend(
        [
            "};",
            "",
            f"#define NATIVE_SCRIPT_FIXTURES_COUNT {len(test_case_root_identifiers)}",
            "",
        ]
    )

    return "\n".join(header_lines), len(test_case_root_identifiers)


def generate_derive_native_script_deny_fixtures() -> int:
    """
    Generate native script hash derivation test fixture header.

    This is the main entry point called from generate_unit_tests_from_ragger.py.
    Creates a single header file with all test fixtures as script trees:
    - Leaf nodes: SIMPLE scripts (PUBKEY, INVALID_BEFORE/HEREAFTER)
    - Internal nodes: COMPLEX scripts (ALL, ANY, N_OF_K) containing children


    Returns:
        The total number of generated fixtures.
    """
    print("Generating derive_native_script_fixtures.h...")
    print()

    fixtures, fixture_count = _build_fixtures()
    write_generated_c_file(FIXTURES_FILE, fixtures)

    print()
    print(f"Generated {FIXTURES_FILE}")
    return fixture_count
