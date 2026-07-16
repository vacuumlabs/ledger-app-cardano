# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
Shared code generation utilities for native script fixtures.

This module contains the recursive tree generation logic used by both
fixture generators (valid and reject test cases).
"""

from __future__ import annotations

from typing import Any

from tests.application_client.command_builder import (
    CommandBuilder,  # type: ignore
    NativeScriptType,
)
from tests.unit.generators.common import (
    extract_apdu_payload,
    format_bytes_as_c_array,
)


def _is_simple_native_script(native_script: Any) -> bool:
    """
    Determine if a native script is a simple (leaf) script.

    Args:
        native_script: NativeScript object

    Returns:
        True if SIMPLE (leaf node), False if COMPLEX (internal node)
    """
    simple_types = {
        NativeScriptType.PUBKEY_DEVICE_OWNED,
        NativeScriptType.PUBKEY_THIRD_PARTY,
        NativeScriptType.INVALID_BEFORE,
        NativeScriptType.INVALID_HEREAFTER,
    }
    return native_script.type in simple_types


def generate_native_script_tree_recursive(
    native_script: Any,
    base_unique_id: str,
    child_index: int = 0,
    simple_script_generator_func: Any = None,
) -> tuple[list[str], str]:
    """
    Recursively generate C structs for a native script tree.

    Tree structure:
    - Leaf nodes: SIMPLE scripts (PUBKEY, INVALID_BEFORE/HEREAFTER)
    - Internal nodes: COMPLEX scripts (ALL, ANY, N_OF_K) containing children

    This function performs a depth-first traversal of the script tree,
    generating C structs in post-order (children before parents).

    Args:
        native_script: NativeScript object (can be SIMPLE or COMPLEX)
        base_unique_id: Base identifier for naming
        child_index: Index of this script among its siblings
        simple_script_generator_func: Function to generate simple script fixtures
                                      (takes current_unique_id and native_script)

    Returns:
        Tuple of (list of C code lines, identifier of generated struct)
    """
    current_unique_id = f"{base_unique_id}_C{child_index}"
    fixture_lines = []

    is_leaf_node = _is_simple_native_script(native_script)

    if is_leaf_node:
        # Leaf node: SIMPLE script (no children)
        simple_script_lines = simple_script_generator_func(current_unique_id, native_script)
        fixture_lines.extend(simple_script_lines)
        return fixture_lines, f"SCRIPT_{current_unique_id}"

    # Internal node: COMPLEX script (has children)
    script_type = native_script.type
    child_scripts_list = native_script.params.scripts
    required_count = getattr(native_script.params, "requiredCount", None)

    if script_type == NativeScriptType.N_OF_K:
        fixture_lines.append(f"// N_OF_K (internal node): {required_count} of {len(child_scripts_list)} children required")
    else:
        fixture_lines.append(f"// {script_type.name} (internal node): {len(child_scripts_list)} children")

    # Recursively generate each child (post-order traversal)
    child_script_identifiers = []
    for child_idx, child_script in enumerate(child_scripts_list):
        child_lines, child_struct_id = generate_native_script_tree_recursive(
            child_script, current_unique_id, child_idx, simple_script_generator_func
        )
        fixture_lines.extend(child_lines)
        fixture_lines.append("")
        child_script_identifiers.append(child_struct_id)

    # Generate array of child script pointers
    fixture_lines.append(f"static const native_script_t* CHILDREN_{current_unique_id}[] = {{")
    if len(child_script_identifiers) == 0:
        fixture_lines.append("    NULL")
    else:
        for child_id in child_script_identifiers:
            fixture_lines.append(f"    (const native_script_t*)&{child_id},")
    fixture_lines.append("};")
    fixture_lines.append("")

    # Generate parent COMPLEX script struct.
    # Union field name and contents differ per type; N_OF_K adds required_count.
    union_field = script_type.name.lower()  # "all", "any", or "n_of_k"
    fixture_lines.append(f"static const native_script_t SCRIPT_{current_unique_id} = {{")
    fixture_lines.append(f"    .type = NATIVE_SCRIPT_TYPE_{script_type.name},")
    fixture_lines.append("    .impl = {")
    fixture_lines.append("        .complex = {")
    fixture_lines.append("             .params = {")
    fixture_lines.append(f"                 .{union_field} = {{")
    if required_count is not None:
        fixture_lines.append(f"                     .required_count = {required_count},")
    fixture_lines.append(f"                     .scripts = CHILDREN_{current_unique_id},")
    fixture_lines.append(f"                     .scripts_count = {len(child_scripts_list)},")
    fixture_lines.append("                 }")
    fixture_lines.append("             }")
    fixture_lines.append("         }")
    fixture_lines.append("     }")
    fixture_lines.append("};")

    return fixture_lines, f"SCRIPT_{current_unique_id}"


def generate_simple_script_apdu_array(
    script_identifier: str,
    script: Any,
) -> tuple[list[str], str]:
    """
    Generate APDU payload array for a simple script.

    Args:
        script_identifier: Unique identifier for this script
        script: Native script object

    Returns:
        Tuple of (C code lines, array name)
    """
    command_builder = CommandBuilder()
    full_apdu = command_builder.derive_script_add_simple(script)
    apdu_payload = extract_apdu_payload(full_apdu)

    lines = []
    array_name = f"APDU_PAYLOAD_{script_identifier}"

    lines.append("// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE")
    lines.append(f"// Script type: {script.type.name}")
    lines.extend(format_bytes_as_c_array(apdu_payload, name=array_name, bytes_per_line=8, return_as_list=True))
    lines.append("")

    return lines, array_name


def generate_simple_script_fixture(
    script_identifier: str,
    script: Any,
) -> list[str]:
    """
    Generate complete simple script fixture.

    Args:
        script_identifier: Unique identifier
        script: Native script object

    Returns:
        List of C code lines
    """
    lines = []

    # Generate APDU payload array
    apdu_lines, apdu_array_name = generate_simple_script_apdu_array(script_identifier, script)
    lines.extend(apdu_lines)

    # Generate script structure
    script_type_enum = f"NATIVE_SCRIPT_TYPE_{script.type.name}"

    lines.append(f"static const native_script_t SCRIPT_{script_identifier} = {{")
    lines.append(f"    .type = {script_type_enum},")
    lines.append("    .impl = {")
    lines.append("        .simple = {")
    lines.append(f"            .apdu_payload = {apdu_array_name},")
    lines.append(f"            .apdu_payload_length = sizeof({apdu_array_name}),")
    lines.append("        }")
    lines.append("    }")
    lines.append("};")
    lines.append("")

    return lines


def generate_finish_apdu_payload(
    test_case_id: str,
    display_format: Any,
) -> tuple[list[str], str]:
    """
    Generate APDU payload for derive_script_finish.

    Args:
        test_case_id: Test case identifier
        display_format: NativeScriptHashDisplayFormat enum value from test case

    Returns:
        Tuple of (C code lines, array name)
    """
    command_builder = CommandBuilder()
    full_apdu = command_builder.derive_script_finish(display_format)
    apdu_payload = extract_apdu_payload(full_apdu)

    lines = []
    array_name = f"FINISH_APDU_PAYLOAD_{test_case_id}"

    lines.append("// APDU payload for P1_NATIVE_SCRIPT_FINISH")
    lines.append(f"// Display format: {display_format.name} (0x{display_format.value:02x})")
    lines.extend(format_bytes_as_c_array(apdu_payload, name=array_name, bytes_per_line=8, return_as_list=True))
    lines.append("")

    return lines, array_name
