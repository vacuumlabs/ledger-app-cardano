# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

import re
from pathlib import Path
from typing import Sequence

from tests.unit.generators.common import (
    read_file_safe,
    write_generated_c_file,
    sanitize_c_identifier,
)
from tests.unit.generators.paths import GENERATED_SIGN_TX_DIR


# ======================================================================
# Compiled Regex Patterns (module level for performance)
# ======================================================================

# Match fixture declarations like: static const tx_fixture_t FIXTURE_NAME = { ... };
_FIXTURE_PATTERN = re.compile(
    r"static\s+const\s+tx_fixture_t\s+(FIXTURE_[A-Z0-9_]+)\s*=\s*\{(.*?)\};",
    re.S,
)

# Match .name fields within fixture bodies, including concatenated C string literals
_NAME_FIELD_PATTERN = re.compile(r'\.name\s*=\s*((?:"[^"]*"\s*)+)')
AUX_INCLUDED_PATTERN = re.compile(r"\.include_aux_data_hash\s*=\s*(true|false)")
AUX_TYPE_PATTERN = re.compile(r"\.aux_data_type\s*=\s*([A-Z0-9_]+|\d+)")
BLIND_SIGNING_MODE_PATTERN = re.compile(
    r"\.blind_signing_mode\s*=\s*(BLIND_SIGNING_MODE_[A-Z_]+|\d+)"
)
SIGNING_MODE_PATTERN = re.compile(r"\.signing_mode\s*=\s*(\d+)")
SIGN_TX_SIGNINGMODE_UNRESTRICTED = 9


ERA_COMMENT_OVERRIDES = {
    "conway_without_certificates": "CONWAY_WITHOUT_CERTIFICATES Era Tests",
    "alonzo_catalyst": "ALONZO_CATALYST Era Tests",
    "alonzo_cip36": "ALONZO_CIP36 Era Tests",
}

ERA_TEST_FILE_MAP: dict[str, tuple[str, str, str]] = {
    "byron": ("test_sign_tx_fixtures_byron.h", "test_sign_tx_byron.c", "BYRON"),
    "shelley": ("test_sign_tx_fixtures_shelley.h", "test_sign_tx_shelley.c", "SHELLEY"),
    "mary": ("test_sign_tx_fixtures_mary.h", "test_sign_tx_mary.c", "MARY"),
    "allegra": ("test_sign_tx_fixtures_allegra.h", "test_sign_tx_allegra.c", "ALLEGRA"),
    "alonzo": ("test_sign_tx_fixtures_alonzo.h", "test_sign_tx_alonzo.c", "ALONZO"),
    "babbage": ("test_sign_tx_fixtures_babbage.h", "test_sign_tx_babbage.c", "BABBAGE"),
    "alonzo_catalyst": (
        "test_sign_tx_fixtures_alonzo_catalyst.h",
        "test_sign_tx_alonzo_catalyst.c",
        "ALONZO_CATALYST",
    ),
    "alonzo_cip36": (
        "test_sign_tx_fixtures_alonzo_cip36.h",
        "test_sign_tx_alonzo_cip36.c",
        "ALONZO_CIP36",
    ),
    "conway": ("test_sign_tx_fixtures_conway.h", "test_sign_tx_conway.c", "CONWAY"),
    "conway_voting": (
        "test_sign_tx_fixtures_conway_voting.h",
        "test_sign_tx_conway_voting.c",
        "CONWAY_VOTING",
    ),
    "conway_without_certificates": (
        "test_sign_tx_fixtures_conway_without_certificates.h",
        "test_sign_tx_conway_without_certificates.c",
        "CONWAY_WITHOUT_CERTIFICATES",
    ),
    "shelley_certificates": (
        "test_sign_tx_fixtures_shelley_certificates.h",
        "test_sign_tx_shelley_certificates.c",
        "SHELLEY_CERTIFICATES",
    ),
    "multisig": (
        "test_sign_tx_fixtures_multisig.h",
        "test_sign_tx_multisig.c",
        "MULTISIG",
    ),
    "pool_registration": (
        "test_sign_tx_fixtures_pool_registration.h",
        "test_sign_tx_pool_registration.c",
        "POOL_REGISTRATION",
    ),
    "streaming": (
        "test_sign_tx_fixtures_streaming.h",
        "test_sign_tx_streaming.c",
        "STREAMING",
    ),
}


def fixture_has_cvote_aux_data(fixture_body: str) -> bool:
    aux_included_match = AUX_INCLUDED_PATTERN.search(fixture_body)
    aux_type_match = AUX_TYPE_PATTERN.search(fixture_body)
    if aux_included_match is None or aux_type_match is None:
        return False

    include_aux_data = aux_included_match.group(1) == "true"
    aux_type_token = aux_type_match.group(1)
    return include_aux_data and aux_type_token in {
        "1",
        "AUX_DATA_TYPE_CVOTE_REGISTRATION",
    }


def fixture_has_blind_signing_prompt(fixture_body: str) -> bool:
    blind_signing_mode_match = BLIND_SIGNING_MODE_PATTERN.search(fixture_body)
    if blind_signing_mode_match is None:
        return False

    return blind_signing_mode_match.group(1) in {
        "BLIND_SIGNING_MODE_PROMPT_REVIEW_HASH",
        "BLIND_SIGNING_MODE_PROMPT_REVIEW_FULL",
    }


def fixture_has_blind_signing_hash_only_path(fixture_body: str) -> bool:
    blind_signing_mode_match = BLIND_SIGNING_MODE_PATTERN.search(fixture_body)
    if blind_signing_mode_match is None:
        return False

    return blind_signing_mode_match.group(1) == "BLIND_SIGNING_MODE_PROMPT_REVIEW_HASH"


def fixture_is_unrestricted(fixture_body: str) -> bool:
    signing_mode_match = SIGNING_MODE_PATTERN.search(fixture_body)
    if signing_mode_match is None:
        return False

    return int(signing_mode_match.group(1)) == SIGN_TX_SIGNINGMODE_UNRESTRICTED


def _build_test_functions(
    fixtures: Sequence[tuple[str, str, bool, bool, bool]],
) -> tuple[list[str], list[str]]:
    functions: list[str] = []
    names: list[str] = []
    for (
        fixture_name,
        display_name,
        has_cvote_aux_data,
        has_blind_signing_hash_only_path,
        is_unrestricted,
    ) in fixtures:
        func_suffix = sanitize_c_identifier(display_name, uppercase=False)
        if not func_suffix:
            raise ValueError(f"Unable to sanitize fixture name {display_name}")
        test_name = f"test_{func_suffix}"
        if is_unrestricted:
            function_name = f"{test_name}_deny_init_expert_off"
            functions.append(
                "static void\n"
                f"{function_name}(void **state) {{\n"
                f"    (void) state;\n"
                f"    run_fixture_init_deny_with_expert_mode(\n"
                f"        &{fixture_name},\n"
                f"        false,\n"
                f"        SWO_SECURITY_CONDITION_NOT_SATISFIED);\n"
                f"}}"
            )
            names.append(function_name)

        expert_mode_variants = (
            [("expert_on", "true")]
            if is_unrestricted
            else [("expert_off", "false"), ("expert_on", "true")]
        )
        for suffix, expert_flag in expert_mode_variants:
            function_name = f"{test_name}_{suffix}"
            functions.append(
                "static void\n"
                f"{function_name}(void **state) {{\n"
                f"    (void) state;\n"
                f"    run_fixture_with_expert_mode(&{fixture_name}, {expert_flag});\n"
                f"}}"
            )
            names.append(function_name)

            reject_tx_function_name = f"{test_name}_reject_tx_{suffix}"
            functions.append(
                "static void\n"
                f"{reject_tx_function_name}(void **state) {{\n"
                f"    (void) state;\n"
                f"    run_fixture_reject_tx_with_expert_mode(&{fixture_name}, {expert_flag});\n"
                f"}}"
            )
            names.append(reject_tx_function_name)

            if has_cvote_aux_data:
                reject_aux_function_name = f"{test_name}_reject_aux_{suffix}"
                functions.append(
                    "static void\n"
                    f"{reject_aux_function_name}(void **state) {{\n"
                    f"    (void) state;\n"
                    f"    run_fixture_reject_aux_with_expert_mode(&{fixture_name}, {expert_flag});\n"
                    f"}}"
                )
                names.append(reject_aux_function_name)

            if has_blind_signing_hash_only_path:
                blind_signing_hash_only_function_name = (
                    f"{test_name}_blind_signing_hash_only_{suffix}"
                )
                functions.append(
                    "static void\n"
                    f"{blind_signing_hash_only_function_name}(void **state) {{\n"
                    f"    (void) state;\n"
                    f"    run_fixture_blind_signing_hash_only_with_expert_mode("
                    f"&{fixture_name}, {expert_flag});\n"
                    f"}}"
                )
                names.append(blind_signing_hash_only_function_name)
    return functions, names


def _build_main_function(test_names: Sequence[str], test_c_file: str) -> str:
    registrations = ",\n".join(
        f"        cmocka_unit_test(\n            {name})" for name in test_names
    )
    return (
        "// ======================================================================\n"
        "// Main\n"
        "// ======================================================================\n\n"
        "int main(void) {\n"
        "    const struct CMUnitTest tests[] = {\n"
        f"{registrations},\n"
        "    };\n"
        f'    return _cmocka_run_group_tests(\n        "{Path(test_c_file).stem}",\n'
        "        tests,\n"
        "        ARRAY_LEN(tests),\n"
        "        NULL,\n"
        "        assert_no_pending_apdu_response);\n"
        "}\n"
    )


def _extract_fixtures_from_header(
    fixture_path: Path,
) -> list[tuple[str, str, bool, bool, bool]]:
    content = read_file_safe(fixture_path)
    fixtures: list[tuple[str, str, bool, bool, bool]] = []
    for match in _FIXTURE_PATTERN.finditer(content):
        fixture_name = match.group(1)
        body = match.group(2)
        name_match = _NAME_FIELD_PATTERN.search(body)
        if not name_match:
            continue
        display_name = "".join(re.findall(r'"([^"]*)"', name_match.group(1)))
        fixtures.append(
            (
                fixture_name,
                display_name,
                fixture_has_cvote_aux_data(body),
                fixture_has_blind_signing_hash_only_path(body),
                fixture_is_unrestricted(body),
            )
        )
    return fixtures


def _build_common_header(fixture_file: str) -> str:
    """Generate the standard header for sign_tx test files."""
    return (
        "// Unit tests for transaction signing (auto-generated)\n"
        "// DO NOT EDIT - regenerate using generators/generate_unit_tests_from_ragger.py\n"
        "\n"
        "#include <stdarg.h>\n"
        "#include <stddef.h>\n"
        "#include <setjmp.h>\n"
        "#include <stdint.h>\n"
        "#include <stdbool.h>\n"
        "#include <string.h>\n"
        "\n"
        "#include <cmocka.h>\n"
        "\n"
        '#include "apdu/dispatcher.h"\n'
        '#include "handler/sign_tx.h"\n'
        '#include "buffer.h"\n'
        '#include "cardano_swo.h"\n'
        '#include "cardano_constants.h"\n'
        '#include "globals.h"\n'
        '#include "tx.h"\n'
        '#include "tx_parse.h"\n'
        '#include "securityPolicy/securityPolicy.h"\n'
        '#include "hexUtils.h"\n'
        '#include "utils/utils.h"\n'
        '#include "blake2b.h"\n'
        '#include "init_apdu.h"\n'
        '#include "io_capture.h"\n'
        '#include "apdu_finalization_check.h"\n'
        "\n"
        f'#include "{fixture_file}"\n'
        "\n"
        '#include "test_sign_tx_common.h"\n'
        '#include "app_mem_utils.h"\n'
        "\n"
        "// ======================================================================\n"
        "// UI code: using REAL ui_display_*.c with mocked NBGL\n"
        "// ======================================================================\n"
        "// The real UI code from ../src/ui/ui_display_tx.c and ui_display_witness.c\n"
        "// is included in cardano_sign_tx_core library. It calls NBGL functions which\n"
        "// are mocked in mock_sources/nbgl_mock.c to auto-approve for testing.\n"
        "// This way we test the actual UI formatting, tag-value pair generation,\n"
        "// and state management logic.\n"
    )


def _generate_complete_test_file(
    era: str, fixture_file: str, test_c_file: str, era_upper: str
) -> int:
    fixture_path = GENERATED_SIGN_TX_DIR / fixture_file
    test_path = GENERATED_SIGN_TX_DIR / test_c_file

    if not fixture_path.exists():
        raise FileNotFoundError(f"Missing fixture header: {fixture_path}")

    era_heading = ERA_COMMENT_OVERRIDES.get(era, f"{era_upper} Era Tests")

    fixtures = _extract_fixtures_from_header(fixture_path)
    if not fixtures:
        raise ValueError(f"No fixtures found in {fixture_file}")

    test_functions, test_names = _build_test_functions(fixtures)
    expected_test_count = 0
    for (
        _,
        _,
        has_cvote_aux_data,
        has_blind_signing_hash_only_path,
        _is_unrestricted,
    ) in fixtures:
        expected_test_count += 3 if _is_unrestricted else 4
        if has_cvote_aux_data:
            expected_test_count += 2
        if has_blind_signing_hash_only_path:
            expected_test_count += 2
    if len(test_names) != expected_test_count:
        raise ValueError(
            f"Test count mismatch for {test_c_file}: expected {expected_test_count}, got {len(test_names)}"
        )

    common_header = _build_common_header(fixture_file)
    tests_block = "\n\n".join(test_functions)
    main_block = _build_main_function(test_names, test_c_file)

    era_comment_block = (
        "// ======================================================================\n"
        f"// {era_heading}\n"
        "// ======================================================================\n\n"
    )

    complete_file = (
        common_header.rstrip()
        + "\n\n"
        + era_comment_block
        + tests_block
        + "\n\n"
        + main_block
    )

    write_generated_c_file(test_path, complete_file)
    print(f"Generated {test_c_file}: {len(test_names)} tests")
    return len(test_names)


def generate_tx_test_runners() -> int:

    total_tests = 0
    for era, (fixture_file, test_c_file, era_upper) in ERA_TEST_FILE_MAP.items():
        total_tests += _generate_complete_test_file(
            era, fixture_file, test_c_file, era_upper
        )

    print("\nAll test files generated successfully!")
    return total_tests
