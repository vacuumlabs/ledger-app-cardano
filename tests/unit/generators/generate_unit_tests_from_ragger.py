#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
Unified generator for unit-test fixtures derived from ragger sources.
"""

from __future__ import annotations

import argparse
import io
import re
import subprocess
import sys
from collections import defaultdict
from collections.abc import Callable
from contextlib import redirect_stdout
from dataclasses import dataclass
from pathlib import Path

from tests.unit.generators.deny_fixture_generators.cvote_deny_generators import (
    generate_cvote_deny_fixtures,
)
from tests.unit.generators.deny_fixture_generators.derive_address_deny_generators import (
    generate_address_derivation_deny_fixtures,
)
from tests.unit.generators.deny_fixture_generators.derive_native_script_deny_generators import (
    generate_derive_native_script_deny_fixtures,
)
from tests.unit.generators.deny_fixture_generators.opcert_deny_generators import (
    generate_opcert_deny_fixtures,
)
from tests.unit.generators.deny_fixture_generators.pubkey_deny_generators import (
    generate_pubkey_deny_fixtures,
)
from tests.unit.generators.deny_fixture_generators.sign_msg_deny_generators import (
    generate_sign_msg_deny_test_runners,
)

# Import deny generators
from tests.unit.generators.deny_fixture_generators.sign_tx_deny_generators import (
    generate_tx_deny_fixtures,
)
from tests.unit.generators.fixture_generators.cvote_generators import (
    _load_cvote_test_cases,
    generate_cvote_fixtures,
)
from tests.unit.generators.fixture_generators.derive_address_generators import (
    _load_address_derivation_test_cases,
    generate_address_derivation_fixtures,
)
from tests.unit.generators.fixture_generators.derive_native_script_generators import (
    _load_native_script_test_cases,
    generate_derive_native_script_fixtures,
)
from tests.unit.generators.fixture_generators.opcert_generators import (
    _load_opcert_test_cases,
    generate_opcert_fixtures,
)
from tests.unit.generators.fixture_generators.pubkey_generators import (
    _load_public_key_test_cases,
    generate_pubkey_fixtures,
)
from tests.unit.generators.fixture_generators.sign_msg_generators import (
    _load_sign_msg_test_cases,
    generate_sign_msg_fixtures,
)

# Import fixture generators
from tests.unit.generators.fixture_generators.sign_tx_generators import (
    _load_sign_tx_tests,
    generate_tx_fixtures,
)
from tests.unit.generators.mock_data_utils import regenerate_mock_data_with_options
from tests.unit.generators.paths import (
    GENERATED_CVOTE_DIR,
    GENERATED_DERIVE_ADDRESS_DIR,
    GENERATED_NATIVE_SCRIPT_DIR,
    GENERATED_OPCERT_DIR,
    GENERATED_PUBKEY_DIR,
    GENERATED_SIGN_MSG_DIR,
    GENERATED_SIGN_TX_DIR,
    REPO_ROOT,
    UNIT_TESTS_DIR,
)
from tests.unit.generators.test_runner_generators.cvote_deny_runner_generators import (
    generate_cvote_deny_test_runners,
)
from tests.unit.generators.test_runner_generators.cvote_test_runner_generators import (
    generate_cvote_test_runners,
)
from tests.unit.generators.test_runner_generators.derive_address_deny_runner_generators import (
    generate_address_derivation_deny_test_runners,
)
from tests.unit.generators.test_runner_generators.derive_address_test_runner_generators import (
    generate_address_derivation_test_runners,
)
from tests.unit.generators.test_runner_generators.derive_native_script_runner_generators import (
    generate_native_script_test_runners,
)
from tests.unit.generators.test_runner_generators.native_script_deny_runner_generators import (
    generate_native_script_deny_test_runners,
)
from tests.unit.generators.test_runner_generators.opcert_deny_runner_generators import (
    generate_opcert_deny_test_runners,
)
from tests.unit.generators.test_runner_generators.opcert_test_runner_generators import (
    generate_opcert_test_runners,
)
from tests.unit.generators.test_runner_generators.pubkey_deny_runner_generators import (
    generate_pubkey_deny_test_runners,
)
from tests.unit.generators.test_runner_generators.pubkey_test_runner_generators import (
    generate_pubkey_test_runners,
)
from tests.unit.generators.test_runner_generators.sign_msg_test_runner_generators import (
    generate_sign_msg_test_runners,
)

# Import test runners
from tests.unit.generators.test_runner_generators.sign_tx_test_runner_generators import (
    fixture_has_blind_signing_hash_only_path,
    fixture_has_cvote_aux_data,
    fixture_is_unrestricted,
    generate_tx_test_runners,
)

_REPORT_WIDTH = 88

# Match deny fixtures array for counting individual deny cases
_SIGN_TX_DENY_FIXTURES_PATTERN = re.compile(
    r"static const sign_tx_deny_fixture_t SIGN_TX_DENY_FIXTURES\[\]\s*=\s*\{(.*?)\n\};",
    flags=re.DOTALL,
)

# Match individual deny fixture entries inside the array
_SIGN_TX_DENY_ENTRY_PATTERN = re.compile(r"\.name\s*=")
_TX_FIXTURE_PATTERN = re.compile(
    r"static\s+const\s+tx_fixture_t\s+(FIXTURE_[A-Z0-9_]+)\s*=\s*\{(.*?)\};",
    flags=re.DOTALL,
)


def _log_stage(message: str, *, verbose: bool) -> None:
    if verbose:
        print(f"\n--- {message} ---")


def _count_sign_tx_deny_fixtures() -> int:
    """Return the number of fixtures in sign_tx deny suite to account for per-test coverage."""
    fixtures_file = GENERATED_SIGN_TX_DIR / "test_sign_tx_fixtures_deny.h"
    if not fixtures_file.exists():
        return 0

    try:
        content = fixtures_file.read_text(encoding="utf-8")
    except OSError:
        return 0

    match = _SIGN_TX_DENY_FIXTURES_PATTERN.search(content)
    if not match:
        return 0

    fixture_body = match.group(1)
    return len(_SIGN_TX_DENY_ENTRY_PATTERN.findall(fixture_body))


def _count_sign_tx_fine_grained_entries_from_fixtures() -> int:
    """
    Count fine-grained sign-tx entries from fixture headers on disk.

    This mirrors tx runner generation granularity:
    - 4 entries per tx fixture (approve/reject-tx x expert-off/on)
    - +2 entries when fixture has CIP36 aux data (reject-aux x expert-off/on)
    - +2 entries when fixture has a blind-signing hash-only path (x expert-off/on)
    - plus deny fixtures from SIGN_TX_DENY_FIXTURES
    """
    total_entries = 0
    fixture_headers = sorted(
        p for p in GENERATED_SIGN_TX_DIR.glob("test_sign_tx_fixtures_*.h") if p.name != "test_sign_tx_fixtures_deny.h"
    )

    for fixture_header_path in fixture_headers:
        try:
            header_content = fixture_header_path.read_text(encoding="utf-8")
        except OSError:
            continue

        for fixture_match in _TX_FIXTURE_PATTERN.finditer(header_content):
            fixture_body = fixture_match.group(2)
            total_entries += 3 if fixture_is_unrestricted(fixture_body) else 4
            if fixture_has_cvote_aux_data(fixture_body):
                total_entries += 2
            if fixture_has_blind_signing_hash_only_path(fixture_body):
                total_entries += 2

    total_entries += _count_sign_tx_deny_fixtures()
    return total_entries


@dataclass(frozen=True)
class CommandMetadata:
    id: str
    display_name: str
    ragger_file_name: str
    generated_dir: Path
    fixture_generators: list[Callable]
    runner_generators: list[Callable]
    deny_generators: list[Callable]


COMMAND_REGISTRY = [
    CommandMetadata(
        id="sign_tx",
        display_name="Sign Transaction",
        ragger_file_name="test_sign_tx.py",
        generated_dir=GENERATED_SIGN_TX_DIR,
        fixture_generators=[generate_tx_fixtures],
        runner_generators=[generate_tx_test_runners],
        deny_generators=[generate_tx_deny_fixtures],
    ),
    CommandMetadata(
        id="sign_msg",
        display_name="Sign Message",
        ragger_file_name="test_signMsg.py",
        generated_dir=GENERATED_SIGN_MSG_DIR,
        fixture_generators=[generate_sign_msg_fixtures],
        runner_generators=[generate_sign_msg_test_runners],
        deny_generators=[generate_sign_msg_deny_test_runners],
    ),
    CommandMetadata(
        id="sign_cvote",
        display_name="Sign CVote",
        ragger_file_name="test_cvote.py",
        generated_dir=GENERATED_CVOTE_DIR,
        fixture_generators=[generate_cvote_fixtures],
        runner_generators=[
            generate_cvote_test_runners,
            generate_cvote_deny_test_runners,
        ],
        deny_generators=[generate_cvote_deny_fixtures],
    ),
    CommandMetadata(
        id="sign_opcert",
        display_name="Sign Opcert",
        ragger_file_name="test_opcert.py",
        generated_dir=GENERATED_OPCERT_DIR,
        fixture_generators=[generate_opcert_fixtures],
        runner_generators=[
            generate_opcert_test_runners,
            generate_opcert_deny_test_runners,
        ],
        deny_generators=[generate_opcert_deny_fixtures],
    ),
    CommandMetadata(
        id="pubkey_export",
        display_name="Pubkey Export",
        ragger_file_name="test_pubkey.py",
        generated_dir=GENERATED_PUBKEY_DIR,
        fixture_generators=[generate_pubkey_fixtures],
        runner_generators=[
            generate_pubkey_test_runners,
            generate_pubkey_deny_test_runners,
        ],
        deny_generators=[generate_pubkey_deny_fixtures],
    ),
    CommandMetadata(
        id="derive_address",
        display_name="Derive Address",
        ragger_file_name="test_derive_address.py",
        generated_dir=GENERATED_DERIVE_ADDRESS_DIR,
        fixture_generators=[generate_address_derivation_fixtures],
        runner_generators=[
            generate_address_derivation_test_runners,
            generate_address_derivation_deny_test_runners,
        ],
        deny_generators=[generate_address_derivation_deny_fixtures],
    ),
    CommandMetadata(
        id="derive_native_script",
        display_name="Derive Native Script",
        ragger_file_name="test_derive_native_script.py",
        generated_dir=GENERATED_NATIVE_SCRIPT_DIR,
        fixture_generators=[generate_derive_native_script_fixtures],
        runner_generators=[
            generate_native_script_test_runners,
            generate_native_script_deny_test_runners,
        ],
        deny_generators=[generate_derive_native_script_deny_fixtures],
    ),
]


_CMOCKA_TEST_PATTERN = re.compile(r"cmocka_unit_test\(\s*([^)]+?)\s*\)")

_GENERATED_BY_SCRIPT = "tests/unit/generators/generate_unit_tests_from_ragger.py"


def _candidate_function_names_for_coverage_match(function_name: str) -> set[str]:
    """
    Return function-name variants used when matching generated unit tests.

    Ragger test function names (from pytest) often match cmocka unit test names directly,
    but there are some exceptions:
    - Trailing `_hash` is dropped in unit tests.
    - `test_sign_tx_` prefix is often shortened to `test_`.
    """
    candidate_names = {function_name}
    if function_name.endswith("_hash"):
        candidate_names.add(function_name[:-5])
    if function_name.startswith("test_sign_tx_"):
        candidate_names.add("test_" + function_name[len("test_sign_tx_") :])
    return candidate_names


def _extract_cmocka_test_names(file_path: Path) -> tuple[list[str], str]:
    """Return cmocka-registered test names plus the raw file content for coverage checks."""
    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError:
        print(f"WARNING: Could not read {file_path} for counting cmocka tests")
        return [], ""
    names = [match.group(1).strip() for match in _CMOCKA_TEST_PATTERN.finditer(content)]
    return names, content


def _count_unit_tests_by_command() -> tuple[dict[str, int], int, set[str], str]:
    """
    Count unit-test entries per command and return the data along with total generated functions.

    The count is based on cmocka_unit_test() registrations so the reporting stays
    independent of the generator output formatting.
    IMPORTANT: this reads test sources from disk and does not depend on in-memory
    generation-phase counters/state from earlier steps in this script.

    Returns:
        (command_counts, total_funcs, registered_names, combined_content)
        registered_names: set of all function names registered via cmocka_unit_test()
        combined_content: concatenated raw source text (used only for A-vs-B sanity check)
    """
    command_counts: dict[str, int] = {cmd.id: 0 for cmd in COMMAND_REGISTRY}
    total_funcs = 0
    registered_names: set[str] = set()
    command_file_contents: list[str] = []

    def _add_file_content_only(path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(f"Unit test source missing: {path}")
        try:
            command_file_contents.append(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise OSError(f"Failed reading {path}") from exc

    def _add_file_counts(path: Path, command: str) -> None:
        nonlocal total_funcs
        if not path.exists():
            raise FileNotFoundError(f"Unit test source missing: {path}")
        names, content = _extract_cmocka_test_names(path)
        command_counts[command] += len(names)
        total_funcs += len(names)
        registered_names.update(names)
        command_file_contents.append(content)

    # Keep sign-tx deny runner out of cmocka-based counting (counted via fixtures),
    # but include its source for function-name coverage matching.
    _add_file_content_only(GENERATED_SIGN_TX_DIR / "test_sign_tx_deny_tests.c")

    command_dir_map = {cmd.id: cmd.generated_dir for cmd in COMMAND_REGISTRY}

    for command, directory in command_dir_map.items():
        if directory.exists():
            for file_path in sorted(directory.glob("test_*.c")):
                _add_file_counts(file_path, command)

    combined_content = "\n".join(command_file_contents)
    return command_counts, total_funcs, registered_names, combined_content


def _is_covered_by_registered_names(candidate_names: set[str], registered_names: set[str]) -> bool:
    """Option B: check coverage against the authoritative set of cmocka-registered names."""
    return any(
        any(
            registered_name == candidate_name or registered_name.startswith(f"{candidate_name}_")
            for registered_name in registered_names
        )
        for candidate_name in candidate_names
    )


def _is_covered_by_substring(candidate_names: set[str], unit_tests_content: str) -> bool:
    """Option A: word-boundary regex check against raw source text."""
    return any(bool(re.search(rf"\b{re.escape(candidate_name)}\b", unit_tests_content)) for candidate_name in candidate_names)


def _verify_ragger_test_coverage(generated_entries_count_by_command: dict[str, int], *, verbose: bool) -> None:
    """Verify that all ragger tests have corresponding unit test coverage."""
    # Collect ragger test names using pytest --collect-only
    ragger_tests_dir = REPO_ROOT / "tests" / "standalone"
    if not ragger_tests_dir.exists():
        print("WARNING: Ragger tests directory not found, skipping coverage check")
        return

    venv_pytest = REPO_ROOT / "tests" / "venv" / "bin" / "pytest"
    pytest_cmd = str(venv_pytest) if venv_pytest.exists() else "pytest"

    try:
        # Try to collect with a device parameter (ragger tests require --device)
        result = subprocess.run(
            [
                pytest_cmd,
                "--collect-only",
                "-q",
                "--device",
                "stax",
                str(ragger_tests_dir),
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        # Check for collection errors (non-zero return code indicates failure)
        if result.returncode != 0:
            if result.returncode == 5:
                print("WARNING: pytest returned 5 (no tests collected). Continuing anyway.")
            else:
                print(f"ERROR: pytest collection failed with return code {result.returncode}")
                if result.stderr:
                    print("STDERR output:")
                    print(result.stderr)
                if result.stdout:
                    print("STDOUT output:")
                    print(result.stdout)
                sys.exit(1)
        # Parse test names from pytest output (format: test_file.py::test_name[...])
        ragger_tests = [line.strip() for line in result.stdout.split("\n") if "::" in line and "test_" in line]
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: Could not collect ragger tests: {exc}")
        sys.exit(1)

    if not ragger_tests:
        print("ERROR: No ragger tests found - check that test files are present and importable")
        sys.exit(1)

    # Count total test cases (including parameterized variants)
    total_ragger_test_cases = len(ragger_tests)

    if not UNIT_TESTS_DIR.exists():
        print(f"ERROR: Unit test directory not found at {UNIT_TESTS_DIR}")
        sys.exit(1)

    ragger_command_counts = {cmd.id: 0 for cmd in COMMAND_REGISTRY}
    comparable_ragger_command_counts = {cmd.id: 0 for cmd in COMMAND_REGISTRY}
    skip_counts: dict[str, int] = defaultdict(int)
    unmapped_counts: dict[str, int] = defaultdict(int)

    skip_test_files = {
        "test_client_constants.py",
        "test_app_mainmenu.py",
        "test_error_cmd.py",
        "test_get_app_info.py",
    }
    skip_test_funcs = {
        "test_wrong_data_length",
        # test_sign_tx_deny coverage is tracked via _count_sign_tx_deny_fixtures() /
        # SIGN_TX_DENY_FIXTURES; the unit-test runner (test_sign_tx_deny_fixture) is
        # a fixture-driven loop, not a per-case cmocka registration, so it will never
        # appear in registered_unit_test_names under its ragger name.
        "test_sign_tx_deny",
    }
    ragger_test_funcs = set()

    for test_line in ragger_tests:
        if "::" not in test_line:
            continue
        module_part, func_part = test_line.split("::", 1)
        module_name = Path(module_part).name
        if module_name in skip_test_files:
            skip_counts[module_name] += 1
            continue
        command = next(
            (cmd.id for cmd in COMMAND_REGISTRY if cmd.ragger_file_name == module_name),
            None,
        )
        if command:
            ragger_command_counts[command] += 1
            comparable_ragger_command_counts[command] += 1
        else:
            unmapped_counts[module_name] += 1
        func_name = func_part.split("[", 1)[0]
        if func_name and func_name not in skip_test_funcs:
            ragger_test_funcs.add(func_name)

    # Coverage/counting is intentionally filesystem-based and independent from
    # generation-phase bookkeeping; it scans current unit-test files on disk.
    (
        unit_command_counts,
        total_unit_test_funcs,
        registered_unit_test_names,
        unit_tests_content,
    ) = _count_unit_tests_by_command()
    deny_fixture_count = _count_sign_tx_deny_fixtures()
    if deny_fixture_count == 0:
        print(
            "ERROR: SIGN_TX_DENY_FIXTURES is empty or missing — "
            "test_sign_tx_deny is skipped from function-level coverage but requires "
            "at least one fixture entry to be meaningful"
        )
        sys.exit(1)
    unit_command_counts["sign_tx"] += deny_fixture_count
    expanded_unit_test_count = total_unit_test_funcs + deny_fixture_count
    # For sign_tx, compare against fine-grained expected entries (same granularity
    # as generated unit tests), not raw pytest parameterized-case count.
    comparable_ragger_command_counts["sign_tx"] = _count_sign_tx_fine_grained_entries_from_fixtures()

    # Extract unique test function names from ragger tests
    # Format: test_file.py::test_func_name[param] -> extract test_func_name
    missing_coverage = []
    covered_coverage = []
    for func_name in sorted(ragger_test_funcs):
        # Some ragger tests expand into indexed unit tests. Match both the exact
        # function name and generated prefixes.
        candidate_function_names = _candidate_function_names_for_coverage_match(func_name)
        # We intentionally use two mechanisms (Option A and Option B) for coverage validation.
        # This redundancy is for validation purposes, and any mismatch between them will be manually investigated.
        # Primary check (B): coverage is determined by cmocka_unit_test() registrations only.
        found_by_registered = _is_covered_by_registered_names(candidate_function_names, registered_unit_test_names)
        # Sanity check (A): word-boundary regex over raw source text.
        found_by_substring = _is_covered_by_substring(candidate_function_names, unit_tests_content)
        if found_by_substring and not found_by_registered:
            if verbose:
                print(
                    f"WARNING: coverage inconsistency for '{func_name}': "
                    f"found as word-boundary match in source text but NOT in cmocka registrations — "
                    f"function may be defined but not registered as a test"
                )
        if found_by_registered:
            covered_coverage.append(func_name)
        else:
            missing_coverage.append(func_name)

    deny_note = ""
    if deny_fixture_count:
        deny_note = f", includes {deny_fixture_count} fixtures sampled through `SIGN_TX_DENY_FIXTURES`"
    insufficient_commands = []
    mismatched_counts = []
    for cmd in COMMAND_REGISTRY:
        command = cmd.id
        ragger_count = comparable_ragger_command_counts.get(command, 0)
        unit_count = unit_command_counts.get(command, 0)

        in_memory_count = generated_entries_count_by_command.get(command, 0)
        if in_memory_count > 0 or ragger_count > 0:
            if in_memory_count != unit_count:
                mismatched_counts.append(
                    f"{cmd.display_name}: Generated {in_memory_count} entries in memory, "
                    f"but parsed {unit_count} cmocka tests from files."
                )
        if unit_count < ragger_count:
            insufficient_commands.append(f"{cmd.display_name} (Ragger {ragger_count}, Unit {unit_count})")

    if verbose or mismatched_counts or insufficient_commands or missing_coverage:
        print("\nRagger test coverage check:")
        print(f"  Ragger: {total_ragger_test_cases} total test cases from {len(ragger_tests)} parameterized variants")
        print(
            f"  Unit tests: {expanded_unit_test_count} total test entries "
            f"({total_unit_test_funcs} generated functions{deny_note})"
        )
        print("  Command breakdown:")
        for cmd in COMMAND_REGISTRY:
            command = cmd.id
            ragger_count = comparable_ragger_command_counts.get(command, 0)
            unit_count = unit_command_counts.get(command, 0)
            delta = unit_count - ragger_count
            delta_note = f" (Δ {delta:+d})" if delta else ""
            print(f"    - {cmd.display_name}: {ragger_count} Ragger -> {unit_count} unit entries{delta_note}")
        if comparable_ragger_command_counts["sign_tx"] != ragger_command_counts["sign_tx"]:
            print(
                "  Note: Sign Transaction uses fine-grained fixture-based counting for comparison "
                f"(raw pytest cases: {ragger_command_counts['sign_tx']})."
            )
        if skip_counts:
            skip_total = sum(skip_counts.values())
            skip_details = ", ".join(f"{name}({count})" for name, count in sorted(skip_counts.items()))
            print(f"  Ignored {skip_total} pytest cases from auxiliary modules ({skip_details})")
        if unmapped_counts:
            unmapped_total = sum(unmapped_counts.values())
            unmapped_details = ", ".join(f"{name}({count})" for name, count in sorted(unmapped_counts.items()))
            print(
                f"  Unmapped pytest modules ({unmapped_total} cases): {unmapped_details}"
                f" — their test functions are still checked for unit-test coverage above"
            )

    if mismatched_counts:
        print("\n" + "!" * _REPORT_WIDTH)
        print("!!! " + "WARNING: Mismatch between in-memory generation and file parsing".center(_REPORT_WIDTH - 8) + " !!!")
        print("!!! " + "(Intentional validation redundancy)".center(_REPORT_WIDTH - 8) + " !!!")
        print("!" * _REPORT_WIDTH)
        for mismatch in mismatched_counts:
            print(f"  - {mismatch}")
        print("!" * _REPORT_WIDTH + "\n")

    if insufficient_commands and (verbose or not missing_coverage):
        print(f"  ERROR: insufficient per-command coverage detected: {', '.join(insufficient_commands)}")
    if verbose or missing_coverage or mismatched_counts or insufficient_commands:
        print(f"  Found {len(ragger_test_funcs)} unique ragger test functions to cover")
        print(f"  Coverage: {len(covered_coverage)} functions covered, {len(missing_coverage)} missing")

    if missing_coverage:
        print("\n" + "=" * _REPORT_WIDTH)
        print((f"WARNING: {len(missing_coverage)} test function(s) lack unit test coverage").center(_REPORT_WIDTH))
        print("=" * _REPORT_WIDTH)
        for test in missing_coverage:
            print(f"    - {test}")

        # Show which test cases are missing for each uncovered function
        print("\n  Missing test cases by function:")
        for func_name in missing_coverage:
            # Find all ragger test cases for this function
            missing_test_cases = [line.strip() for line in ragger_tests if f"::{func_name}[" in line]
            if missing_test_cases:
                print(f"    {func_name}: ({len(missing_test_cases)} cases)")
                for case in missing_test_cases:
                    # Extract just the test case name part for readability
                    if "::" in case:
                        _, test_case = case.split("::", 1)
                        print(f"      - {test_case}")
        print("\n" + "=" * _REPORT_WIDTH)
        print("COVERAGE FAILURE: missing unit-test coverage for one or more ragger test functions.")
        print("The generator run is unsuccessful until all missing functions above are covered.")
        print("=" * _REPORT_WIDTH)
        sys.exit(1)

    if mismatched_counts:
        print("\n" + "=" * _REPORT_WIDTH)
        print("MOCK DATA / COUNTING FAILURE: In-memory counts do not match file parsing.")
        print("The generator run is unsuccessful until all mismatches are resolved.")
        print("=" * _REPORT_WIDTH)
        sys.exit(1)

    if insufficient_commands:
        print("\n" + "=" * _REPORT_WIDTH)
        print("COVERAGE FAILURE: insufficient per-command coverage detected.")
        print("=" * _REPORT_WIDTH)
        sys.exit(1)

    print(
        "Coverage OK: "
        f"{len(covered_coverage)}/{len(ragger_test_funcs)} functions covered, "
        f"{expanded_unit_test_count} unit entries validated"
    )


def _run_generator_step(message: str, func: Callable[[], object], *, verbose: bool) -> object:
    _log_stage(message, verbose=verbose)
    if verbose:
        return func()

    # Quiet mode suppresses generator chatter and only forwards key summary lines
    # or the full captured output when the step fails.
    captured_stdout = io.StringIO()
    try:
        with redirect_stdout(captured_stdout):
            result = func()
    except SystemExit:
        output = captured_stdout.getvalue().strip()
        if output:
            print(output)
        raise
    except Exception:
        output = captured_stdout.getvalue().strip()
        if output:
            print(output)
        raise
    output = captured_stdout.getvalue().strip()
    if output:
        for line in output.splitlines():
            if line.startswith(("Mock data OK:", "Coverage OK:")):
                print(line)
    return result


def _collect_missing_unit_expected_results() -> list[str]:
    missing_reports: list[str] = []

    def _extract_name_from_source_line(line: str) -> str | None:
        source_prefix = "// Source:"
        if not line.startswith(source_prefix):
            return None
        _, separator, name = line.rpartition(" > ")
        if separator == "":
            return None
        return name.strip()

    sign_msg_header_path = GENERATED_SIGN_MSG_DIR / "test_sign_msg_fixtures.h"
    if sign_msg_header_path.exists():
        current_name: str | None = None
        for line in sign_msg_header_path.read_text(encoding="utf-8").splitlines():
            source_name = _extract_name_from_source_line(line)
            if source_name is not None:
                current_name = source_name
                continue
            if ".expected = NULL," in line:
                missing_reports.append(f"Sign Message: {current_name or '<unknown fixture>'}")

    derive_address_header_path = GENERATED_DERIVE_ADDRESS_DIR / "test_derive_address_fixtures.h"
    if derive_address_header_path.exists():
        current_name: str | None = None
        fixture_expects_success_response = False
        for line in derive_address_header_path.read_text(encoding="utf-8").splitlines():
            source_name = _extract_name_from_source_line(line)
            if source_name is not None:
                current_name = source_name
                fixture_expects_success_response = False
                continue
            if ".check_expected = SWO_SUCCESS," in line:
                fixture_expects_success_response = True
                continue
            if fixture_expects_success_response and ".expected_address = NULL," in line:
                missing_reports.append(f"Derive Address: {current_name or '<unknown fixture>'}")
                fixture_expects_success_response = False

    opcert_header_path = GENERATED_OPCERT_DIR / "test_opcert_fixtures.h"
    if opcert_header_path.exists():
        current_name: str | None = None
        for line in opcert_header_path.read_text(encoding="utf-8").splitlines():
            if '.name = "' in line:
                current_name = line.split('"')[1]
                continue
            if ".expected_signature = NULL," in line:
                missing_reports.append(f"Sign Opcert: {current_name or '<unknown fixture>'}")

    cvote_header_path = GENERATED_CVOTE_DIR / "test_cvote_fixtures.h"
    if cvote_header_path.exists():
        current_name: str | None = None
        missing_votecast_hash = False
        missing_witness_signature = False
        for line in cvote_header_path.read_text(encoding="utf-8").splitlines():
            if line.strip() == "{":
                current_name = None
                missing_votecast_hash = False
                missing_witness_signature = False
                continue
            if '.name = "' in line:
                current_name = line.split('"')[1]
                continue
            if ".expected_votecast_hash = NULL," in line:
                missing_votecast_hash = True
                continue
            if ".expected_witness_signature = NULL," in line:
                missing_witness_signature = True
                continue
            if line.strip() == "}," and (missing_votecast_hash or missing_witness_signature):
                missing_reports.append(f"Sign CVote: {current_name or '<unknown fixture>'}")

    sign_tx_header_paths = sorted(
        path for path in GENERATED_SIGN_TX_DIR.glob("test_sign_tx_fixtures_*.h") if path.name != "test_sign_tx_fixtures_deny.h"
    )
    for sign_tx_header_path in sign_tx_header_paths:
        current_name: str | None = None
        missing_hash = False
        missing_witness_signature = False
        for line in sign_tx_header_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("// Test ") and ": " in line:
                if missing_hash or missing_witness_signature:
                    missing_parts: list[str] = []
                    if missing_hash:
                        missing_parts.append("expected_hash_hex")
                    if missing_witness_signature:
                        missing_parts.append("expected witness signature")
                    missing_reports.append(
                        f"Sign Transaction: {current_name or '<unknown fixture>'} missing {', '.join(missing_parts)}"
                    )
                current_name = line.split(": ", 1)[1].strip()
                missing_hash = False
                missing_witness_signature = False
                continue
            if ".expected_hash_hex = NULL," in line or '.expected_hash_hex = "",' in line:
                missing_hash = True
                continue
            if ".expected_signature = NULL" in line:
                missing_witness_signature = True
        if missing_hash or missing_witness_signature:
            missing_parts = []
            if missing_hash:
                missing_parts.append("expected_hash_hex")
            if missing_witness_signature:
                missing_parts.append("expected witness signature")
            missing_reports.append(f"Sign Transaction: {current_name or '<unknown fixture>'} missing {', '.join(missing_parts)}")

    pubkey_header_path = GENERATED_PUBKEY_DIR / "test_pubkey_fixtures.h"
    if pubkey_header_path.exists():
        current_name: str | None = None
        fixture_expects_success_response = False
        for line in pubkey_header_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("// Test ") and ": " in line:
                current_name = line.split(": ", 1)[1].strip()
                fixture_expects_success_response = False
                continue
            if ".check_expected = SWO_SUCCESS," in line:
                fixture_expects_success_response = True
                continue
            if fixture_expects_success_response and (
                ".expected_response = NULL," in line or ".expected_response_len = 0," in line
            ):
                missing_reports.append(f"Public Key: {current_name or '<unknown fixture>'}")
                fixture_expects_success_response = False

    return missing_reports


def _collect_python_fixture_cases() -> list[tuple[str, object]]:
    python_fixture_cases: list[tuple[str, object]] = []

    sign_tx_data = _load_sign_tx_tests()
    for era_name, test_cases in sign_tx_data["era_tests"].items():
        python_fixture_cases.extend((f"SignTx/{era_name}", test_case) for test_case in test_cases)

    for test_case in _load_sign_msg_test_cases():
        python_fixture_cases.append(("SignMsg", test_case))

    all_address_test_cases, _ = _load_address_derivation_test_cases()
    for category_name, test_cases in all_address_test_cases.items():
        python_fixture_cases.extend((f"DeriveAddress/{category_name}", test_case) for test_case in test_cases)

    for test_case in _load_native_script_test_cases():
        python_fixture_cases.append(("NativeScript", test_case))

    pubkey_test_groups = _load_public_key_test_cases()
    for group_name, test_group in pubkey_test_groups.items():
        python_fixture_cases.extend((f"PubKey/{group_name}", test_case) for test_case in test_group.test_cases)

    for test_case in _load_opcert_test_cases():
        python_fixture_cases.append(("OpCert", test_case))

    for test_case in _load_cvote_test_cases():
        python_fixture_cases.append(("CVote", test_case))

    return python_fixture_cases


def _collect_missing_object_fields(
    owner_name: str,
    obj: object | None,
    required_fields: tuple[str, ...],
) -> list[str]:
    if obj is None:
        return [f"{owner_name} is missing"]

    missing_fields: list[str] = []
    for field_name in required_fields:
        value = getattr(obj, field_name, None)
        if value is None or value == "":
            missing_fields.append(field_name)
    return missing_fields


def _validate_sign_tx_expectations(suite_name: str, test_case: object, missing_reports: list[str]) -> None:
    fixture_name = getattr(test_case, "name", "<unknown fixture>")
    missing_unit_fields = _collect_missing_object_fields(
        "unit_test_expect",
        getattr(test_case, "unit_test_expect", None),
        ("txBodyHex",),
    )
    if missing_unit_fields:
        missing_reports.append(f"{suite_name}: {fixture_name} is missing {', '.join(missing_unit_fields)}")

    if getattr(test_case, "unsuitable_in_ragger_reason", None) is not None:
        return

    missing_ragger_fields = _collect_missing_object_fields(
        "ragger_expect",
        getattr(test_case, "ragger_expect", None),
        ("txHashHex",),
    )
    if missing_ragger_fields:
        missing_reports.append(f"{suite_name}: {fixture_name} is missing {', '.join(missing_ragger_fields)}")
        return

    ragger_expect = getattr(test_case, "ragger_expect", None)
    witnesses = getattr(ragger_expect, "witnesses", None)
    if witnesses is None or len(witnesses) == 0:
        missing_reports.append(f"{suite_name}: {fixture_name} is missing ragger_expect.witnesses")
        return

    for witness_index, witness in enumerate(witnesses):
        witness_signature_hex = getattr(witness, "witnessSignatureHex", None)
        if witness_signature_hex is None or witness_signature_hex == "":
            missing_reports.append(f"{suite_name}: {fixture_name} witness {witness_index} is missing witnessSignatureHex")


def _validate_expected_result_fields(
    suite_name: str,
    test_case: object,
    missing_reports: list[str],
    *,
    unit_fields: tuple[str, ...],
    ragger_fields: tuple[str, ...] | None = None,
) -> None:
    fixture_name = getattr(test_case, "name", "<unknown fixture>")

    missing_unit_fields = _collect_missing_object_fields(
        "unit_test_expect",
        getattr(test_case, "unit_test_expect", None),
        unit_fields,
    )
    if missing_unit_fields:
        missing_reports.append(f"{suite_name}: {fixture_name} is missing {', '.join(missing_unit_fields)}")

    if getattr(test_case, "unsuitable_in_ragger_reason", None) is not None:
        return

    if ragger_fields is None:
        return

    missing_ragger_fields = _collect_missing_object_fields(
        "ragger_expect",
        getattr(test_case, "ragger_expect", None),
        ragger_fields,
    )
    if missing_ragger_fields:
        missing_reports.append(f"{suite_name}: {fixture_name} is missing {', '.join(missing_ragger_fields)}")


def _collect_missing_python_expected_results() -> list[str]:
    missing_reports: list[str] = []

    for suite_name, test_case in _collect_python_fixture_cases():
        if getattr(test_case, "expected_swo", None) is not None:
            continue

        if suite_name.startswith("SignTx/"):
            _validate_sign_tx_expectations(suite_name, test_case, missing_reports)
        elif suite_name == "SignMsg":
            _validate_expected_result_fields(
                suite_name,
                test_case,
                missing_reports,
                unit_fields=(
                    "signatureHex",
                    "signingPublicKeyHex",
                    "addressFieldHex",
                ),
                ragger_fields=(
                    "signatureHex",
                    "signingPublicKeyHex",
                    "addressFieldHex",
                ),
            )
        elif suite_name.startswith("DeriveAddress/"):
            _validate_expected_result_fields(
                suite_name,
                test_case,
                missing_reports,
                unit_fields=("addressHex",),
                ragger_fields=("addressHex",),
            )
        elif suite_name == "NativeScript":
            _validate_expected_result_fields(
                suite_name,
                test_case,
                missing_reports,
                unit_fields=("hash",),
                ragger_fields=("hash",),
            )
        elif suite_name.startswith("PubKey/"):
            _validate_expected_result_fields(
                suite_name,
                test_case,
                missing_reports,
                unit_fields=("publicKeyHex", "chainCodeHex"),
                ragger_fields=("publicKeyHex", "chainCodeHex"),
            )
        elif suite_name == "OpCert":
            _validate_expected_result_fields(
                suite_name,
                test_case,
                missing_reports,
                unit_fields=("signatureHex",),
                ragger_fields=("signatureHex",),
            )
        elif suite_name == "CVote":
            _validate_expected_result_fields(
                suite_name,
                test_case,
                missing_reports,
                unit_fields=("votecastHashHex", "witnessSignatureHex"),
                ragger_fields=("votecastHashHex", "witnessSignatureHex"),
            )

    return missing_reports


def run_all(*, verbose: bool) -> None:
    generated_entries_count_by_command = {cmd.id: 0 for cmd in COMMAND_REGISTRY}

    # Regenerate mock data first so that updated MOCK_TX_HASH_* constants in
    # crypto_mock_data.h produce correct signatures before the fixture headers
    # are written.  A second pass at the end picks up any hash constants that
    # were introduced by this very run.
    _run_generator_step(
        "Regenerating mock data (pre-pass)",
        lambda: regenerate_mock_data_with_options(
            verbose=verbose,
            report_summary=False,
        ),
        verbose=verbose,
    )

    _log_stage("Validating Python fixture expectations", verbose=verbose)
    python_expected_result_reports = _collect_missing_python_expected_results()
    if python_expected_result_reports:
        print("\n" + "=" * _REPORT_WIDTH)
        print("EXPECTED-RESULT FAILURE: missing expectations in Python fixtures.")
        print("=" * _REPORT_WIDTH)
        for report in python_expected_result_reports:
            print(f"  - {report}")
        print("=" * _REPORT_WIDTH)
        sys.exit(1)

    _log_stage("Generating fixtures", verbose=verbose)
    for cmd in COMMAND_REGISTRY:
        for gen in cmd.fixture_generators:
            count = _run_generator_step(
                f"Generating fixtures: {cmd.display_name}/{gen.__name__}",
                gen,
                verbose=verbose,
            )
            if count is not None:
                # We do not add fixture counts to generated_entries_count because
                # the test_runner_generators (or deny_generators) will tally the actual test count.
                pass

    _log_stage("Generating deny fixtures", verbose=verbose)
    for cmd in COMMAND_REGISTRY:
        deny_count_for_cmd = 0
        any_counted = False
        for gen in cmd.deny_generators:
            count = _run_generator_step(
                f"Generating deny fixtures: {cmd.display_name}/{gen.__name__}",
                gen,
                verbose=verbose,
            )
            if count is not None:
                has_deny_runner = any("deny" in r.__name__ for r in cmd.runner_generators)
                if not has_deny_runner:
                    generated_entries_count_by_command[cmd.id] += count
                deny_count_for_cmd += count
                any_counted = True
        if any_counted and deny_count_for_cmd == 0:
            print(
                f"ERROR: deny generators for '{cmd.display_name}' produced 0 test entries — "
                f"deny test cases may be missing or the generator failed silently"
            )
            sys.exit(1)

    _log_stage("Generating test runners", verbose=verbose)
    for cmd in COMMAND_REGISTRY:
        for gen in cmd.runner_generators:
            count = _run_generator_step(
                f"Generating test runners: {cmd.display_name}/{gen.__name__}",
                gen,
                verbose=verbose,
            )
            if count is not None:
                generated_entries_count_by_command[cmd.id] += count

    _run_generator_step(
        "Regenerating mock data (post-pass)",
        lambda: regenerate_mock_data_with_options(
            verbose=verbose,
            report_summary=True,
        ),
        verbose=verbose,
    )
    _log_stage("Verifying Ragger coverage", verbose=verbose)
    _verify_ragger_test_coverage(
        generated_entries_count_by_command,
        verbose=verbose,
    )
    missing_expected_reports = _collect_missing_unit_expected_results()
    if missing_expected_reports:
        print("\n" + "=" * _REPORT_WIDTH)
        print("EXPECTED-RESULT FAILURE: missing unit expected results in generated fixtures.")
        print("=" * _REPORT_WIDTH)
        for report in missing_expected_reports:
            print(f"  - {report}")
        print("=" * _REPORT_WIDTH)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate unit-test fixtures from ragger sources.")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed generation output. Default is quiet.",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("all", help="Run all generators (default).")
    subparsers.add_parser("fixtures", help="Generate sign-tx fixture headers.")
    subparsers.add_parser("generate-test-runners", help="Regenerate test_sign_tx_*.c files.")
    subparsers.add_parser("deny_tests", help="Generate deny fixture headers.")
    subparsers.add_parser("mock-data", help="Regenerate mocks/crypto_mock_data.h.")

    args = parser.parse_args()

    if args.verbose:
        print(f"Unit tests directory: {UNIT_TESTS_DIR}")

    if args.command in (None, "all"):
        run_all(verbose=args.verbose)
    elif args.command == "fixtures":
        _log_stage("Generating fixtures", verbose=args.verbose)
        for cmd in COMMAND_REGISTRY:
            for gen in cmd.fixture_generators:
                _ = _run_generator_step(
                    f"Generating fixtures: {cmd.display_name}/{gen.__name__}",
                    gen,
                    verbose=args.verbose,
                )
    elif args.command == "generate-test-runners":
        _log_stage("Generating test runners", verbose=args.verbose)
        for cmd in COMMAND_REGISTRY:
            for gen in cmd.runner_generators:
                _ = _run_generator_step(
                    f"Generating test runners: {cmd.display_name}/{gen.__name__}",
                    gen,
                    verbose=args.verbose,
                )
    elif args.command == "deny_tests":
        _log_stage("Generating deny fixtures", verbose=args.verbose)
        for cmd in COMMAND_REGISTRY:
            for gen in cmd.deny_generators:
                _ = _run_generator_step(
                    f"Generating deny fixtures: {cmd.display_name}/{gen.__name__}",
                    gen,
                    verbose=args.verbose,
                )
    elif args.command == "mock-data":
        _run_generator_step(
            "Regenerating mock data",
            lambda: regenerate_mock_data_with_options(
                verbose=args.verbose,
                report_summary=True,
            ),
            verbose=args.verbose,
        )
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
