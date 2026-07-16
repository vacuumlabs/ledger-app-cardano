#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from tests.unit.generators.common import (
    extract_brace_delimited_entries,
    extract_static_uint8_array_bodies,
)
from tests.unit.generators.mock_data_utils import (
    _ENTRY_START_PATTERN,
    _GENERATED_SIGN_TX_MESSAGE_NAME_PATTERN,
    _MOCK_SIGNATURES_PATTERN,
    collect_required_sign_tx_signature_keys,
)
from tests.unit.generators.paths import UNIT_TESTS_DIR

DEFAULT_RUNTIME_USAGE_CTEST_REGEX = r"test_(message_signing|sign_msg|sign_tx|opcert|cvote)"


@dataclass(frozen=True)
class SignatureEntry:
    index: int
    message_name: str
    path_words: tuple[int, ...]
    hash_bytes: bytes

    @property
    def is_generated_sign_tx(self) -> bool:
        return bool(_GENERATED_SIGN_TX_MESSAGE_NAME_PATTERN.fullmatch(self.message_name))


def _parse_path_words(path_words_str: str) -> tuple[int, ...]:
    return tuple(int(word.strip(), 16) for word in path_words_str.split(","))


def _load_signature_entries() -> list[SignatureEntry]:
    mock_data_header = UNIT_TESTS_DIR / "mock_crypto" / "crypto_mock_data.h"
    content = mock_data_header.read_text(encoding="utf-8")
    message_bodies = extract_static_uint8_array_bodies(content)
    mock_signatures_match = _MOCK_SIGNATURES_PATTERN.search(content)
    if mock_signatures_match is None:
        raise ValueError("MOCK_SIGNATURES array not found in mock crypto data header")

    signature_entries_body = mock_signatures_match.group(2)
    entry_texts = extract_brace_delimited_entries(signature_entries_body, _ENTRY_START_PATTERN)

    entries: list[SignatureEntry] = []
    for entry_index, entry_text in enumerate(entry_texts):
        path_words_match = re.search(r"\.path\s*=\s*\{\s*(?P<path_words>[^}]+)\}", entry_text)
        message_name_match = re.search(r"\.message\s*=\s*(?P<message_name>[A-Z0-9_]+)", entry_text)
        if path_words_match is None or message_name_match is None:
            raise ValueError(f"Failed to parse MOCK_SIGNATURES entry at index {entry_index}")
        message_name = message_name_match.group("message_name")
        message_body = message_bodies.get(message_name)
        if message_body is None:
            raise ValueError(f"Failed to resolve message buffer {message_name} for MOCK_SIGNATURES entry at index {entry_index}")
        hash_bytes = bytes.fromhex("".join(re.findall(r"0x([0-9a-fA-F]{2})", message_body)))
        entries.append(
            SignatureEntry(
                index=entry_index,
                message_name=message_name,
                path_words=_parse_path_words(path_words_match.group("path_words")),
                hash_bytes=hash_bytes,
            )
        )
    return entries


def _report_generated_sign_tx_usage(entries: list[SignatureEntry]) -> int:
    available_keys = {(entry.path_words, entry.hash_bytes) for entry in entries if entry.is_generated_sign_tx}
    required_keys = set(collect_required_sign_tx_signature_keys())
    missing_keys = sorted(required_keys - available_keys)
    unused_keys = sorted(available_keys - required_keys)

    print(f"Required generated sign-tx mock signatures: {len(required_keys)}")
    print(f"Available generated sign-tx mock signatures: {len(available_keys)}")
    print(f"Missing generated sign-tx mock signatures: {len(missing_keys)}")
    for path_words, hash_bytes in missing_keys:
        print(f"  MISSING path={path_words} hash={hash_bytes.hex()}")

    print(f"Unused generated sign-tx mock signatures: {len(unused_keys)}")
    for path_words, hash_bytes in unused_keys:
        print(f"  UNUSED path={path_words} hash={hash_bytes.hex()}")

    return 1 if missing_keys else 0


def _collect_runtime_used_signature_indices(ctest_regex: str) -> set[int]:
    build_dir = UNIT_TESTS_DIR / "build"
    if not build_dir.exists():
        raise FileNotFoundError(
            f"Unit-test build directory not found: {build_dir}. Build tests first with cmake -Bbuild -H. && cmake --build build."
        )

    with tempfile.NamedTemporaryFile(
        prefix="cardano_mock_sig_usage_",
        suffix=".log",
        delete=False,
    ) as temp_file:
        log_path = Path(temp_file.name)

    try:
        env = dict(os.environ)
        env["CARDANO_MOCK_SIGNATURE_USAGE_LOG"] = str(log_path)
        result = subprocess.run(
            [
                "ctest",
                "--test-dir",
                str(build_dir),
                "-R",
                ctest_regex,
                "--output-on-failure",
            ],
            env=env,
            text=True,
            capture_output=True,
            timeout=1800,
            check=False,
        )
        if result.returncode != 0:
            if result.stdout:
                print(result.stdout, end="")
            if result.stderr:
                print(result.stderr, end="", file=sys.stderr)
            raise RuntimeError(f"ctest failed with return code {result.returncode} for regex {ctest_regex!r}")

        used_indices: set[int] = set()
        if log_path.exists():
            for line in log_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line == "":
                    continue
                used_indices.add(int(line))
        return used_indices
    finally:
        if log_path.exists():
            log_path.unlink()


def _report_runtime_static_usage(entries: list[SignatureEntry], ctest_regex: str) -> int:
    used_indices = _collect_runtime_used_signature_indices(ctest_regex)

    static_entries = [entry for entry in entries if not entry.is_generated_sign_tx]
    static_indices = {entry.index for entry in static_entries}
    used_static_indices = used_indices & static_indices
    unused_static_indices = static_indices - used_static_indices

    used_generated_indices = used_indices - static_indices

    print(f"Static mock signatures available: {len(static_entries)}")
    print(f"Static mock signatures used in runtime sample: {len(used_static_indices)}")
    print(f"Static mock signatures unused in runtime sample: {len(unused_static_indices)}")
    print(f"Runtime sample: ctest -R {ctest_regex!r}")
    print(f"Generated sign-tx mock signatures touched in runtime sample: {len(used_generated_indices)}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check mock-crypto data consistency and optional runtime usage.")
    parser.add_argument(
        "--runtime-static-usage",
        action="store_true",
        help=(
            "Run relevant unit tests with runtime logging and report how many static "
            "MOCK_SIGNATURES entries were actually exercised."
        ),
    )
    parser.add_argument(
        "--ctest-regex",
        default=DEFAULT_RUNTIME_USAGE_CTEST_REGEX,
        help=(f"CTest regex used with --runtime-static-usage. Default: {DEFAULT_RUNTIME_USAGE_CTEST_REGEX!r}"),
    )
    args = parser.parse_args()

    entries = _load_signature_entries()
    exit_code = _report_generated_sign_tx_usage(entries)

    if args.runtime_static_usage:
        runtime_exit_code = _report_runtime_static_usage(entries, args.ctest_regex)
        exit_code = max(exit_code, runtime_exit_code)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
