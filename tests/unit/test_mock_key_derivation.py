# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
Verify that unit-test mock key derivation data matches the standard test mnemonic.

This keeps hardcoded mock data in tests/unit/mock_crypto/crypto_mock_data.h synchronized with
actual key derivation from the standard test mnemonic:
"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
"""

import hashlib
import re
from pathlib import Path

import pytest
from ragger.bip import CurveChoice, calculate_public_key_and_chaincode

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def parse_bip32_path_from_c_array(path_array_str: str) -> str:
    """
    Convert C array representation to BIP32 path string.
    E.g., "{0x8000073c, 0x80000717, 0x80000000, 0x00000003, 0x00000000}"
    -> "m/1852'/1815'/0'/3/0"
    """
    hex_values = re.findall(r"0x[0-9a-fA-F]+", path_array_str)

    path_parts = ["m"]
    for hex_val in hex_values:
        val = int(hex_val, 16)
        if val & 0x80000000:
            path_parts.append(f"{val & 0x7FFFFFFF}'")
        else:
            path_parts.append(str(val))

    return "/".join(path_parts)


def parse_hex_array_from_c(c_array_str: str) -> bytes:
    """Parse a C byte array into Python bytes."""
    hex_values = re.findall(r"0x[0-9a-fA-F]{2}", c_array_str)
    return bytes(int(h, 16) for h in hex_values)


def parse_mock_paths_from_header() -> list[dict[str, bytes | str]]:
    """
    Parse all mock path entries from crypto_mock_data.h.

    Returns entries with path, public_key, chain_code, key_hash, and description.
    """
    header_file = Path(__file__).parent / "mock_crypto" / "crypto_mock_data.h"

    if not header_file.exists():
        pytest.skip(f"Mock data header not found: {header_file}")

    content = header_file.read_text(encoding="utf-8")

    entries = []
    pattern = (
        r'/\* Path "([^"]+)".*?\.path = (\{[^}]+\}).*?'
        r"\.public_key = (\{[^}]+\}).*?\.chain_code = (\{[^}]+\}).*?\.key_hash = (\{[^}]+\})"
    )
    blocks = re.findall(pattern, content, re.DOTALL)

    for path_desc, path_array, pubkey_array, chaincode_array, keyhash_array in blocks:
        entries.append(
            {
                "description": path_desc,
                "path": parse_bip32_path_from_c_array(path_array),
                "public_key": parse_hex_array_from_c(pubkey_array),
                "chain_code": parse_hex_array_from_c(chaincode_array),
                "key_hash": parse_hex_array_from_c(keyhash_array),
            }
        )

    return entries


def test_all_mock_key_derivation() -> None:
    """
    Verify that all mock path entries match key derivation from the standard mnemonic.

    This test:
    1. Parses crypto_mock_data.h to extract all mock entries.
    2. For each entry, derives the key from the standard mnemonic.
    3. Verifies public key, chain code, and key hash match.
    """
    mock_entries = parse_mock_paths_from_header()

    if not mock_entries:
        pytest.skip("No mock entries found in crypto_mock_data.h")

    print(f"\nVerifying {len(mock_entries)} mock path entries...")

    for entry in mock_entries:
        path = str(entry["path"])
        description = str(entry["description"])
        expected_pubkey = bytes(entry["public_key"])
        expected_chaincode = bytes(entry["chain_code"])
        expected_keyhash = bytes(entry["key_hash"])

        derived_pk_hex, derived_chain_code_hex = calculate_public_key_and_chaincode(
            CurveChoice.Ed25519Kholaw, path, mnemonic=MNEMONIC
        )

        # Ragger returns the public key in the 0x00-prefixed 33-byte representation.
        derived_pk = bytes.fromhex(derived_pk_hex[2:])
        derived_chaincode = bytes.fromhex(derived_chain_code_hex)

        assert derived_pk == expected_pubkey, (
            f"{description} ({path}): Public key mismatch!\n"
            f"  Expected: {expected_pubkey.hex()}\n"
            f"  Derived:  {derived_pk.hex()}\n"
            f"  Check tests/unit/mock_crypto/crypto_mock_data.h"
        )

        assert derived_chaincode == expected_chaincode, (
            f"{description} ({path}): Chain code mismatch!\n"
            f"  Expected: {expected_chaincode.hex()}\n"
            f"  Derived:  {derived_chaincode.hex()}\n"
            f"  Check tests/unit/mock_crypto/crypto_mock_data.h"
        )

        calculated_keyhash = hashlib.blake2b(derived_pk, digest_size=28).digest()
        assert calculated_keyhash == expected_keyhash, (
            f"{description} ({path}): Key hash mismatch!\n"
            f"  Expected: {expected_keyhash.hex()}\n"
            f"  Calculated: {calculated_keyhash.hex()}\n"
            "  The key_hash field should be blake2b-224 of the public key"
        )

        print(f"OK {description} ({path})")

    print(f"\nOK all {len(mock_entries)} entries verified successfully!")
