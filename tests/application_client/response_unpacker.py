# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from enum import IntFlag
from struct import unpack
from typing import NamedTuple


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


# Unpack from response:
# response = app_name (var)
def unpack_get_app_name_response(response: bytes) -> str:
    return response.decode("ascii")


class GetVersionFlag(IntFlag):
    DEBUG = 1 << 0


class GetVersionResponse(NamedTuple):
    major: int
    minor: int
    patch: int
    flags: int

    @property
    def is_debug(self) -> bool:
        return bool(self.flags & GetVersionFlag.DEBUG)


# Unpack from response:
# response = MAJOR (1)
#            MINOR (1)
#            PATCH (1)
#            FLAGS (1)
def unpack_get_version_response(response: bytes) -> GetVersionResponse:
    _require(len(response) == 4, f"Invalid version response length: {len(response)}")
    major, minor, patch, flags = unpack("BBBB", response)
    return GetVersionResponse(major=major, minor=minor, patch=patch, flags=flags)


# Unpack from response:
# response = serial (7)
def unpack_get_serial_response(response: bytes) -> bytes:
    SERIAL_LENGTH = 7
    _require(
        len(response) == SERIAL_LENGTH,
        f"Invalid serial response length: {len(response)}",
    )
    return response


# Unpack from response:
# response = pub_key (32)
#            chain_code (32)
def unpack_get_pubkey_response(response: bytes) -> tuple[bytes, bytes]:
    PUBLIC_KEY_LENGTH = 32
    CHAIN_CODE_LENGTH = 32
    _require(
        len(response) == PUBLIC_KEY_LENGTH + CHAIN_CODE_LENGTH,
        f"Invalid pubkey response length: {len(response)}",
    )
    public_key = response[:PUBLIC_KEY_LENGTH]
    chain_code = response[PUBLIC_KEY_LENGTH:]
    return public_key, chain_code


# Unpack from response:
# response = signature (64)
def unpack_sign_opcert_response(response: bytes) -> bytes:
    SIGNATURE_LENGTH = 64
    _require(
        len(response) == SIGNATURE_LENGTH,
        f"Invalid opcert signature length: {len(response)}",
    )
    return response


# Unpack from response:
# response = signature (64)
def unpack_sign_tx_witness_response(response: bytes) -> bytes:
    SIGNATURE_LENGTH = 64
    _require(
        len(response) == SIGNATURE_LENGTH,
        f"Invalid witness signature length: {len(response)}",
    )
    return response


# Unpack from response:
# response = tx_hash (32)
def unpack_sign_tx_hash_response(response: bytes) -> bytes:
    TX_HASH_LENGTH = 32
    _require(
        len(response) == TX_HASH_LENGTH,
        f"Invalid tx hash response length: {len(response)}",
    )
    return response


# Unpack from response:
# response = address (var, 1..128 raw bytes)
def unpack_derive_address_response(response: bytes) -> bytes:
    MIN_ADDRESS_LENGTH = 1
    MAX_ADDRESS_LENGTH = 128  # MAX_ADDRESS_LENGTH from addressUtilsShelley.h
    _require(
        MIN_ADDRESS_LENGTH <= len(response) <= MAX_ADDRESS_LENGTH,
        f"Invalid derive-address response length: {len(response)}",
    )
    return response


# Unpack from response:
# response = script_hash (28)
def unpack_derive_native_script_hash_response(response: bytes) -> bytes:
    SCRIPT_HASH_LENGTH = 28
    _require(
        len(response) == SCRIPT_HASH_LENGTH,
        f"Invalid native script hash length: {len(response)}",
    )
    return response


# Unpack from response:
# response = signature (64)
#            public_key (32)
#            address_field_size (4)
#            address_field (variable, up to 128)
def unpack_sign_message_response(response: bytes) -> tuple[bytes, bytes, bytes]:
    SIGNATURE_LENGTH = 64
    PUBLIC_KEY_LENGTH = 32
    ADDRESS_FIELD_SIZE_LENGTH = 4
    MAX_ADDRESS_FIELD_LENGTH = 128

    # Validate minimum response length
    min_length = SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + ADDRESS_FIELD_SIZE_LENGTH
    _require(
        len(response) >= min_length,
        f"Response too short: {len(response)} < {min_length}",
    )
    _require(
        len(response) <= min_length + MAX_ADDRESS_FIELD_LENGTH,
        f"Response too long: {len(response)} > {min_length + MAX_ADDRESS_FIELD_LENGTH}",
    )

    # Extract signature
    offset = 0
    signature = response[offset : offset + SIGNATURE_LENGTH]
    _require(
        len(signature) == SIGNATURE_LENGTH,
        f"Invalid sign-message signature length: {len(signature)}",
    )
    offset += SIGNATURE_LENGTH

    # Extract public key
    public_key = response[offset : offset + PUBLIC_KEY_LENGTH]
    _require(
        len(public_key) == PUBLIC_KEY_LENGTH,
        f"Invalid sign-message public key length: {len(public_key)}",
    )
    offset += PUBLIC_KEY_LENGTH

    # Extract address field size
    address_field_size = int.from_bytes(response[offset : offset + ADDRESS_FIELD_SIZE_LENGTH], "big")
    _require(
        address_field_size <= MAX_ADDRESS_FIELD_LENGTH,
        f"Address field too long: {address_field_size} > {MAX_ADDRESS_FIELD_LENGTH}",
    )
    offset += ADDRESS_FIELD_SIZE_LENGTH

    # Extract address field
    address_field = response[offset : offset + address_field_size]
    _require(
        len(address_field) == address_field_size,
        f"Address field truncated: expected {address_field_size}, got {len(address_field)}",
    )
    offset += address_field_size

    _require(
        offset == len(response),
        f"Trailing bytes in response: parsed {offset} of {len(response)}",
    )

    return signature, public_key, address_field


# Unpack from response:
# response = aux_data_hash (32) + registration_signature (64)
def unpack_sign_tx_aux_data_confirm_response(response: bytes) -> tuple[bytes, bytes]:
    AUX_DATA_HASH_LENGTH = 32
    SIGNATURE_LENGTH = 64
    _require(
        len(response) == AUX_DATA_HASH_LENGTH + SIGNATURE_LENGTH,
        f"Invalid sign_tx aux data confirm response length: {len(response)}",
    )
    aux_data_hash = response[:AUX_DATA_HASH_LENGTH]
    registration_signature = response[AUX_DATA_HASH_LENGTH:]
    return aux_data_hash, registration_signature


# Unpack from response:
# response = votecast_hash (32) + signature (64)
def unpack_sign_cip36_confirm_response(response: bytes) -> tuple[bytes, bytes]:
    HASH_LENGTH = 32
    SIGNATURE_LENGTH = 64
    _require(
        len(response) == HASH_LENGTH + SIGNATURE_LENGTH,
        f"Invalid CIP-36 confirm response length: {len(response)}",
    )
    votecast_hash = response[:HASH_LENGTH]
    signature = response[HASH_LENGTH:]
    return votecast_hash, signature
