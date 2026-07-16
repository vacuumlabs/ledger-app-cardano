# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for application metadata APDUs.
Tests app-level information commands: GET_APP_NAME, GET_VERSION, GET_SERIAL.
"""

from ragger.backend.interface import BackendInterface
from ragger.utils.misc import get_current_app_name_and_version

from tests.application_client.command_sender import CommandSender
from tests.application_client.response_unpacker import (
    unpack_get_app_name_response,
    unpack_get_serial_response,
)
from tests.application_client.status_words import StatusWord

from .utils import verify_name, verify_version


def test_get_app_name(backend: BackendInterface) -> None:
    """Check application name via GET_APP_NAME APDU and verify against OS."""
    client = CommandSender(backend)
    response = client.get_app_name()
    app_name = unpack_get_app_name_response(response.data)
    verify_name(app_name)

    # Verify app name matches what OS reports
    os_app_name, _ = get_current_app_name_and_version(backend)
    assert app_name == os_app_name, f"App name mismatch: app reports '{app_name}', OS reports '{os_app_name}'"


def test_get_version(backend: BackendInterface) -> None:
    """Check version returned by the app via GET_VERSION APDU and verify against OS."""
    client = CommandSender(backend)
    version = client.get_version()
    vers_str = f"{version.major}.{version.minor}.{version.patch}"

    print(f" Version: {vers_str}")
    verify_version(vers_str)

    # Verify app version matches what OS reports
    _, os_version = get_current_app_name_and_version(backend)
    assert vers_str == os_version, f"Version mismatch: app reports '{vers_str}', OS reports '{os_version}'"


def test_get_serial(backend: BackendInterface) -> None:
    """Check application serial number via GET_SERIAL APDU."""
    client = CommandSender(backend)
    first_response = client.get_serial()
    second_response = client.get_serial()

    assert first_response.status == StatusWord.SWO_SUCCESS
    assert second_response.status == StatusWord.SWO_SUCCESS

    first_serial = unpack_get_serial_response(first_response.data)
    second_serial = unpack_get_serial_response(second_response.data)

    assert first_serial == first_response.data
    assert second_serial == second_response.data
    assert len(first_serial) == 7
    assert first_serial == second_serial, "Serial must be stable within one session"
