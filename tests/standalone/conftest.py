# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E402

import os
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = ROOT / "tests"
for extra_path in (ROOT, TESTS_ROOT):
    str_extra = str(extra_path)
    if str_extra not in sys.path:
        sys.path.insert(0, str_extra)

import pytest

from .client_constants_check import (
    assert_app_definition_constants_match,
    assert_app_status_words_match,
    assert_cla_constant_match,
    assert_cvote_credential_constants_match,
    assert_default_setting_values_match,
    assert_ins_constants_match,
    assert_max_sign_msg_chunk_size_match,
    assert_max_sign_tx_chunk_size_match,
    assert_p1_p2_constants_match,
    assert_response_unpacker_constants_match,
    assert_setting_value_constants_match,
    assert_settings_menu_constants_match,
    assert_sign_msg_and_native_script_constants_match,
    assert_sign_tx_related_constants_match,
    assert_warning_bit_constants_match,
)

NANO_STREAMING_TIMEOUT_SECONDS = 600

###########################
### CONFIGURATION START ###
###########################

# You can configure optional parameters by overriding the value of ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values

# Ragger tests are supposed to run without any hardcoded seed / mnemonic.
# However, for debugging, we might want to fix the seed occasionally
# to a value corresponding to the unit test fixtures.
# configuration.OPTIONAL.CUSTOM_SEED = (
#     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# )

#########################
### CONFIGURATION END ###
#########################


def _assert_client_constants_match() -> None:
    assert_ins_constants_match()
    assert_p1_p2_constants_match()
    assert_cla_constant_match()
    assert_cvote_credential_constants_match()
    assert_warning_bit_constants_match()
    assert_max_sign_tx_chunk_size_match()
    assert_max_sign_msg_chunk_size_match()
    assert_setting_value_constants_match()
    assert_default_setting_values_match()
    assert_settings_menu_constants_match()
    assert_app_status_words_match()
    assert_app_definition_constants_match()
    assert_sign_tx_related_constants_match()
    assert_sign_msg_and_native_script_constants_match()
    assert_response_unpacker_constants_match()


def pytest_sessionstart(session: pytest.Session) -> None:  # pylint: disable=unused-argument
    """Ensure the Python helpers stay aligned with the C dispatcher before raggers run."""
    try:
        _assert_client_constants_match()
    except AssertionError as assertion_error:
        pytest.exit(
            f"Client constants do not match the C app sources: {assertion_error}",
            returncode=1,
        )


# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest",)


@pytest.fixture(scope="class")
def additional_speculos_arguments() -> list[str]:
    """Assign probed Speculos ports from a worker-specific range under pytest-xdist.

    Ragger's default "find a free port" logic races across xdist workers.
    Keep workers separated in distinct port ranges, but still probe within the
    worker's range to avoid collisions with lingering Speculos processes or
    unrelated services.
    """
    worker_id = os.environ.get("PYTEST_XDIST_WORKER")
    if not worker_id:
        return []

    if not worker_id.startswith("gw"):
        raise AssertionError(f"Unexpected xdist worker id: {worker_id}")

    worker_index = int(worker_id[2:])
    base_port = 40000 + worker_index * 1000
    range_size = 1000

    def _port_is_free(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                return False
        return True

    def _find_free_port(start_offset: int) -> int:
        for offset in range(start_offset, range_size):
            port = base_port + offset
            if _port_is_free(port):
                return port
        raise AssertionError(f"No free Speculos port found in worker range {base_port}-{base_port + range_size - 1}")

    api_port = _find_free_port(0)
    apdu_port = _find_free_port((api_port - base_port) + 1)
    return ["--api-port", str(api_port), "--apdu-port", str(apdu_port)]


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Apply targeted timeout overrides for slow parameterized scenarios."""
    for item in items:
        callspec = getattr(item, "callspec", None)
        if callspec is None:
            continue

        device_name = callspec.id.split("-", 1)[0]
        if not device_name.startswith("nano"):
            continue

        test_case = callspec.params.get("testCase")
        test_case_name = getattr(test_case, "name", None)
        if test_case_name is None:
            continue

        if "streaming" not in test_case_name.lower():
            continue

        item.add_marker(pytest.mark.timeout(NANO_STREAMING_TIMEOUT_SECONDS))
