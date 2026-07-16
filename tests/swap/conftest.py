# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

import os
import sys
from pathlib import Path

import pytest
from ledger_app_clients.exchange.navigation_helper import ExchangeNavigationHelper
from ragger.conftest import configuration

# Add parent tests directory to path so we can import application_client
sys.path.insert(0, str(Path(__file__).parent.parent))

###########################
### CONFIGURATION START ###
###########################

# You can configure optional parameters by overriding the value of ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values

configuration.OPTIONAL.BACKEND_SCOPE = "function"
configuration.OPTIONAL.MAIN_APP_DIR = "tests/swap/.test_dependencies/main"
configuration.OPTIONAL.SIDELOADED_APPS_DIR = "tests/swap/.test_dependencies/libraries/"

#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest",)


@pytest.fixture(scope="session")
def snapshots_path():
    """
    This fixture provides the default path for screenshots.
    It is used in the ExchangeNavigationHelper.
    """
    # Use the current file's directory as the base path
    return Path(__file__).parent.resolve()


@pytest.fixture
def additional_speculos_arguments() -> list[str]:
    """Assign deterministic per-worker Speculos ports under pytest-xdist.

    Ragger's default "find a free port" logic races across xdist workers.
    Keep single-process runs unchanged and only pin ports when running under xdist.
    """
    worker_id = os.environ.get("PYTEST_XDIST_WORKER")
    if not worker_id:
        return []

    if not worker_id.startswith("gw"):
        raise AssertionError(f"Unexpected xdist worker id: {worker_id}")

    worker_index = int(worker_id[2:])
    api_port = 5000 + worker_index * 10
    apdu_port = api_port + 1
    return ["--api-port", str(api_port), "--apdu-port", str(apdu_port)]


@pytest.fixture(scope="function")
def exchange_navigation_helper(backend, navigator, snapshots_path, test_name):  # pylint: disable=redefined-outer-name
    return ExchangeNavigationHelper(
        backend=backend,
        navigator=navigator,
        snapshots_path=snapshots_path,
        test_name=test_name,
    )


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Sort collected tests by node ID for deterministic ordering across xdist workers."""
    items[:] = sorted(items, key=lambda item: item.nodeid)
