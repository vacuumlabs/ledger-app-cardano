# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

import os
import shutil
import subprocess
from pathlib import Path

base = Path(__file__).parent.resolve() / ".test_dependencies"

APP_EXCHANGE_URL = "git@github.com:LedgerHQ/app-exchange.git"
APP_EXCHANGE_DIR = base / "main/app-exchange/"
APP_EXCHANGE_CLONE_DIR = base / "app-exchange/"

APP_ETHEREUM_URL = "git@github.com:LedgerHQ/app-ethereum.git"
APP_ETHEREUM_DIR = base / "libraries/app-ethereum/"
APP_ETHEREUM_CLONE_DIR = base / "app-ethereum/"

DEVICES_CONF = {
    "nanos+": {
        "sdk": "NANOSP_SDK",
        "target": "nanos2",
        "bin_path": "build/nanos2/bin/",
    },
    "nanox": {
        "sdk": "NANOX_SDK",
        "target": "nanox",
        "bin_path": "build/nanox/bin/",
    },
    "stax": {
        "sdk": "STAX_SDK",
        "target": "stax",
        "bin_path": "build/stax/bin/",
    },
    "flex": {
        "sdk": "FLEX_SDK",
        "target": "flex",
        "bin_path": "build/flex/bin/",
    },
    "apex_p": {
        "sdk": "APEX_P_SDK",
        "target": "apex_p",
        "bin_path": "build/apex_p/bin/",
    },
}


def run_cmd(
    cmd: list[str],
    cwd: Path = Path("."),
    print_output: bool = False,
    no_throw: bool = False,
) -> str:
    print(f"[run_cmd] Running: {cmd!r} inside '{cwd}'")

    ret = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=cwd,
        check=False,
    )
    if no_throw is False and ret.returncode:
        print(f"[run_cmd] Error {ret.returncode} raised while running cmd: {cmd}")
        print("[run_cmd] Output was:")
        print(ret.stdout)
        raise ValueError()

    if print_output:
        print(f"[run_cmd] Output:\n{ret.stdout}")

    return ret.stdout.strip()


def clone_or_pull(repo_url: str, clone_dir: str):
    # Only needed when cloning / pulling, not when building.
    # By putting the import here we allow the script to be imported inside the docker image
    from git import Repo

    clone_dir_path = Path(clone_dir)
    git_dir = clone_dir_path / ".git"
    if not git_dir.exists():
        print(f"Cloning into {clone_dir}")
        shutil.rmtree(clone_dir_path, ignore_errors=True)
        Repo.clone_from(repo_url, clone_dir, recursive=True)
    else:
        print(f"Pulling latest changes in {clone_dir}")
        repo = Repo(clone_dir)
        origin = repo.remotes.origin
        origin.fetch()
        repo.git.reset("--hard", "origin/develop")

        # Update submodules
        print(f"Updating submodules in {clone_dir}")
        run_cmd(["git", "submodule", "sync"], cwd=clone_dir_path)
        run_cmd(["git", "submodule", "update", "--init", "--recursive"], cwd=clone_dir_path)


def build_app(clone_dir: str, flags: str):
    clone_dir_path = Path(clone_dir)
    use_unified_sdk = all(d["sdk"] not in os.environ for d in DEVICES_CONF.values())
    unified_sdk_path = os.environ.get("BOLOS_SDK") if use_unified_sdk else None
    first_device_config = next(iter(DEVICES_CONF.values()))
    clean_cmd = ["make"]
    if unified_sdk_path is not None:
        clean_cmd += [
            f"TARGET={first_device_config['target']}",
            f"BOLOS_SDK={unified_sdk_path}",
        ]
    clean_cmd.append("clean")
    run_cmd(clean_cmd, cwd=clone_dir_path)

    for d in DEVICES_CONF.values():
        if unified_sdk_path is not None:
            cmd = [
                "make",
                "-j",
                f"TARGET={d['target']}",
                f"BOLOS_SDK={unified_sdk_path}",
                *flags.split(),
            ]
        else:
            sdk = d["sdk"]
            sdk_path = os.environ.get(sdk)
            if sdk_path is None:
                raise ValueError(f"Environment variable {sdk} is not set")
            cmd = ["make", "-j", f"BOLOS_SDK={sdk_path}", *flags.split()]
        run_cmd(cmd, cwd=clone_dir_path)


def copy_build_output(clone_dir: str, dest_dir: str):
    clone_build_dir = Path(clone_dir) / "build"
    destination_build_dir = Path(dest_dir) / "build"

    destination_build_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(destination_build_dir, ignore_errors=True)
    shutil.copytree(clone_build_dir, destination_build_dir)


# ==== Build app-exchange ====
def clone_and_pull_exchange():
    clone_or_pull(APP_EXCHANGE_URL, APP_EXCHANGE_CLONE_DIR)


def build_and_copy_exchange():
    build_app(
        APP_EXCHANGE_CLONE_DIR,
        flags=("TESTING=1 TEST_PUBLIC_KEY=1 TRUSTED_NAME_TEST_KEY=1 DEBUG=1 DEBUG_OS_STACK_CONSUMPTION=1"),
    )
    copy_build_output(APP_EXCHANGE_CLONE_DIR, APP_EXCHANGE_DIR)


# ==== Build app-ethereum ====
def clone_and_pull_ethereum():
    clone_or_pull(APP_ETHEREUM_URL, APP_ETHEREUM_CLONE_DIR)


def build_and_copy_ethereum():
    build_app(
        APP_ETHEREUM_CLONE_DIR,
        flags=(
            "COIN=ethereum CHAIN=ethereum CAL_TEST_KEY=1 DOMAIN_NAME_TEST_KEY=1"
            " SET_PLUGIN_TEST_KEY=1 NFT_TEST_KEY=1 TRUSTED_NAME_TEST_KEY=1"
        ),
    )
    copy_build_output(APP_ETHEREUM_CLONE_DIR, APP_ETHEREUM_DIR)
