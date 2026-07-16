# Fuzzing Harnesses for Cardano Ledger App

## Overview

Fuzzing allows us to test how a program behaves when provided with invalid, unexpected, or random data as input.
Fuzzing is part of our comprehensive testing strategy, which is described in the testing section of [doc/OVERVIEW.md](../doc/OVERVIEW.md).

This directory contains 13 fuzzing harnesses covering APDU handlers, transaction
parsing, address derivation, script hashing, and other security-critical components.
Each harness implements `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`.

For a local compile-health build from the repository root, a convenience wrapper is available:

```bash
make -C tests fuzzing
```

This builds the fuzzing harnesses and runs each built fuzzer for 1 second by default.
Override the duration with `FUZZ_SECONDS`, for example:

```bash
make -C tests fuzzing FUZZ_SECONDS=30
```

Quick start to build and run all fuzzers locally:

```bash
rm -rf build && cmake -S . -B build -DBOLOS_SDK=${BOLOS_SDK} -DTARGET=stax -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=address -G Ninja && cmake --build build -j4 && ./run_all_fuzzers.sh 600
```

## Available Harnesses

The `tests/fuzzing/harness/` directory contains harnesses for individual APDU handlers,
internal parsers/builders, and a combined dispatcher fuzzer. Each implements
`int LLVMFuzzerTestOneInput(...)` and is built into a `fuzz_*` binary.

Current harnesses:

- `fuzz_all_handlers`
- `fuzz_bip44_policy`
- `fuzz_cvote_aux_parser`
- `fuzz_deriveAddress`
- `fuzz_deriveNativeScriptHash`
- `fuzz_getAppName`
- `fuzz_getPublicKeys`
- `fuzz_getSerial`
- `fuzz_getVersion`
- `fuzz_native_script_hash_builder`
- `fuzz_signOpCert`
- `fuzz_signTx`
- `fuzz_tx_parser_entrypoints`

## Building and Running Fuzzers from the container

### Preparation

The fuzzer can be run inside the active Ledger VS Code dev-tools container used
for this repository, typically `ledger-app-cardano-container`. That keeps the
SDK version aligned with normal app builds.

```bash
docker exec -ti ledger-app-cardano-container bash
```

If the VS Code container is not running, start it through the Ledger VS Code
extension. As a fallback, use the same dev-tools image and mount the repository
at `/app`:

```bash
docker run --rm -ti -v "$(realpath .):/app" \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

### Compile and run the fuzzer from the container

Once inside the container, navigate to the `tests/fuzzing` folder to generate the fuzzer:

#### Preparation

Install the needed modules and set the BOLOS_SDK variable:

```bash
export BOLOS_SDK=/opt/flex-secure-sdk/
cd tests/fuzzing
```

#### Compile the fuzzers

```bash
${BOLOS_SDK}/fuzzing/local_run.sh --j=4 --build=1 --BOLOS_SDK=${BOLOS_SDK}
```

#### Run the fuzzer

```bash
${BOLOS_SDK}/fuzzing/local_run.sh --j=4 --run-fuzzer=1 --fuzzer=build/fuzz_XXX --compute-coverage=1
```

#### Compile and run the fuzzer

```bash
${BOLOS_SDK}/fuzzing/local_run.sh --j=4 --build=1 --BOLOS_SDK=${BOLOS_SDK} \
                                  --run-fuzzer=1 --fuzzer=build/fuzz_XXX --compute-coverage=1
```

### About local_run.sh

| Parameter              | Type                | Description                                                          |
| :--------------------- | :------------------ | :------------------------------------------------------------------- |
| `--BOLOS_SDK`          | `PATH TO BOLOS SDK` | **Required**. Path to the BOLOS SDK                                  |
| `--build`              | `bool`              | **Optional**. Whether to build the project (default: 0)              |
| `--fuzzer`             | `PATH`              | **Required**. Path to the fuzzer binary                              |
| `--compute-coverage`   | `bool`              | **Optional**. Whether to compute coverage after fuzzing (default: 0) |
| `--run-fuzzer`         | `bool`              | **Optional**. Whether to run or not the fuzzer (default: 0)          |
| `--run-crash`          | `FILENAME`          | **Optional**. Run the on a specific crash input file (default: 0)    |
| `--sanitizer`          | `address or memory` | **Optional**. Compile with sanitizer (default: address)              |
| `--j`                  | `int`               | **Optional**. N-parallel jobs for build and fuzzing (default: 1)     |
| `--help`               |                     | **Optional**. Display help message                                   |

### Visualizing code coverage

After running your fuzzer, if `--compute-coverage=1` the coverage will be available in your browser.

## Building and Running Fuzzers (SDK Fuzzing Framework)

The fuzzing infrastructure uses the Ledger SDK fuzzing framework (`${BOLOS_SDK}/fuzzing/`).
Compile definitions are extracted automatically from the app Makefile via `make list-defines`,
with app-specific additions/exclusions managed in `macros/add_macros.txt` and
`macros/exclude_macros.txt`.

### Using `local_run.sh` (Recommended)

The SDK provides `local_run.sh` for building and running fuzzers with proper sanitizer
and coverage support. This is the recommended method.

```bash
export BOLOS_SDK=${FLEX_SDK} # Enforce a valid sdk path
cd tests/fuzzing

# Remove any stale build cache copied from a container run under /app.
rm -rf build

# Select a supported SDK target explicitly when BOLOS_SDK has no .target file.
export TARGET=stax  # or: export TARGET=flex

# Install missing dependencies
apt-get update -y && apt install clang lld -y

# Build all fuzzers
${BOLOS_SDK}/fuzzing/local_run.sh \
    --BOLOS_SDK=${BOLOS_SDK} \
    --fuzzer=build/fuzz_getVersion \
    --j=4 \
    --build=1

# Run a specific fuzzer
${BOLOS_SDK}/fuzzing/local_run.sh \
    --BOLOS_SDK=${BOLOS_SDK} \
    --j=4 \
    --run-fuzzer=1 \
    --fuzzer=build/fuzz_signTx

# Run with coverage report (generates HTML in out/<fuzzer>/index.html)
${BOLOS_SDK}/fuzzing/local_run.sh \
    --BOLOS_SDK=${BOLOS_SDK} \
    --j=4 \
    --run-fuzzer=1 \
    --fuzzer=build/fuzz_signTx \
    --compute-coverage=1

# Reproduce a specific crash
${BOLOS_SDK}/fuzzing/local_run.sh \
    --BOLOS_SDK=${BOLOS_SDK} \
    --fuzzer=build/fuzz_signTx \
    --run-crash=out/fuzz_signTx/crashes/crash-abc123
```

`local_run.sh` handles sanitizer flags, corpus management, crash collection, and LLVM
coverage report generation automatically. Run with `--help` for all options.

The SDK script forwards the `TARGET` environment variable to the app's `make list-defines`
step, so one of `stax` or `flex` must be selected unless `${BOLOS_SDK}/.target` already
exists.

### Manual CMake Build (Alternative)

For more control over the build process:

```bash
cd tests/fuzzing
rm -rf build
export TARGET=stax  # or: export TARGET=flex
cmake -DBOLOS_SDK=/opt/ledger-secure-sdk \
      -DTARGET=${TARGET} \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_BUILD_TYPE=Debug \
      -DSANITIZER=address \
      -Bbuild -H.
cmake --build build -j4
```

Then run fuzzers directly:

```bash
# Interactive fuzzing with an optional shared seed corpus
mkdir -p ./corpus
./build/fuzz_signOpCert ./corpus

# Fuzzing without seed (finds more edge cases, slower startup)
./build/fuzz_getPublicKeys

# Test multi-command sequences
./build/fuzz_all_handlers ./corpus -max_len=8192
```

### Batch Run (All Fuzzers)

The `run_all_fuzzers.sh` convenience script discovers and runs all built fuzzers:

```bash
cd tests/fuzzing
./run_all_fuzzers.sh 600 out-local
```

### Container-Based Build (For CI/Continuous Fuzzing)

For continuous fuzzing integration with OSS-Fuzz:

```bash
mkdir -p tests/fuzzing/out
docker build -t cardano-app --file .clusterfuzzlite/Dockerfile .
docker run --rm --privileged -e FUZZING_LANGUAGE=c \
    -v "$(realpath .)/tests/fuzzing/out:/out" -ti cardano-app
```

## Macro Management

Compile definitions are handled by the SDK's macro extraction system:

1. **Automatic extraction:** The SDK runs `make list-defines` against the app Makefile
   to collect all `DEFINES` (crypto flags, platform flags, etc.).
2. **`macros/add_macros.txt`:** Additional defines needed only for fuzzing builds
   (e.g. `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1`).
3. **`macros/exclude_macros.txt`:** Defines to remove from fuzzing builds
   (e.g. `NDEBUG` to keep asserts active, `PRINTF(...)=` to avoid conflicts).

This replaces the previous approach of hardcoding all defines in CMakeLists.txt and
ensures fuzzing builds stay in sync with the app's actual build configuration.

## Continuous Fuzzing via Google OSS-Fuzz

For production continuous fuzzing integration with Google's OSS-Fuzz infrastructure:

The repository includes `.clusterfuzzlite/` configuration files that enable automatic fuzzing campaigns.

**How it works:**

1. `.clusterfuzzlite/Dockerfile` - Uses `ledger-app-builder-lite` to provide the SDK,
   then `oss-fuzz-base/base-builder` for clang/libfuzzer/sanitizers.
2. `.clusterfuzzlite/build.sh` - Runs cmake with `LIB_FUZZING_ENGINE` and `CFLAGS`
   set by the OSS-Fuzz environment (the SDK detects this and uses those instead
   of its own sanitizer flags).

**Status:** The configuration files exist but CI integration is not yet active.

## Corpus Seed Data

The shared `corpus/` directory is optional and is used only for manual direct runs of
the fuzzing binaries. The SDK `local_run.sh` workflow manages per-fuzzer corpora under
`out/<fuzzer>/corpus` automatically.

## Notes

- Fuzzing requires **Clang** compiler
- Address sanitizer and memory sanitizer are supported (via `--sanitizer=address|memory`)
- Coverage mapping is available via `--compute-coverage=1`
- The `-fno-sanitize=alignment` flag is applied to suppress false positives from packed struct accesses
- Corpus files should be added as new interesting inputs are discovered

## References

- [Ledger SDK Fuzzing Framework](https://github.com/LedgerHQ/ledger-secure-sdk/tree/master/fuzzing)
- [Google Sanitizers](https://github.com/google/sanitizers)
- [LLVM LibFuzzer](https://llvm.org/docs/LibFuzzer/)
- [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/)
- [OSS-Fuzz](https://google.github.io/oss-fuzz/)
