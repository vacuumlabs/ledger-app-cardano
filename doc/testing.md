# Testing Overview

This is the main entry point for test documentation in the Cardano Ledger app.

## Python Environment

Python-based test tooling in this repository uses a shared virtual environment at
`tests/venv`.

Create it once from the repository root:

```bash
python3 -m venv tests/venv
source tests/venv/bin/activate
pip install -r tests/requirements.txt
```

Use this environment for:

- `tests/standalone/` ragger tests
- `tests/application_client/`
- `tests/unit/generators/`
- other Python helpers under `tests/`

## System Prerequisites

On Ubuntu, install the following required dependencies for building and running unit tests:

```bash
sudo apt update
sudo apt install cmake libcmocka-dev lcov
```

For standalone functional tests (ragger), you also need:

```bash
sudo apt install qemu-user-static
```

### Linting and Formatting (Ruff)

The project uses [Ruff](https://docs.astral.sh/ruff/) for Python linting and formatting. Ruff is included in the shared `tests/requirements.txt`.

Always run Ruff before committing Python changes:

```bash
# From repository root
source tests/venv/bin/activate

# Format files
ruff format . --exclude tests/venv

# Run linter and apply automatic fixes
ruff check --fix . --exclude tests/venv
```

Run the Python lint and type checks used in CI from the repository root:

```bash
source tests/venv/bin/activate
make -C tests python-checks
```

Notes:
- The project follows absolute import patterns (`from tests.pkg...`).
- Most `E402` (imports not at top) errors have been resolved by moving path bootstrapping to module execution (`python3 -m ...`). Avoid introducing new `sys.path` hacks.

Activation examples:

```bash
# From repository root
source tests/venv/bin/activate

# From tests/unit
source ../venv/bin/activate
```

Notes:

- Do not rely on the system `python3` for these workflows; missing packages and
  import-path mismatches are common outside the shared venv.

## Test Suites

- Unit tests: `tests/unit/README.md`
- Standalone functional tests (ragger): `tests/standalone/README.md`
- Swap/library-mode tests: `tests/swap/README.md`
- Fuzzing: `tests/fuzzing/FUZZING.md`

## Workflow

- When C code is modified, run unit tests.
- After unit tests pass, run a fuzzing build as a compile-health gate.
- Regenerate unit-test fixtures when `tests/standalone/input_files/` or
  `tests/application_client/` changes via:
  `PYTHONPATH=. tests/venv/bin/python -m tests.unit.generators.generate_unit_tests_from_ragger all` from the repository root.
- When `clang-format-14` is available, generated unit-test C/H files are normalized by the generator itself, and `make -C tests generated-fixture-drift` verifies that generated output still matches `clang-format-14`.
- Happy-path unit fixtures must have explicit expected output values. Missing unit
  expected results are a hard error: generators must report them, and unit tests
  must not silently skip response verification for those fixtures.
- For the concrete edit/regenerate/build/run sequence, see
  `tests/unit/README.md` -> `Fixture Workflow`.
- Use the shared venv above when running generator scripts or other Python-based
  test tooling.
- Run ragger and swap tests only when explicitly requested.
- Convenience wrappers from the repository root:
  - `make -C tests python-checks` runs Ruff format check, pylint, and mypy.
  - `make -C tests clang-format-src-check` checks `clang-format-14` on `src/**/*.c` and `src/**/*.h`.
  - `make -C tests clang-format-generated-check` checks `clang-format-14` on generated unit-test C/H files.
  - `make -C tests tests-unit` regenerates unit fixtures, checks drift and generated C formatting, builds, and runs unit tests.
  - `make -C tests unit-coverage` builds unit tests, runs them, and generates an HTML coverage report at `tests/unit/coverage/index.html`.
  - `make -C tests fuzzing` builds fuzzing harnesses and runs each for 1 second by default (override with `FUZZ_SECONDS=<n>`, requires `BOLOS_SDK`).

## Coverage Exclusion Policy

Use `LCOV_EXCL_*` only for invariant-only dead paths that are intentionally
unreachable after existing validation, not for behavior branches.

Good candidates:

- `default` arms on validated enum domains.
- Impossible request/state-machine transitions.
- Defensive invariant checks used to catch internal contract violations.

Avoid excluding:

- parser/validation failures from malformed APDU, buffer, or Tx input,
- user-visible policy branches that can produce a deny/ reject outcome,
- missing-error paths that should be validated by unit fixtures.

Recommended style:

- Prefer `// LCOV_EXCL_LINE` for single-line invariant assertions.
- For `default:` switch cases, use `// LCOV_EXCL_START` / `// LCOV_EXCL_STOP` around
  the entire block including the `default:` label, because `lcov` will otherwise flag
  the `default:` keyword itself as uncovered.
- Keep the check as `LEDGER_ASSERT(false, "...")` (or `ASSERT(false)` for low-level checks).
- If a branch is reachable with realistic malformed-but-not-impossible input, add a
  test instead of excluding it.

Example:

```c
switch (status) {
    case VALID:
        ...
        break;
    // LCOV_EXCL_START
    default:
        LEDGER_ASSERT(false, "Unknown status: %u", status);
        return;
    // LCOV_EXCL_STOP
}
```

## Terminology: Deny vs Reject

Use these terms consistently across ragger tests, generator scripts, unit-test fixtures, and unit-test runners:

- **Deny**: app-level refusal (non-`9000`) enforced by app policy/validation.
  - This may happen before review UI, during review flow processing, or later in witness phase after review approval.
  - Example: invalid input, forbidden path/signing mode combination, malformed APDU payload, witness-path policy failure.
  - Naming: use `deny` in test names, fixture sets, generated fixture labels, and runner names.
- **Reject**: explicit user decision in UI to refuse an otherwise valid flow.
  - Example: user taps reject on NBGL confirmation, or unit tests simulate that UI action.
  - Naming: use `reject` only for user-decision paths and related NBGL/mock helpers.

This distinction is required to avoid conflating security-policy/input validation failures with human confirmation refusals.

## Debugging & Tracing

Excessive tracing strings in the debug version of the app can lead to the binary exceeding the available flash memory on the device. To mitigate this, the app uses **conditional tracing guards** for verbose or repetitive debug output.

### Implementation Guide

To use a guard in your module:
1. Define the guard at the top of your `.c` file:
   ```c
   #ifdef TRACE_MY_MODULE
   #define TRACE_MODULE(...) TRACE("[module] " __VA_ARGS__)
   #else
   #define TRACE_MODULE(...) (void)0
   #endif
   ```
2. Use `TRACE_MODULE()` for state tracking, loops, or field-level parsing.
3. Keep standard `TRACE()` for critical errors and security-relevant information.

### Available Tracing Guards

| Guard Name | Target Modules | Purpose |
|------------|----------------|---------|
| `TRACE_TX_PARSE` | `src/transaction/tx_parse*.c`, `src/parsers/cardano_parsers.c` | Transaction component and core parsing |
| `TRACE_TX_HASH_BUILDER` | `src/transaction/tx_hash_builder.c` | Core transaction hashing |
| `TRACE_HANDLERS` | `src/handler/*.c` | APDU command handler flow |
| `TRACE_UI_DISPLAY` | `src/ui/ui_display*.c`, `src/ui/ui_sign_msg.c`, `src/ui/ui_cvote.c`, `src/ui/ui_display_pubkey.c`, `src/ui/ui_display_tx.c` | UI rendering and state |
| `TRACE_CVOTE` | `src/cvote/cvote_parser.c` | Catalyst voting data parsing |
| `TRACE_AUX_DATA_HASH_BUILDER` | `src/cvote/aux_data_hash_builder.c` | Voting aux data hashing |
| `TRACE_VOTECAST_HASH_BUILDER` | `src/cvote/vote_cast_hash_builder.c` | Vote cast hashing |
| `TRACE_NATIVE_SCRIPT_HASH_BUILDER` | `src/deriveNativeScriptHash/derive_native_script_hash_builder.c` | Native script hashing |
| `TRACE_SWAP` | `src/swap/swap_lib.c` | Swap/library-mode validation flow |

### How to Build & Verify

These guards apply to the **device binary** built via the repo-root Makefile (inside the
Ledger SDK / Docker environment). Pass extra defines via `DEFINES+=`:
```bash
make DEBUG=1 DEFINES+=TRACE_TX_PARSE DEFINES+=TRACE_HANDLERS -j8
```

To verify that strings are correctly removed from the compiled binary:
```bash
# Build with guard disabled, then check count
make clean_target && make DEBUG=1 -j8
strings build/app-cardano/bin/app.elf | grep "your-string" | wc -l
```

### Impact on Release Builds
**None.** In release builds (where `HAVE_PRINTF` is not defined), the `TRACE` macro is defined as `do {} while(0)` in `utils/utils.h`. This means all strings are removed by the preprocessor regardless of guards. These guards specifically target the **debug binary** size constraints.

## Additional Index
