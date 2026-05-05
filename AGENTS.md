# Cardano Ledger App Development Guidelines

We are converting an old version of the Ledger Cardano app into a new modernized version with a refreshed UI.

## Context
- **Old app (Shelley):** `../app-cardano`. Refer to this for established logic and processing patterns.
- **New app:** `../ledger-app-cardano`. The modernized Ledger Cardano app in this repository.
- **Local reference repos:** Use the checked-out local copies first, not web search:
  - `../../ledger/app-ethereum`
  - `../../ledger/app-bitcoin-new`
  - `../../ledger/app-boilerplate`
  - `../../ledger/ledger-app-workflows`
- **Device Support:** Supporting Stax, Flex, Nano X, and Nano S+. *Nano S is no longer supported.*
- **UI Framework:** NBGL is used exclusively for UI. Prefer high-level functions for standard use cases.

## Architectural Overview
For detailed analysis, see:
- [doc/OVERVIEW.md](doc/OVERVIEW.md): High-level architecture, directory structure, and data flow.
- [doc/tx.md](doc/tx.md): Detailed transaction body processing and hashing.

**Note:** When exploring the codebase or answering questions about code organization, consult `doc/OVERVIEW.md` first for directory structure and conventions.

## Instructions for Coding Agent

### What to DO
- **Mimic Established Patterns:** Search the new app repository before copying logic from the old app.
- **Prefer local references:** Compare against the local copies listed above before reaching for web search.
- **No web search:** Do not use web search; if you feel you need some info from the web, ask explicitly.
- **Style:** Use long, descriptive variable names.
- **Security:** Use `STATIC_ASSERT` and `LEDGER_ASSERT` liberally for parameter validation and state machine invariants.
- **Static-analysis-friendly null checks:** Prefer combined guards like `x != NULL && x->field ...` in conditions/assertions (including `LEDGER_ASSERT`) when dereferencing pointers, to keep `scan-build`/clang analyzer free of false-positive null-dereference warnings. Use function contracts like `__attribute__((nonnull(...)))` where appropriate (already used in this repo), and note the SDK `__clang_analyzer__` trick with `__attribute__((analyzer_noreturn))` (see `exceptions.h`) for analyzer-specific control-flow hints.
- **Debugging:** Use `TRACE` (avoid `PRINTF`) and `TRACE_MODULE()` for verbose or repetitive output. See `doc/testing.md` for the guard list and usage pattern.
- **Memory Management:** Be extremely mindful of scarce memory. Global context data should be strictly necessary.
- **Stack Discipline:** Ledger targets, especially Nano X, are sensitive to stack pressure. Use `__noinline_due_to_stack__` from `src/utils/utils.h` for helpers with large local buffers or helpers that commonly compose into stack-heavy call chains, particularly in address derivation / formatting and transaction parsing / formatting paths. Put the attribute on its own line immediately above the function declaration / definition. Prefer this over adding temporary global scratch buffers unless there is a stronger architectural reason.
- **Temporary Buffers:** For short-lived byte buffers in tx/UI code, a tiny local helper such as `alloc_temp_buffer_or_fail()` using `APP_MEM_CALLOC`/`APP_MEM_FREE_AND_NULL` is acceptable when the allocation/free stay tightly scoped and improve stack usage.
- **Imports:** Organize imports logically and avoid forward declarations.
- **Use cheap fast model for subagents:** When spawning agents for simple tasks (searching codebases, gathering context, reading files, repetitive straightforward small-scope changes), prefer cheaper/faster models (e.g. Haiku, Gemini Flash, DeepSeek Flash, GPT-5.4-mini) to save context and cost on the main model thread. Reserve the main model for reasoning-heavy tasks.

### When the Model Makes a Mistake

If you make a wrong decision, take a wrong approach, or the user has to stop and redirect you, append a 1–2 sentence note to a `## Lessons Learned` section at the bottom of this file summarizing: (1) what the mistake was, and (2) the correct behavior going forward. Keep entries terse and actionable — the goal is to prevent repeating the same error.

### What NOT to DO
- **Do NOT modify `src/transaction/tx_hash_builder.c` or `src/addressUtils/bip44.c`** without explicit confirmation. They are trusted components.
- **Do NOT add custom CBOR serialization**, address manipulation, or BIP44 path functions. Use existing utilities.
- **Do NOT remove original comments** explaining crucial details without confirmation.
- **Do NOT perform git write operations** (modifications/writes). Read-only commands like `git diff` are allowed.
- **Do NOT install anything**.
- **Do NOT add extended-length APDU support.** This app uses short-form APDUs only (5-byte header, Lc ≤ 255). Do not modify `tests/unit/generators/common.py::extract_apdu_payload()` or any parser/generator to handle the extended-length case.
- **Do NOT generate golden snapshots** (`--golden_run` flag or equivalent). Golden snapshots must be reviewed and approved by a human before being committed. If a snapshot test fails, report the mismatch and stop.

### License Comment Policy
- **Preserve attribution:** Apache-2.0 requires preserving copyright/attribution notices from upstream code.
- **Do not imply false authorship:** If code is Ledger-derived, keep Ledger as original work.
- **Use file-by-file classification:**
  - **Vacuumlabs-only:** files created in this repo (Cardano-specific original work) use Vacuumlabs copyright.
  - **Copied from upstream Ledger code (unmodified):** keep original upstream copyright/license header.
  - **Copied + modified:** keep original upstream attribution and add Vacuumlabs in a separate `Modifications` block.
  - **Copied from old app (`../app-cardano`):** treat as Vacuumlabs-only unless there is evidence the specific part is Ledger-origin; ambiguous cases require confirmation.
- **Third-party code:** never replace third-party license blocks (e.g., ISC/MIT). Keep them intact; only append minimal modification note if needed.
- **Header text stability:** keep established file title wording when present (e.g., `Ledger App Cardano.`), change only ownership/license lines unless explicitly requested.
- **Ambiguous provenance:** do not auto-rewrite; prepare a numbered decision list for human confirmation first.
- **Repository-level notices:** keep `LICENSE.md` Apache-2.0; maintain a `NOTICE` file with third-party components and attributions when distributing.

## Instructions for Reviewing Agent

- **Review Scope:** A review should identify bugs, regressions, security issues, and concrete opportunities for improvement; do not spend review output describing what the code does unless that explanation is needed to justify a finding.
- **Security focus:** Be thorough and paranoid about security and correctness. Unless a security policy allows HIDE, all data must be displayed or confirmed by human app users.
- **Verification:** Ensure that every received BIP44 path is validated against `securityPolicy.c` (typically applies to other incoming data too, e.g. tx body elements).
- **Consistency:** Verify that new handlers are consistent with existing ones.
- **Memory Safety:** Check for potential memory leaks, overflows, or excessive stack usage.
- **UI Logic:** Ensure that UI display items follow the order of items in the transaction body and display format/encoding is consistent with old app.
- **Instruction Interleaving:** Confirm that handlers correctly guard against instruction interleaving attacks.
- **Review Baseline:** Treat [doc/non_bugs.md](doc/non_bugs.md) as a maintained list of known non-issues and intentional tradeoffs; do not re-report listed items as bugs.

## Coverage Hygiene

- Use `LCOV_EXCL_LINE` for invariant-only branches that cannot occur through supported app flow:
  - exhaustive `default` branches over validated enum domains,
  - defensive invariants after earlier guard/parse checks,
  - impossible transition paths between request/state-machine steps.
- For these invariants:
  - keep the branch as `LEDGER_ASSERT(...)` (or `ASSERT(...)`) and append `// LCOV_EXCL_LINE`.
  - for two-line `if (cond) { ... } else { LEDGER_ASSERT(false, ...); }` patterns, prefer two single-line `// LCOV_EXCL_LINE` comments on the assert and the unreachable fallback/return.
- Do **not** use LCOV exclusions for realistic malformed-input flow, parser-failure paths, or policy outcomes that can be exercised with valid APDU scenarios.
- If a branch can be covered from a bad APDU / bad Tx / bad buffer path with concrete fixtures, do not exclude it; add a unit test.
- Prefer per-line marks (`// LCOV_EXCL_LINE`) for small branches. However, for `default:` switch cases, you **must** use `LCOV_EXCL_START/STOP` around the entire block (including the `default:` label) because `lcov` will otherwise flag the `default:` keyword itself as uncovered. Use `LCOV_EXCL_START/STOP` only when a contiguous block is truly all structural invariants or for these `default:` cases.

## Additional Resources
- **BOLOS SDK:** `/opt/ledger-secure-sdk` (underlying library).
- **Reference Apps:** `../../ledger/app-ethereum` (eth app) and `../../ledger/app-bitcoin-new` (btc app) for modern coding patterns.
- **Client Libraries:** `../ledgerjs-cardano-shelley` and `../cardano-hw-interop-lib`.
- **Testing:**
    - [doc/testing.md](doc/testing.md): Testing entry point and workflow.
    - [tests/unit/README.md](tests/unit/README.md): Unit tests setup, build, and fixture management.
    - [tests/standalone/README.md](tests/standalone/README.md): Ragger standalone tests.
    - [tests/swap/README.md](tests/swap/README.md): Swap/library-mode tests.
    - [tests/fuzzing/FUZZING.md](tests/fuzzing/FUZZING.md): Fuzzing harnesses and usage.

## Testing Workflow

The detailed testing workflow, including environment setup and specific commands, is documented in **[doc/testing.md](doc/testing.md)**.

Brief summary:
- **Python venv**: `tests/venv` — activate with `source tests/venv/bin/activate` before running any Python tooling.
- **Unit tests**: `make -C tests tests-unit` (run when C code changes — regenerates fixtures, checks drift, builds, and runs). Use `make -C tests/unit` to build and run only, without fixture regeneration.
- **Fuzzing**: Extra compile-health gate after unit tests.
- **Fixture generation**: `PYTHONPATH=. tests/venv/bin/python -m tests.unit.generators.generate_unit_tests_from_ragger all` (run when ragger inputs change).
- **Linting**: `source tests/venv/bin/activate && ruff check --fix . --exclude tests/venv` (run when Python code changes).
- **Ragger/Swap tests**: Run only on explicit request.
- **Strictness**: Compilation warnings and lint errors are treated as failures.
- **No leniency for expected outputs:** if a happy-path fixture is missing unit-side
  expected results, treat it as an error. Do not omit the fixture, do not leave
  generated success fixtures with null expected outputs unnoticed, and do not skip
  assertions at runtime for that reason.

## Lessons Learned

- 2026-05-08: When a body-processing failure shows a `tx_handle_parse_error` with an exact SWO, cross-reference `cardano_swo.h` first to identify the error category before searching code paths.

<!-- Append 1–2 sentence notes here when the model makes a mistake that should be avoided in the future. Format: date, brief description of mistake, and the correct behavior. -->
