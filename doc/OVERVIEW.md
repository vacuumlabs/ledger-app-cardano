# Cardano Ledger App Architecture Overview

This document provides a high-level overview of the Cardano Ledger application architecture, data flow, and testing infrastructure.

## 1. C Application Architecture (`src/`)

The application is written in C and runs on Ledger devices (Stax, Flex, Nano X, Nano S+).
*Note: Nano S is no longer supported.*

### Core Components
- **`app_main.c`**: Entry point. Contains the main loop that initializes the device, shows the main menu, and waits for APDU commands.
- **`apdu/dispatcher.c`**: Maps APDU instructions (`INS_*`) to their respective handlers. It also protects against instruction interleaving attacks.
- **`handler/`**: Contains logic for specific commands.
    - `get_public_key.c`: Exports public keys.
    - `sign_tx.c`: Coordinates the multi-stage transaction signing process.
    - `sign_tx_aux_data.c`: Handles CIP-36 Catalyst voting registration data embedded in transaction auxiliary data.
    - `sign_opcert.c`: Handles operational certificate signing.
    - `sign_msg.c`: CIP8 message signing.
    - `sign_cvote.c`: Catalyst voting (ballot signing).
    - `derive_address.c`: Address derivation and display.
    - `derive_native_script_hash.c`: Native script hash derivation.
    - Other utility handlers: `get_version.c`, `get_app_name.c`, `get_serial.c`, `debug_settings.c` (debug builds only).
- **`transaction/`**: Core transaction processing logic using a 2-phase architecture:
    - **Phase 1** (`tx_processing.c`, `tx_processing_outputs.c`, `tx_processing_certificates.c` with `tx_hash_builder.c`): Validates transaction structure, enforces security policies, computes the Blake2b-256 transaction hash, and counts required UI display pairs.
    - **Phase 2** (`src/ui/ui_display_tx.c` orchestrates; rendering logic in `src/transaction/tx_ui_render.c`, `tx_ui_render_outputs.c`, `tx_ui_render_certificates.c`): Formats validated transaction data into human-readable strings for NBGL UI display.
    - Also includes parsing (`tx_parse.c`, `tx_parse_outputs.c`, `tx_parse_certificates.c`) and utility functions (`tx_utils.c`).
    - Detailed documentation can be found in [tx.md](tx.md).
- **`ui/`**: User interface components using NBGL framework.
    - `ui_formatters.c`: Low-level formatting functions for addresses, amounts, tokens.
    - Display modules for different operations: `ui_display_tx.c`, `ui_display_pubkey.c`, `ui_display_opcert.c`, `ui_display_cvote_aux_data.c`, `ui_display_native_script_hash.c`, `ui_display_address_derivation.c`, `ui_display_witness.c`, `ui_sign_msg.c`.
    - `ui_warnings.c`: Warning display logic.
    - `menu.c`: Main menu UI.
    - **UI callback convention**: Review callbacks should follow `cleanup -> finalize -> status`.
      - Cleanup must always call `ui_all_cleanup()` to keep handlers robust if warnings are added later.
      - Finalization should be delegated to handler-level `finalize_*()` functions rather than performing APDU response/state reset inline in UI modules.
- **`securityPolicy/`**: Enforces security rules for every operation, especially validating BIP44 paths and ensuring that transaction components are safe to sign.
- **`addressUtils/`**: Utilities for Cardano address manipulation (Shelley, Byron, Bech32).
- **`cvote/`**: Catalyst voting infrastructure.
    - `cvote_parser.c`, `cvote_hash.c`: Voting data parsing and hashing.
    - `vote_cast_hash_builder.c`, `aux_data_hash_builder.c`: Hash builders for voting structures.
- **`messageSigning/`**: CIP8 message signing implementation (`messageSigning.c`).
- **`deriveNativeScriptHash/`**: Native script hash derivation logic (`derive_native_script_hash_builder.c`).
- **`opcert/`**: Operational certificate parsing (`opcert_parse.c`).
- **`crypto/`**: Cryptographic operations and key derivation.
- **`keyDerivation/`**: BIP32/BIP44 key derivation logic.
- **`cardano_tokens/`**: Token registry for native token metadata.
- **`parsers/`**: Generic parsing utilities for CBOR and other formats.
- **`utils/`**: Helper utilities (`textUtils`, `cbor`, `buffer_write`, `ipUtils`, `assert`, `mem.c` allocator).

### Stack Usage Discipline

Ledger targets have materially different stack limits, and Nano X is tight enough that otherwise-correct code can corrupt adjacent state when multiple stack-heavy helpers get inlined into one call chain.

- Use `__noinline_due_to_stack__` from `src/utils/utils.h` on helpers that keep large local buffers or are common stack-pressure concentrators, especially address derivation / address formatting helpers and transaction-output parsing / formatting helpers.
- Put `__noinline_due_to_stack__` on a separate line immediately above the function declaration / definition.
- Treat this as a correctness requirement, not a style preference: if a function gains a substantial local array or starts composing other stack-heavy helpers, consider adding the attribute before investigating more invasive memory changes.
- Prefer this over introducing temporary global scratch buffers unless there is a stronger reason, because globals increase coupling and can hide the original stack-shape problem.
- For short-lived byte buffers in tx/UI paths, a tiny helper such as `alloc_temp_buffer_or_fail()` backed by `APP_MEM_CALLOC`/`APP_MEM_FREE_AND_NULL` is acceptable when it keeps stack pressure low and the allocation/free stay in the same function or helper-sized scope.

## 2. Security Policy System

**Critical Component:** The `securityPolicy/` module is the cornerstone of the app's security model. Every operation that uses cryptographic keys or displays transaction data must pass through security policy validation.

**Key Functions:**
- **BIP44 Path Validation**: `policyForPrivateKey()` validates every BIP44 path before key derivation. Ensures paths follow allowed patterns and enforces the single-account constraint.
- **Transaction Element Policies**: During transaction validation, each element (output, certificate, withdrawal, etc.) is checked via `policyFor*()` functions (e.g., `policyForOutput()`, `policyForCertificate()`).
- **Policy Decisions**:
  - `POLICY_DENY`: Deny immediately (security risk).
  - `POLICY_SHOW`: Display to user (increment UI pair count).
  - `POLICY_HIDE`: Don't display (only allowed when safe, e.g., change outputs).

**Enforced Constraints:**
- Single-account: All witness paths in a transaction must use the same BIP44 account.
- Credential restrictions: Script hashes forbidden in ordinary signing mode (prevents deception attacks).
- Signing mode restrictions: Certificate types allowed depend on the signing mode; see the `txSigningMode` table in `doc/apdu_reference.md` for the current list of modes.
- Address ownership: Change outputs and collateral returns must use device-owned addresses.

Security policies are the gatekeeper that prevents the device from signing transactions that could deceive the user or result in loss of funds. See `doc/spec_*.md` for detailed rationale behind specific policy decisions.

## 3. Transaction Signing Data Flow

Detailed data flow and transaction-specific logic are documented in [tx.md](tx.md).

## 4. APDU Reference

For a compact command/flow reference and links to APDU source-of-truth headers, see [apdu.md](apdu.md).

## 5. Testing Infrastructure

The application uses a multi-layered testing approach to ensure correctness and security. Detailed documentation for the testing setup and workflows can be found in **[testing.md](testing.md)**.

### Testing Layers
- **Unit Tests (`tests/unit/`)**: C unit tests (using `cmocka`) for individual modules.
- **Functional Tests (`tests/standalone/`)**: End-to-end Python tests (using `ragger` and `speculos`) that simulate device UI.
- **Swap Tests (`tests/swap/`)**: Specialized tests for exchange/swap library mode.
- **Fuzzing (`tests/fuzzing/`)**: libFuzzer-based security testing for critical parsers and handlers.

For specific instructions on running tests and managing fixtures, refer to the following:
- [doc/testing.md](testing.md): Main testing entry point and shared workflow.
- [tests/unit/README.md](../tests/unit/README.md): Unit test build and fixture generation details.
- [tests/standalone/README.md](../tests/standalone/README.md): Ragger functional test usage.
- [tests/fuzzing/FUZZING.md](../tests/fuzzing/FUZZING.md): Fuzzing harness details.

## 6. Generic Helpers

- **`LEDGER_ASSERT`** (`ledger_assert.h` / `utils/assert.h`): Assertion macros for parameter validation and invariant checking. Use liberally for all non-trivial functions that perform actual work on objects (not in simple pass-through helpers). Assertions document preconditions and catch logic errors early.

- **`buffer_t`** (SDK's `buffer.h`): Read-only buffer structure with const pointer. Used for safe APDU parsing and reading data. Provides bounds-checked operations like `buffer_read_u8()`, `buffer_read_u32()`, etc.

- **`write_buffer_t`** (`utils/buffer_write.h`): Write buffer structure with mutable pointer. Used for serializing data and building responses. Provides bounds-checked write operations.

- **Streaming parsing**: Transaction components are processed one item at a time directly from the raw transaction buffer. The app does not materialize full transaction body lists in memory.

- **`mem.h`**: Dynamic memory allocator optimized for Ledger device constraints (`app_mem_alloc`).

## 6.1. Debugging and Tracing

**TRACE macro** (`utils/utils.h`): Use for debug output during development.

- In release builds (no `HAVE_PRINTF`), all `TRACE()` calls compile to no-op, incurring **zero overhead**.
- In debug builds, TRACE strings become part of the binary and consume memory.
- **Best practice**: Use **conditional tracing guards** for verbose/repetitive debug output:

```c
// In your module header or at top of .c file:
#ifdef TRACE_MY_MODULE
#define TRACE_MODULE(...) TRACE(__VA_ARGS__)
#else
#define TRACE_MODULE(...) // Empty - compiled out
#endif

// In code:
TRACE_MODULE("Verbose state tracking: state=%d", state);  // Compiled out unless -DTRACE_MY_MODULE
TRACE("Critical error detected: %d", error);              // Always compiled in debug builds
```

This pattern is already used in hash builders (`TRACE_TX_HASH_BUILDER`, `TRACE_VOTECAST_HASH_BUILDER`, etc.).

**Reserved guard names for common modules:**
- `TRACE_TX_PARSE` - Transaction parsing (certificates, outputs)
- `TRACE_UI_DISPLAY` - UI rendering modules
- `TRACE_HANDLERS` - Command handlers
- `TRACE_CVOTE` - Voting module

See `doc/testing.md` for memory footprint analysis and recommendations.

## 7. Security

Apart from avoiding memory leaks and bugs in general, the security of the app has two main pillars:

1. Users must be shown everything important that is included in the transaction. There are very few exceptions where something is hidden, typically when the data cannot be verified by a human (inline datum) and are too long (in which case the error rate of human verification on a small screen mostly defeats the purpose of showing it), or when it is safe to hide data because user will not lose control of his assets (e.g. change outputs).

2. Data being displayed should not allow "attacks by deception", e.g. including several elements in the transaction that are signed by the same key, and tricking the user into overlooking some of them (most users are not aware of most security implications, so a compromised software wallet has a good chance of deceiving them). This means some combinations of elements are forbidden (e.g. key hash certificates in ordinary transaction signing mode because the user cannot easily determine if the key hash in the certificate comes from some of his keys).

There is an "expert mode" setting (see `doc/expert_mode.xlsx`) that allows the user to somewhat control the amount of data being displayed. It is mostly relevant for Plutus transactions.

## Security Policy Documentation (`doc/spec_*.md`)

The reasoning behind specific security restrictions is the result of years of discussion among stakeholders (IOG, Intersect, Vacuumlabs, stake pool operators, wallet developers, power users, etc.). This historical context and decision rationale is documented in era/feature-specific files:

- **`spec_shelley.md`**: Base Shelley era rules (addresses, stake keys, delegation, certificates, withdrawals).
- **`spec_alonzo.md`**: Script support (Plutus v1, native scripts, script data hash).
- **`spec_babbage.md`**: Plutus v2, inline datums, reference scripts, reference inputs.
- **`spec_conway.md`**: Conway era features (DReps, constitutional committee, voting procedures, treasury, donation).
- **`spec_pool_registration.md`**: Stake pool signing modes (owner / operator / payer) and pool registration and retirement certificates.
- **`spec_multisig.md`**: Multisig/multi-account transaction validation rules.
- **`spec_single_account.md`**: Single account constraint explanation.
- **`spec_msg_signing.md`**: CIP8 message signing rules and restrictions.
- **`spec_cvote.md`**: Catalyst voting (cvote) restrictions and ballot signing.

These documents explain *why* certain combinations are forbidden, when data is hidden vs. shown, and how each era extended the app's capabilities. They serve as the authoritative source for understanding security policy decisions.

## Cryptographic Error Handling

Cryptographic operations in this app use **CX_ASSERT** rather than error checking. Crypto errors are unrecoverable:
broken device hardware, buggy crypto implementation, wrong usage of crypto API (app bug) etc.
**CX_CHECK** is appropriate if we need to wipe out some memory buffers before exiting (so that no attacker can read them).
