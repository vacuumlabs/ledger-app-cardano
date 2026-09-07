# Swap / Library Mode

This document describes how the Cardano app participates in a Ledger Exchange
("swap") operation: the SDK contract it implements, the end-to-end flow, every in-app
integration point, the security model, and how the feature is tested.

---

## Table of Contents

1. [Background and Scope](#1-background-and-scope)
   - 1.1 [What a Swap Is](#what-a-swap-is)
   - 1.2 [How Ledger Live Triggers a Swap](#how-ledger-live-triggers-a-swap)
   - 1.3 [Consequences for This App](#consequences-for-this-app)
   - 1.4 [Supported Scope](#supported-scope)
2. [Flow](#2-flow)
   - 2.1 [`CHECK_ADDRESS`](#21-check_address)
   - 2.2 [`GET_PRINTABLE_AMOUNT`](#22-get_printable_amount)
   - 2.3 [`SIGN_TRANSACTION` setup](#23-sign_transaction-setup)
   - 2.4 [APDU phase](#24-apdu-phase)
   - 2.5 [Return to Exchange](#25-return-to-exchange)
   - 2.6 [Rejection path](#26-rejection-path)
3. [SDK Contract (`lib_standard_app`)](#3-sdk-contract-lib_standard_app)
4. [File Inventory](#4-file-inventory)
5. [Security Model](#5-security-model)
   - 5.1 [Why `POLICY_HIDE` is legitimate here](#51-why-policy_hide-is-legitimate-here)
   - 5.2 [Init policy](#52-init-policy)
   - 5.3 [Output policy](#53-output-policy)
   - 5.4 [Witness policy](#54-witness-policy)
   - 5.5 [Error taxonomy](#55-error-taxonomy)
   - 5.6 [Nano X memory interaction](#56-nano-x-memory-interaction)
6. [Testing](#6-testing)
   - 6.1 [Unit tests (`tests/unit/`)](#61-unit-tests-testsunit)
   - 6.2 [Functional tests (`tests/swap/`)](#62-functional-tests-testsswap)
   - 6.3 [Fuzzing](#63-fuzzing)

---

## 1. Background and Scope

### What a Swap Is

A **swap** exchanges one crypto asset for another — ADA for ETH, say — through a
third-party exchange partner (Changelly, ChangeNOW, …), brokered by Ledger Live. The
user does not send funds to the partner blindly: the partner returns a *signed*
proposal naming the pay-in address, the pay-in amount, the refund address, the payout
address and the fee, and the device verifies that signature and has the user confirm
those values before any coin app signs anything. What the user approved and what the
signed transaction actually moves must be identical.

Ledger's Exchange protocol covers three operations — `SWAP` (crypto for crypto),
`SELL` (crypto for fiat) and `FUND` (crypto into a Ledger-partner account) — plus
their `_NG` variants. They differ in which addresses Exchange checks, not in what the
coin app does; from the Cardano app's side all three look the same, and this document
says "swap" for all of them.

Three parties are involved:

- **Ledger Live** (desktop or mobile) is the host. It requests the quote from the
  partner backend, drives every APDU, and finally broadcasts the signed transaction to
  the Cardano network. It is transport, not a trust anchor — the whole protocol is
  designed on the assumption that a compromised host may lie about anything.
- **The Exchange app** (`app-exchange`) is a separate embedded app on the device and
  *is* the trust anchor. It enrols the partner's public key against a Ledger
  signature, verifies the partner's signature over the proposal, owns the screen for
  the user's confirmation, and calls coin apps as libraries via `os_lib_call()`.
- **The Cardano app** runs as that library. It answers two questions for Exchange
  (is this address mine? how do I print this amount?), then signs the payment
  transaction — with no UI of its own at any point.

> **`os_lib_call()`.** A BOLOS syscall (`os_lib.h:14`), not a function call: it asks
> the OS to start another *installed* application as a library of the caller, which
> is the only way one embedded app can invoke another — no host involvement. Its
> argument is a flat array: `[0]` the library application's name, `[1]` a call
> identifier (Exchange uses `0x100`), `[2+]` the arguments. The OS suspends the
> caller and starts the callee's `main()` with that block as `arg0`, which the SDK
> reads as a `libargs_t *`; the library returns control with `os_lib_end()`. There
> is no return value — results are written straight into the parameter struct, which
> lives in Exchange's memory.

### How Ledger Live Triggers a Swap

The user picks *Swap* in Ledger Live, selects source and target accounts and a
provider, and accepts a quote. Ledger Live opens the Exchange app on the device and
runs the sequence below (Exchange CLA `0xE0`; command values from `ExchangeClient` in
the Exchange Python client, and the ordering from its `_perform_valid_exchange()`,
which is exactly what [`tests/swap/test_cardano_swap.py`](../tests/swap/test_cardano_swap.py)
drives).

### Consequences for This App

Two constraints follow from this, and nearly every design decision in the swap code
traces back to one of them:

- **The Cardano app must not show any UI.** The screen belongs to Exchange. There is
  no transaction review, no witness confirmation, and no signing spinner. Every
  security policy in the swap flow therefore resolves to `POLICY_HIDE` or
  `POLICY_DENY`, never `POLICY_SHOW`.
- **The Cardano app must verify that what it is asked to sign is exactly what
  Exchange showed the user.** The user consented to one destination, one amount and
  one fee. Anything else in the transaction body is a potential hidden value transfer
  and is rejected outright.

Swap support is compiled in by default: `ENABLE_SWAP = 1` in
[`Makefile`](../Makefile), which the SDK translates into the `HAVE_SWAP` define. All
swap code is guarded by `#ifdef HAVE_SWAP`.

### Supported Scope

The swap flow is deliberately much narrower than the app's normal signing surface:

| Dimension       | Supported |
|-----------------|-----------|
| Network         | **Mainnet only.** Hardcoded `MAINNET_NETWORK_ID` in the address check; mainnet network id **and** protocol magic enforced by policy. See [`doc/non_bugs.md`](non_bugs.md). |
| Address era     | **Shelley only.** Enforced by a `bip44_hasShelleyPrefix()` guard, which requires a hardened `1852'` purpose and the ADA `1815'` coin type; Byron (`44'`) is rejected (`swap_check_address.c:50-57`). |
| Assets          | **Native ADA only.** Multi-asset outputs are denied; there is no token-ticker configuration parsing. |
| Signing mode    | `SIGN_TX_SIGNINGMODE_ORDINARY` only. |
| Outputs         | Exactly **one** third-party output (the swap destination). Remaining outputs must be device-owned change that the normal output policy already hides. |
| Witnesses       | Exactly **one**, and it must be an ordinary payment key path. |
| Tx body features | No certificates, withdrawals, auxiliary data, minting, Plutus data, collateral, required signers, reference inputs, governance voters, treasury or donation. |

---

## 2. Flow

```
 Ledger Live            Exchange app                 Cardano app (library)
      |                      |                                 |
      |--- swap proposal --->|                                 |
      |                      | verify partner signature        |
      |                      | user confirms dest/amount/fee   |
      |                      |                                 |
      |                      |== os_lib_call CHECK_ADDRESS ====>|  refund address
      |                      |   (Exchange CRC-guards its BSS) |  belongs to device?
      |                      |<---- params->result = 0/1 ======|  os_lib_end()
      |                      |                                 |
      |                      |== os_lib_call GET_PRINTABLE ===>|  format lovelace
      |                      |   _AMOUNT                       |  as "N.NNNNNN ADA"
      |                      |<---- printable_amount ==========|  os_lib_end()
      |                      |                                 |
      |                      |== os_lib_call SIGN_TRANSACTION =>|  swap_copy_transaction
      |                      |   (BSS guard deliberately off)   |  _parameters():
      |                      |                                 |    stack copy
      |                      |         [Exchange suspended]     |    zero BSS
      |                      |                                 |    commit to global
      |                      |                                 |  SDK sets globals,
      |                      |                                 |  runs app_main()
      |                      |                                 |
      |--------- INS_SIGN_TX P1_TX_INIT ---------------------->|  init policy
      |<-------- SWO_SUCCESS ---------------------------------|
      |--------- P1_TX_CHUNK (body) --------------------------->|  fee / output /
      |<-------- SWO_SUCCESS ---------------------------------|  donation checks
      |--------- P1_TX_CONFIRM -------------------------------->|  UI review SKIPPED
      |<-------- tx hash (intermediate) ----------------------|
      |--------- P1_WITNESS ----------------------------------->|  witness policy
      |<-------- 64-byte signature ---------------------------|  G_swap_response
      |                      |                                 |  _ready = true
      |                      |<== os_lib_end() (from io.c) ====|  result written
      |                      |                                 |
      |<-- swap complete ----|
```

On any validation failure the app calls `swap_reject_and_exit()` instead, which sends
`0x6001` with the two detail bytes and never returns. Control lands back in Exchange,
which reports the failure to Ledger Live.

### 2.1 `CHECK_ADDRESS`

Exchange asks whether the refund address is really derived from a key on this device.
This prevents a malicious host from naming a refund address it controls.

[`swap_handle_check_address()`](../src/swap/swap_check_address.c#L14):

1. Sets `params->result = 0` first, so every early return is a rejection
   (`swap_check_address.c:22`).
2. Parses the derivation path from the packed wire format (one length byte followed by
   big-endian 4-byte components) using the existing `buffer_read_bip44_path()`, and
   rejects trailing bytes (`swap_check_address.c:36-48`).
3. Requires a Shelley path prefix via `bip44_hasShelleyPrefix()`, which checks both a
   hardened `1852'` purpose **and** the ADA `1815'` coin type — stricter than a bare
   purpose comparison (`swap_check_address.c:50-57`).
4. Builds a `BASE_PAYMENT_KEY_STAKE_KEY` address: payment key from the supplied path,
   staking key from the **same account** with `chain = 2` and `index = 0`, network id
   hardcoded to mainnet (`swap_check_address.c:59-76`). Two `LEDGER_ASSERT`s guard the
   path length and the resulting staking-path classification.
5. Derives, formats via `format_address_human_readable()`, and `strcmp`s against
   `params->address_to_check` (`swap_check_address.c:78-90`).
6. Sets `params->result = 1` only on an exact match (`swap_check_address.c:93`).

Byron (`44'`) and every other prefix are rejected at step 3. The check is a single early
guard rather than a `switch` on the purpose, so a path with the right purpose but a wrong
coin type is rejected too.

Exchange wraps this call (and `GET_PRINTABLE_AMOUNT`) in a CRC check over its own BSS
plus a stack canary: the callee must not disturb Exchange's memory. This callback
therefore uses only locals and touches no app globals.

### 2.2 `GET_PRINTABLE_AMOUNT`

[`swap_handle_get_printable_amount()`](../src/swap/swap_printable_amount.c#L13) zeroes
the output buffer, converts the decimal-string amount with the SDK's
`swap_str_to_u64()`, and formats it with the app's own `format_ada_amount()` (6
decimals plus an " ADA" suffix).

The SDK gives this callback no return value, so **the error convention is to leave
`printable_amount` an empty string** (`swap_printable_amount.c:11-12`). A failure of
`swap_str_to_u64()` is a legitimate outcome for malformed partner input; a failure of
`format_ada_amount()` on an already-parsed `uint64_t` is not, and asserts.

### 2.3 `SIGN_TRANSACTION` setup

[`swap_copy_transaction_parameters()`](../src/swap/swap_lib.c#L48) first rejects a
non-empty `destination_address_extra_id` (`swap_lib.c:53-61`). Cardano has no
memo/extra-id concept, so a populated field means the caller believes it is talking to
a different chain.

It then performs the mandatory three-step copy (`swap_lib.c:63-103`):

1. **Copy into a stack-local `swap_validated_t`.** The incoming
   `create_transaction_parameters_t` may physically overlap the app's own BSS:
   Exchange allocated it in its own memory, and the two apps' segments are not
   disjoint. Writing straight into a global could clobber the source mid-copy.
2. **`os_explicit_zero_BSS_segment()`** (`swap_lib.c:100`). BSS is **not** zeroed when
   an app is launched as a library, yet the whole codebase assumes zero-initialized
   globals. This call also removes any residue of Exchange's data from the app's
   memory.
3. **`memcpy` the stack copy into `G_swap_validated`** (`swap_lib.c:103`). After step 2
   the `params` pointer is tainted and is never read again.

Amount and fee are parsed with `swap_str_to_u64()`; the destination is copied with
`strlcpy` into a `MAX_HUMAN_ADDRESS_LENGTH` buffer with an explicit truncation check.
`initialized = true` is set on the stack copy **before** the commit, so the flag and
the data it guards become visible atomically.

Returning `false` from here aborts the swap before `G_called_from_swap` is ever set.

### 2.4 APDU phase

Exchange is now suspended and Ledger Live talks to the Cardano app directly. Only four
instructions are reachable
([`dispatcher.c:142-151`](../src/apdu/dispatcher.c#L142)); everything else terminates
the swap with `SWAP_APP_CODE_BAD_INS`.

`INS_SIGN_TX` proceeds as normal, with these differences:

- **`P1_TX_INIT`**: rejects a second signing attempt (`SWAP_APP_CODE_MULTI_SIGN`),
  clears `G_swap_response_ready`, requires `num_witnesses == 1`, and applies
  `policyForSignTxSwapInit()` instead of `policyForSignTxInit()`. No spinner.
- **`P1_TX_CHUNK`**: the body is parsed and hashed as usual, but three extra checks
  fire during validation. The fee must equal the Exchange-approved fee. Each output
  must satisfy `policyForSignTxSwapOutput()`, and the single third-party output must
  match the approved destination **and** amount. A donation is rejected outright.
  After the output loop, `swap_third_party_output_count` must be exactly 1.
- **`P1_TX_CONFIRM`**: there is no interactive review, so the handler frees `raw_tx`,
  jumps from `TX_STATE_HASHED` straight to `TX_STATE_APPROVED`, and returns the
  transaction hash. This response is **intermediate**: `G_swap_response_ready` is still
  `false`, so the SDK does not return to Exchange.
- **`P1_WITNESS`**: `policyForSignTxWitness()` is called with `isSwap = true`. Because
  there is exactly one witness, that witness is also the last one.

### 2.5 Return to Exchange

Immediately before the final witness signature is transmitted,
[`sign_tx.c:655-663`](../src/handler/sign_tx.c#L655) sets
`G_swap_response_ready = true`. The SDK's IO path (`io.c:142-152`) sees the flag,
writes `(sw == SWO_SUCCESS)` into Exchange's `result` field, and calls `os_lib_end()`.
Execution does not come back, which is why the
`LEDGER_ASSERT(!G_called_from_swap, ...)` after that point
([`sign_tx.c:782-785`](../src/handler/sign_tx.c#L782)) would fire if the control-flow
assumption ever broke.

The app must never call `app_exit()` here. That would drop the user to the dashboard
with Exchange's swap left unfinished.

### 2.6 Rejection path

[`swap_reject_and_exit()`](../src/swap/swap_lib.c#L40) calls the SDK's
`send_swap_error_simple(SWO_SWAP_CHECKING_FAIL, common_code, app_code)`, which is
NORETURN. The trailing `LEDGER_ASSERT(false, ...)` documents that and keeps the
contract explicit at every call site even if the SDK annotation regresses.

---

## 3. SDK Contract (`lib_standard_app`)

The swap protocol lives in the BOLOS SDK, not in this repository. The app supplies
three callbacks and reads three globals; the SDK owns `main()`, the command dispatch
and the return path back to Exchange.

> **Note on paths.** The SDK is not checked out on the host filesystem. It exists only
> inside the Ledger dev-tools container, as one tree per target:
> `/opt/{ledger,flex,stax,nanox,nanosplus,apex}-secure-sdk`. To read these files:
>
> ```bash
> docker exec ledger-app-cardano-container \
>     grep -n 'library_app_main' /opt/flex-secure-sdk/lib_standard_app/main.c
> ```
>
> Line references below were taken from `/opt/flex-secure-sdk/lib_standard_app` and
> may drift when the SDK is bumped.

### Commands

Exchange selects one of four library commands (`swap_lib_calls.h:19-22`):

| Value | Command                | Used by this app |
|-------|------------------------|------------------|
| 1     | `RUN_APPLICATION`      | No. This is the "start me as a full app, not a library" command used by Ethereum clones and plugins; Exchange never sends it in a swap. |
| 2     | `SIGN_TRANSACTION`     | Yes |
| 3     | `CHECK_ADDRESS`        | Yes |
| 4     | `GET_PRINTABLE_AMOUNT` | Yes |

Which of these commands the app receives depends on whether ADA is the source or the
destination currency of the swap; whichever ones it does receive always arrive in the
same order. As the destination currency, the app gets `CHECK_ADDRESS` followed by
`GET_PRINTABLE_AMOUNT` for the payout address, and nothing more. As the source
currency, it gets that same pair for the refund address and then `SIGN_TRANSACTION`
— the sequence drawn in [2](#2-flow). Each command is a separate library launch
ending in `os_lib_end()`, so the app carries no state between them and must not
assume a preceding call happened.

### Structures and Globals

| Item | Location |
|------|----------|
| `check_address_parameters_t` | `swap_lib_calls.h:36-58` |
| `get_printable_amount_parameters_t` | `swap_lib_calls.h:63-80` |
| `create_transaction_parameters_t` | `swap_lib_calls.h:85-113` |
| `libargs_t` (`id`, `command`, `unused`, union of the three parameter pointers) | `swap_lib_calls.h:119-128` |
| `MAX_PRINTABLE_AMOUNT_SIZE` (50) | `swap_lib_calls.h:32` |
| `G_called_from_swap` | `swap_utils.h:23` |
| `G_swap_response_ready` | `swap_utils.h:27` |
| `G_swap_signing_return_value_address` | `swap_utils.h:31` |
| `swap_str_to_u64()` | `swap_utils.h:33` |
| `swap_parse_config()` (token tickers, unused here) | `swap_utils.h:34` |
| `swap_handle_check_address()` declaration | `swap_entrypoints.h:64` |
| `swap_handle_get_printable_amount()` declaration | `swap_entrypoints.h:79` |
| `swap_copy_transaction_parameters()` declaration | `swap_entrypoints.h:93` |
| `swap_error_common_code_t` | `swap_error_code_helpers.h:61-71` |
| `send_swap_error_simple()` (NORETURN) | `swap_error_code_helpers.h:81` |
| `ENABLE_SWAP=1` -> `DEFINES += HAVE_SWAP` | `Makefile.standard_app` |

The `result` field of `create_transaction_parameters_t` is **owned by the SDK**. The
app never writes it; the SDK's IO path writes the success flag through
`G_swap_signing_return_value_address` on the way out.

### SDK Entry and Exit

`main(int arg0)` (`main.c:167-193`) branches on its argument:

- `arg0 == 0`: launched from the dashboard. `standalone_app_main()` clears the three
  swap globals and runs the normal app.
- `arg0 != 0`: launched as a library. `arg0` is a `libargs_t *`; the SDK checks
  `args->id == 0x100` and calls `library_app_main(args)`, otherwise `app_exit()`.

`library_app_main()` (`main.c:113-163`) dispatches on `args->command` and wraps the
whole switch in `BEGIN_TRY` / `FINALLY { os_lib_end(); }` (`main.c:159`). Every path
that returns from a handler therefore returns control to Exchange automatically.

The `SIGN_TRANSACTION` case is different, because signing does not return from a
handler; it runs the app's entire APDU loop. The SDK:

1. calls `swap_copy_transaction_parameters(args->create_transaction)`;
2. on success sets `G_called_from_swap = true`, `G_swap_response_ready = false`, and
   stashes `G_swap_signing_return_value_address = &args->create_transaction->result`;
3. calls `common_app_init()`, then `nbgl_useCaseSpinner("Signing")`, then `app_main()`.

Exit happens from inside the IO layer instead (`io.c:142-152`): when a response is
being transmitted and `G_called_from_swap && G_swap_response_ready` are both set, the
SDK writes `*G_swap_signing_return_value_address = (sw == SWO_SUCCESS)` and calls
`os_lib_end()`.

**Two consequences:** `G_swap_response_ready` must be set **before** the final
response is sent, and the app must never call `app_exit()` in swap mode.

### Error Reporting

Swap errors are reported with a status word plus two bytes of detail: an SDK-defined
"common" code (`swap_error_code_helpers.h:61-71`) and an app-defined code. Exchange
surfaces both, which is what makes a failed swap diagnosable.

Common codes: `SWAP_EC_ERROR_INTERNAL` (0x00), `SWAP_EC_ERROR_WRONG_AMOUNT` (0x01),
`SWAP_EC_ERROR_WRONG_DESTINATION` (0x02), `SWAP_EC_ERROR_WRONG_FEES` (0x03),
`SWAP_EC_ERROR_WRONG_METHOD` (0x04), `SWAP_EC_ERROR_CROSSCHAIN_WRONG_MODE` (0x05),
`SWAP_EC_ERROR_CROSSCHAIN_WRONG_METHOD` (0x06),
`SWAP_EC_ERROR_CROSSCHAIN_WRONG_HASH` (0x07), `SWAP_EC_ERROR_GENERIC` (0xFF). The
three cross-chain codes are unused by this app.

---

## 4. File Inventory

### Core Module (`src/swap/`)

Every file is wrapped in `#ifdef HAVE_SWAP`, so a build without swap support compiles
them to empty translation units.

- [`swap_lib.h`](../src/swap/swap_lib.h): the module's public API, the app-specific
  error codes `SWAP_APP_CODE_DEFAULT` / `_BAD_INS` / `_MULTI_SIGN` /
  `_DENIED_WITNESS_POLICY` (`swap_lib.h:16-19`), and `SWO_SWAP_CHECKING_FAIL 0x6001`
  (`swap_lib.h:22`).
- [`swap_lib.c`](../src/swap/swap_lib.c): owns the swap-validated state and all
  comparison checks. Module tracing is available via `-DTRACE_SWAP`
  (`swap_lib.c:21-25`).

  | Symbol | Line | Purpose |
  |--------|------|---------|
  | `swap_validated_t` / `G_swap_validated` | `27-34` | `initialized`, `amount`, `fee`, `destination[MAX_HUMAN_ADDRESS_LENGTH]` |
  | `swap_transaction_params_initialized()` | `36` | Invariant probe used by asserts |
  | `swap_reject_and_exit()` | `40` | NORETURN wrapper over `send_swap_error_simple()` |
  | `swap_copy_transaction_parameters()` | `48` | SDK `SIGN_TRANSACTION` setup callback |
  | `swap_check_destination_validity()` | `108` | Formats the tx output address and compares it to the Exchange-approved destination |
  | `swap_check_amount_validity()` | `141` | Exact `uint64_t` compare |
  | `swap_check_fee_validity()` | `152` | Exact `uint64_t` compare |

- [`swap_check_address.c`](../src/swap/swap_check_address.c): the `CHECK_ADDRESS`
  callback, `swap_handle_check_address()` at `swap_check_address.c:14`.
- [`swap_printable_amount.c`](../src/swap/swap_printable_amount.c): the
  `GET_PRINTABLE_AMOUNT` callback, `swap_handle_get_printable_amount()` at
  `swap_printable_amount.c:13`.

There is no app-owned `main.c` or `libargs` dispatcher; the SDK's
`lib_standard_app/main.c` performs the dispatch.

### Integration Hooks

Every `#ifdef HAVE_SWAP` site outside `src/swap/` (include blocks omitted). Note that
grepping for the guard does not find everything: the swap policies in
[`securityPolicy.c`](../src/securityPolicy/securityPolicy.c) are unguarded and compile
into every build; they are described in [5.2](#52-init-policy)-[5.4](#54-witness-policy).

| Site | What it does |
|------|--------------|
| [`app_main.c:103-108`](../src/app_main.c#L103) | Suppresses `ui_menu_main()`. The screen belongs to Exchange. |
| [`apdu/dispatcher.c:142-151`](../src/apdu/dispatcher.c#L142) | Instruction allow-list: `INS_GET_VERSION`, `INS_GET_PUBLIC_KEY`, `INS_DERIVE_ADDRESS`, `INS_SIGN_TX`. Anything else -> `SWAP_EC_ERROR_WRONG_METHOD` / `SWAP_APP_CODE_BAD_INS`. |
| [`handler/sign_tx.c:306-312`](../src/handler/sign_tx.c#L306) | Requires exactly one witness. A host-supplied witness count above one would let the device sign extra inputs. |
| [`handler/sign_tx.c:371-381`](../src/handler/sign_tx.c#L371) | Runs `policyForSignTxSwapInit()` in place of the normal init policy. |
| [`handler/sign_tx.c:394-401`](../src/handler/sign_tx.c#L394) | Skips the signing spinner. |
| [`handler/sign_tx.c:492-503`](../src/handler/sign_tx.c#L492) | Double-sign guard: a second `P1_TX_INIT` after a completed swap signature aborts with `SWAP_APP_CODE_MULTI_SIGN`. Also resets `G_swap_response_ready = false`, because the tx hash is returned as an **intermediate** response and must not trigger `os_lib_end()`. |
| [`handler/sign_tx.c:559-574`](../src/handler/sign_tx.c#L559) | On `P1_TX_CONFIRM`: frees `raw_tx`, skips `TX_STATE_UI_REVIEW`, transitions straight to `TX_STATE_APPROVED`, and returns the transaction hash. `finalize_sign_tx()` is not used in this flow. |
| [`handler/sign_tx.c:655-663`](../src/handler/sign_tx.c#L655) | Sets `G_swap_response_ready = true` immediately before sending the **last** witness signature, so the SDK IO path returns to Exchange. |
| [`handler/sign_tx.c:739-745`](../src/handler/sign_tx.c#L739) | Passes `isSwap` into `policyForSignTxWitness()`. |
| [`handler/sign_tx.c:753-757`](../src/handler/sign_tx.c#L753) | Invariant: swap-validated parameters may only exist inside a swap invocation. |
| [`handler/sign_tx.c:763-767`](../src/handler/sign_tx.c#L763) | Witness policy denial -> `SWAP_APP_CODE_DENIED_WITNESS_POLICY`. |
| [`handler/sign_tx.c:782-785`](../src/handler/sign_tx.c#L782) | Invariant: the swap flow must have terminated before `finalize_witness()` returns. |
| [`transaction/tx_processing.c:376-380`](../src/transaction/tx_processing.c#L376) | Fee check against the Exchange-approved fee. |
| [`transaction/tx_processing.c:994-1001`](../src/transaction/tx_processing.c#L994) | Rejects any treasury donation; it is not part of the reviewed ADA amount. |
| [`transaction/tx_processing_outputs.c:118-142`](../src/transaction/tx_processing_outputs.c#L118) | Per-output `policyForSignTxSwapOutput()`, plus destination and amount checks for the third-party output, plus the third-party output counter. |
| [`transaction/tx_processing_outputs.c:483-487`](../src/transaction/tx_processing_outputs.c#L483) | Enforces exactly one third-party output after the output loop. |
| [`transaction/tx_processing.h:74`](../src/transaction/tx_processing.h#L74) | `swap_third_party_output_count` in `tx_processing_state_t`. |

### Build and CI Configuration

| File | Relevance |
|------|-----------|
| [`Makefile`](../Makefile) | `ENABLE_SWAP = 1`; `APP_SOURCE_PATH += src` pulls in `src/swap/*.c` |
| [`ledger_app.toml`](../ledger_app.toml) | `[pytest.swap] directory = "./tests/swap/"` |
| `.github/workflows/build_and_functional_tests.yml` | `tests_swap` job, via `ledger-app-workflows/.github/workflows/reusable_swap_tests.yml@v1` |
| `.github/workflows/python_client_checks.yml` | `lint_swap` job over `tests/swap` |
| [`tests/unit/CMakeLists.txt`](../tests/unit/CMakeLists.txt) | `src/swap` and SDK `lib_standard_app` include paths; the `cardano_sign_tx_core_swap` library built with `HAVE_SWAP` |
| [`tests/fuzzing/CMakeLists.txt`](../tests/fuzzing/CMakeLists.txt) | `set(DEFINES FUZZ HAVE_SWAP)`; all of `src/swap/*.c` is compiled into `code_lib`, and the swap harnesses are built like any other |
| [`.clusterfuzzlite/build.sh`](../.clusterfuzzlite/build.sh) | Builds the fuzzers for ClusterFuzzLite, zips `seeds/<fuzzer>/`, and copies `dict/cardano.dict` to `<fuzzer>.dict` |

---

## 5. Security Model

### 5.1 Why `POLICY_HIDE` is legitimate here

Everywhere else in this app, hiding transaction data from the user would be a security
defect. In swap mode it is correct, for exactly one reason: **Exchange has already
obtained the user's confirmation of the destination, the amount and the fee**, and the
app has independently verified that the transaction it is signing matches those three
values.

That precondition holds only because:

- the transaction shape is restricted so tightly that nothing else of value can be
  encoded in the body (no certificates, no minting, no donation, no datum, no
  multi-asset, no extra third-party output);
- the one third-party output's destination and amount, and the fee, are compared
  against the Exchange-approved values;
- change outputs must be ones the normal policy would already hide, so no unreviewed
  device-owned oddity slips through;
- exactly one witness is signed, on an ordinary payment path in the single allowed
  account.

Remove any one of those and `POLICY_HIDE` stops being safe. **This is not a pattern to
generalize to other flows.**

### 5.2 Init policy

[`policyForSignTxSwapInit()`](../src/securityPolicy/securityPolicy.c#L537) first
requires the normal init policy to pass, then adds: `SIGN_TX_SIGNINGMODE_ORDINARY`;
mainnet network id and mainnet protocol magic; at least one input and one output; and
zero of certificates, withdrawals, auxiliary data hash, mint asset groups, script data
hash, collateral inputs, required signers, collateral output, total collateral,
reference inputs, governance voters, treasury and donation. Result: `HIDE()`.

### 5.3 Output policy

[`policyForSignTxSwapOutput()`](../src/securityPolicy/securityPolicy.c#L913) requires
ordinary mode and mainnet, then delegates to `policyForSignTxOutput()` and denies if
that policy denies **or raises any warning bit at all**. In swap mode there is no UI in
which to show a warning, so a warning is a denial. It additionally denies
`numAssetGroups != 0`, `includeDatum` and `includeRefScript`.

By destination type:

- `DESTINATION_THIRD_PARTY` -> `HIDE()`. The caller then verifies destination and
  amount against the Exchange-approved values.
- `DESTINATION_DEVICE_OWNED` -> allowed only if the normal policy already returned
  `POLICY_HIDE`; change outputs must be unremarkable.

### 5.4 Witness policy

[`_swapWitnessPolicy()`](../src/securityPolicy/securityPolicy.c#L2664) requires
ordinary mode and accepts only `PATH_ORDINARY_PAYMENT_KEY`, additionally enforcing the
single-account invariant and `bip44_isPathReasonable()`. Everything else denies: pool
cold keys, staking keys, multisig, mint, governance/DRep paths, unusual indices.
`policyForSignTxWitness()` routes to it when `isSwap` is set.

### 5.5 Error taxonomy

| Common code | App code | Triggered by |
|-------------|----------|--------------|
| `WRONG_METHOD` | `BAD_INS` | Instruction outside the swap allow-list ([`dispatcher.c:148`](../src/apdu/dispatcher.c#L148)) |
| `GENERIC` | `MULTI_SIGN` | Second `P1_TX_INIT` after a completed swap signature ([`sign_tx.c:496`](../src/handler/sign_tx.c#L496)) |
| `GENERIC` | `DENIED_WITNESS_POLICY` | Witness policy denial ([`sign_tx.c:765`](../src/handler/sign_tx.c#L765)) |
| `GENERIC` | `DEFAULT` | `num_witnesses != 1` ([`sign_tx.c:310`](../src/handler/sign_tx.c#L310)); init policy denial ([`sign_tx.c:375`](../src/handler/sign_tx.c#L375)); output policy denial ([`tx_processing_outputs.c:129`](../src/transaction/tx_processing_outputs.c#L129)); donation present ([`tx_processing.c:999`](../src/transaction/tx_processing.c#L999)) |
| `WRONG_FEES` | `DEFAULT` | Fee mismatch ([`tx_processing.c:378`](../src/transaction/tx_processing.c#L378)) |
| `WRONG_DESTINATION` | `DEFAULT` | Destination mismatch ([`tx_processing_outputs.c:135`](../src/transaction/tx_processing_outputs.c#L135)); third-party output count != 1 ([`tx_processing_outputs.c:485`](../src/transaction/tx_processing_outputs.c#L485)) |
| `WRONG_AMOUNT` | `DEFAULT` | Amount mismatch ([`tx_processing_outputs.c:138`](../src/transaction/tx_processing_outputs.c#L138)) |

All of these carry status word `0x6001` (`SWO_SWAP_CHECKING_FAIL`); see also
[`doc/apdu_reference.md`](apdu_reference.md).

### 5.6 Nano X memory interaction

Library mode changes the stack/BSS layout in a way that has already produced a real
failure on Nano X (symptoms: `0x6e00`, `invalid CLA 215`, or the review UI appearing in
swap mode). That analysis (detection via `build/nanox/dbg/app.map`, the 22 KiB
`SIZE_MEM_BUFFER` mitigation, and the invariants to preserve) lives in
[`doc/tx_raw_buffer.md`](tx_raw_buffer.md#nano-x-stackbss-interaction-in-swap-library-mode)
and is not repeated here.

---

## 6. Testing

### 6.1 Unit tests (`tests/unit/`)

[`test_handler_sign_tx_swap.c`](../tests/unit/test_handler_sign_tx_swap.c) holds cmocka
cases in three groups:

- **Policy-only**: init policy accepts the plain-ADA shape and rejects required signers
  and unrestricted mode; output policy accepts plain device-owned change and rejects
  change carrying tokens or a datum.
- **Handler flow**: swap mode skips the UI and calls each exchange-parameter check
  exactly once; init rejects multiple witnesses, a policy denial, unrestricted mode,
  and double signing; a non-payment witness path is rejected; witness finalization
  triggers `os_lib_end()`.
- **Hand-built transaction bodies**: denials for donation, wrong fee, an output policy
  violation, wrong destination, wrong amount, and multiple third-party outputs, each
  asserting the expected common error code.

Mechanically, these tests override `abort()` and `longjmp` out of the SDK's
`os_lib_end()` so a NORETURN rejection can be observed and asserted.

[`test_swap_check_address.c`](../tests/unit/test_swap_check_address.c) tests the
**real** `swap_check_address.c` — it is the one swap source file linked
unstubbed into a unit test, with `HAVE_SWAP` set on the target:

- **Rejections**: `address_parameters == NULL`, `address_to_check == NULL`, a length byte
  claiming more components than the payload provides, trailing bytes after the path, a
  valid path against a non-matching address string, and a Byron (`44'`) prefix.
- **Acceptance**: `test_valid_shelley_match` re-derives the expected base address
  independently (same `BASE_PAYMENT_KEY_STAKE_KEY` / mainnet / `chain = 2, index = 0`
  construction) and asserts `params->result == 1`.

Every rejection case pre-sets `params->result = 1` so that the handler's own
`params->result = 0` is what the assertion observes, not a zero-initialized field.

[`test_security_policy_witness.c`](../tests/unit/test_security_policy_witness.c)
adds swap-witness cases: non-ordinary mode, staking, multisig payment, pool cold key
and DRep paths all deny; an ordinary payment path hides; a second account and an unusual
address index deny.

Supporting mocks:

| File | Role |
|------|------|
| `tests/unit/mock_sources/swap_test_stubs.c` | Defines the SDK globals and stubs every `swap_lib.h` function with call counters, injectable pass/fail, and a `longjmp` on `swap_reject_and_exit` |
| `tests/unit/mock_includes/swap_test_stubs.h` | Stub control API |
| `tests/unit/mock_includes/swap_error_code_helpers.h` | Local copy of the SDK error enum and `send_swap_error_simple` |
| `tests/unit/mock_sources/os_lib_end_stub.c` | Asserts on an unexpected `os_lib_end()` in non-swap tests |
| `tests/unit/test_utils/io_capture.c` | Reproduces the SDK behavior: calls `os_lib_end()` from the response path once `G_called_from_swap && G_swap_response_ready` |

### 6.2 Functional tests (`tests/swap/`)

These run the **real** Exchange app in Speculos, with this app sideloaded as a library,
the same relationship as on a device. Exchange is the Speculos main app and
`build/<device>/bin/app.elf` is passed with `-l`; `app-ethereum` is sideloaded too,
because several Exchange scenarios pair ADA against ETH.

[`test_cardano_swap.py`](../tests/swap/test_cardano_swap.py) defines three test
functions:

| Test | Coverage |
|------|----------|
| `test_cardano_swap` | Parametrized over `ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES` from the Exchange client library: valid swap/fund/sell flows, wrong destination, wrong amount, wrong refund address, UI-only |
| `test_cardano_swap_deny_multiple_third_party_outputs` | Builds a body with two third-party outputs; expects `0x6001` |
| `test_cardano_swap_deny_witness_pool_cold_path` | Adds a witness on `m/1853'/1815'/0'/0'`; expects `0x6001` |

Local details worth knowing:

- `perform_coin_specific_final_tx` is **overridden** so that a post-signing snapshot
  mismatch cannot mask the primary APDU exception, and it asserts `SWO_SUCCESS` plus a
  64-byte signature. This is the reporting requirement set out in
  [`doc/tx_raw_buffer.md`](tx_raw_buffer.md#nano-x-stackbss-interaction-in-swap-library-mode).
- `_assert_exchange_started_with_retry` retries for ~1.2 s, tolerating a transient
  `0x6001` from `GET_VERSION` while `os_lib_end()` is still unwinding back into
  Exchange.
- `conftest.py` pins per-xdist-worker Speculos API/APDU ports instead of relying on
  ragger's free-port search, which races under parallel execution.

Setup and invocation are in [`tests/swap/README.md`](../tests/swap/README.md). One
thing that README does not mention: `pytest.ini` sets `testpaths = tests/standalone`,
so `tests/swap/` must always be named explicitly.

In CI this suite runs as `tests_swap` in `build_and_functional_tests.yml`, through
`reusable_swap_tests.yml@v1`, which clones and builds Exchange and Ethereum itself —
the local helper scripts exist only for developer machines.

### 6.3 Fuzzing

The fuzz build defines `HAVE_SWAP` (`tests/fuzzing/CMakeLists.txt`), and no `src/swap/*.c`
file is excluded from the `code_lib` glob. Swap branches are therefore compiled into
**every** harness, though only the three swap harnesses below actually set
`G_called_from_swap`, so `fuzz_signTx` / `fuzz_all_handlers` still exercise the
non-swap path.

| Harness | Target | Input layout |
|---------|--------|--------------|
| [`fuzz_swap_check_address.c`](../tests/fuzzing/harness/fuzz_swap_check_address.c) | `swap_handle_check_address()` | `[path_len][packed BIP44 path][address string]`; the address is copied into a `MAX_HUMAN_ADDRESS_LENGTH` buffer and NUL-terminated |
| [`fuzz_swap_printable_amount.c`](../tests/fuzzing/harness/fuzz_swap_printable_amount.c) | `swap_handle_get_printable_amount()` | `[is_fee flag][amount bytes]`, `amount_length` clamped to `UINT8_MAX` |
| [`fuzz_swap_sign_tx.c`](../tests/fuzzing/harness/fuzz_swap_sign_tx.c) | the whole library-mode sign flow | `[dest_len][dest][amt_len][amt<=8][fee_len][fee<=8][(p1,p2,lc,data)...]` |

`fuzz_swap_sign_tx` is the only harness that reaches the real `swap_lib.c`: it fills a
`create_transaction_parameters_t` from the input, calls the genuine
`swap_copy_transaction_parameters()`, sets `G_called_from_swap`, then streams SIGN_TX
APDUs through `apdu_dispatcher()` with `CLA` and `INS_SIGN_TX` forced and P1/P2/Lc/payload
fuzzed, calling `apdu_response_state_force_reset()` between APDUs. All three harnesses
point the SDK parameter structs straight at the fuzz input rather than heap copies, so a
`swap_reject_and_exit()` `longjmp` mid-call cannot leak.

Two SDK behaviors have to be neutralized for this to work, both in
[`tests/fuzzing/mock/os_mocks.c`](../tests/fuzzing/mock/os_mocks.c):

| Symbol | Treatment | Why |
|--------|-----------|-----|
| `os_explicit_zero_BSS_segment` | linker-wrapped (`-Wl,--wrap=`) to a no-op | the real BSS wipe inside the swap parameter copy would clobber the fuzzer, sanitizer, and heap globals |
| `os_lib_end` | `siglongjmp` to the harness exit context | makes the NORETURN swap rejection observable instead of terminating the process |

The shared dictionary and the seed corpora described in
[`tests/fuzzing/FUZZING.md`](../tests/fuzzing/FUZZING.md) apply to these harnesses as well,
but with a caveat: `generate_seed_corpus.py` produces **no** swap seeds, so all three swap
fuzzers cold-start from `dict/cardano.dict` plus random bytes. `fuzz_swap_check_address` in
particular is unlikely to reach the closing `strcmp` unaided, since that needs a valid
Shelley path paired with the exact bech32 address the device derives from it.

---

## References

- [`tests/swap/README.md`](../tests/swap/README.md): setup and run guide for the
  functional suite.
- [`doc/tx_raw_buffer.md`](tx_raw_buffer.md#nano-x-stackbss-interaction-in-swap-library-mode):
  Nano X stack/BSS interaction in library mode.
- [`doc/apdu_reference.md`](apdu_reference.md): status words, including `0x6001`.
- [`doc/non_bugs.md`](non_bugs.md): the intentional mainnet-only address check.
- [`doc/testing.md`](testing.md): testing entry point and workflow rules.
- [`tests/fuzzing/FUZZING.md`](../tests/fuzzing/FUZZING.md): fuzzing setup, the shared
  dictionary, and the seed corpora.
- [Ledger Exchange documentation](https://ledgerhq.github.io/app-exchange/)
