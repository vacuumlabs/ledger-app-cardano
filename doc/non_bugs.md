# Review instructions

* Security and auditability is critically important for this app.
* Efficiency is not critically important; if doing something twice makes the code cleaner and more auditable, it is preferable to do it twice.
* Auditability is increased by following the same text patterns (macro calls, function params, style of loops, switch instead of if chain over enum values, memory init/cleanup etc.).
* Ledger devices have little memory, so standard ways of doing things are sometimes unsuitable.
* Unless told specifically, we do not want legacy wrappers or support for deprecated stuff.


# List of **not bugs**, do not report them.

Format: -> means explanation why not a bug.

* IPv6 Relay Address Byte Order: The app serializes each relay IPv6 address into the tx hash as 4 big-endian uint32 words. This matches how Cardano transmits IPv6 relay addresses — as 4 little-endian uint32 words — which differs from standard network byte order (RFC 4291). The UI calls `inet_ntop6` which reads the bytes bytewise (standard order) and displays the address correctly. Both the hash and the display are self-consistent and match the Cardano ledger expectation.
-> intentional. Cardano's non-standard per-word little-endian IPv6 encoding must be followed.

* Missing Canonical Ordering Checks (CDDL Violations): required_signers (Key 14) are not checked for canonical sorting, pool_owners within stake pool registration certificates are not checked for canonical sorting.
-> for historical reason, we do not check unique elements in sets.

* Unsupported Field Omission (Protocol Gap): Key 20 (proposal_procedures) is defined as "NOT SUPPORTED" in the CDDL but is silently ignored by the app's parsing logic.
-> no plans to support proposal_procedures for now, it is ok. The app behaves as if it did not know anything about proposal procedures and that is the intended behavior.

* `swap_handle_check_address` hardcodes `MAINNET_NETWORK_ID`.
-> intentional and inherited from the old app (`../app-cardano/src/swap/handle_check_address.c`); swap flow is mainnet-only.

* Init ordering nit: whether handlers set `G_context.req_type` before or after a local state check in INIT flow.
-> not a bug by itself. Both patterns are acceptable when handler invariants hold and failures route through reset/deny paths. Prefer consistency within each handler/state machine over enforcing one global ordering rule.

* "Redundant state check" right after setting state in handler flow (for example `derive_address` PARSED check) and CVote INIT check after `explicit_bzero(&G_context.cvote_info, ...)`.
-> not a bug by itself. In `derive_address`, the immediate check is an intentional defensive invariant/style pattern. In CVote, zeroing `cvote_info` does not zero `state.cvote_state` (different global-context fields), so `ensure_sign_cvote_state(VOTECAST_STATE_NONE)` is a real precondition check.

* `mark_unusual_key_derivation(...)` may look coupled to `bip44_isPathReasonable(...)` / SHOW behavior.
-> not a bug by itself. Preferred style is to keep the link explicit at call sites with `SHOW_IF(mark_unusual_key_derivation(...))`, optionally followed by unconditional `SHOW()` when the field/path must always be shown anyway. This makes warning-vs-visibility behavior local and auditable.

* Unreachable `default` in `switch` over enum/type value after prior strict validation.
-> intentional defensive programming pattern. Keeping `ASSERT(false)`/`LEDGER_ASSERT(false, ...)` in logically unreachable branches documents invariants and catches unexpected state corruption or future regressions during development; this should not be downgraded to a normal runtime fallback just to remove "dead code". Also protects against memory-modified-in-the-middle attacks.

* Host-provided total length causes early allocation/reservation (up to protocol/app limits), even before all bytes are received.
-> not a bug by itself. In streamed APDU flows, the app commits to the declared size and then strictly enforces that exact byte count in subsequent chunks. The device handles one request/session at a time (no parallel users/calls), so this is perfectly intentional.

* Missing `amount > 0` check for withdrawals.
-> not a bug. CDDL defines `withdrawals = {+ reward_account => coin}` and `coin = uint`, so zero is protocol-valid. This differs from places that require strictly positive quantities (for example output token amounts). Allowing zero withdrawals is harmless and avoids adding wallet-local restrictions beyond the ledger format.

* "Unbounded" loops over host-declared counts (withdrawals, mint groups, mint tokens) without extra small hardcaps.
-> not a bug by itself. These loops are bounded by protocol field widths (`uint16_t` counts) and by the already-validated transaction byte budget (`raw_tx_total_length`, capped by app limit). Parsing uses bounded buffer readers and fails immediately on underflow/malformed data; full consumption is enforced at the end. This is an intentional compatibility/auditability tradeoff (no arbitrary wallet-local count limits), not an infinite-loop risk.

* No extra wallet-local upper bound for length-prefixed nested payloads (for example stake pool registration certificate payload).
-> not a bug by itself. The nested payload length is validated against remaining bytes before parsing, then parsed via a bounded sub-buffer, required to be fully consumed, and finally the outer cursor advances by exactly that length. Combined with global transaction size caps, this is a safe and auditable framing strategy without arbitrary additional caps.

* Missing repeated UI-time bound assertion for fields that were already strictly bounded at parse time (for example pool metadata `urlSize` in rendering).
-> not a bug by itself. If the field is parsed with strict limits and then carried through immutable parse->policy->render flow, rechecking the same bound in each consumer is optional defense-in-depth, not a correctness or security requirement.

* No explicit small hardcaps for stake pool registration `numPoolOwners` / `numRelays`.
-> not a bug by itself. Counts are wire-bounded (`uint16_t`) and constrained by the enclosing payload length and full-consumption checks. Processing is finite and fails on malformed/short input. Additional wallet-local maxima would be policy restrictions, not a memory-safety fix.

* URL formatter enforces printable ASCII without spaces for displayed URLs.
-> intentional display-safety policy. Percent-encoded URLs (including `%20`) are ASCII and allowed; non-ASCII/confusable URLs are intentionally rejected as not safely displayable without ambiguity. The shared helper `str_isPrintableAsciiWithoutSpaces(...)` is also intentionally vacuously true for zero-length buffers; emptiness is a separate policy question handled by the caller/spec, not by the character-class check itself.

* UI formatters reject exact-fit output buffers (`written + 1 < outSize` returns false/asserts when `written == outSize - 1`).
-> intentional sentinel-byte convention. One spare byte beyond the NUL is required so that a full-capacity snprintf write is detectable as potential truncation. Callers must size buffers with this extra byte in mind. Documented in `src/ui/ui_formatters.h`.

* Non-mainnet network IDs 2–15 are rendered with mainnet-looking `addr`/`stake` bech32 prefixes.
-> not a bug. These IDs don't exist on any real network, and `isNetworkUsual()` returns false for them, triggering an unusual-network warning to the user. Behavior matches the old app.

* Tx body field 15 (`network_id`) is hashed without a dedicated per-field review screen.
-> not a bug. The app intentionally treats `includeNetworkId` itself as making network identity verifiable and only shows network details when the network parameters are unusual. This matches the local specs and the old app behavior; a separate “field 15 present” screen is not required.

* `aux_data_hash_builder.c` trace buffers (`AUX_DATA_TRACE_BUFFER_SIZE` / `CVOTE_PAYLOAD_TRACE_BUFFER_SIZE`) are only 4 KiB each and will assert if a high-delegation CIP-36 registration overflows them.
-> intentional. Buffers are debug-only (compiled in only under `-DTRACE_AUX_DATA_HASH_BUILDER`, never in production). The assert-on-overflow is deliberate: if a developer enables tracing and hits the limit, they get a loud failure rather than silent truncation of the trace, and can decide how to proceed. Production hashing is unaffected.

* `parse_opcert` reads `kesPeriod` before `issueCounter` from the wire, but `finalize_sign_opcert` serializes them in the opposite order (`issueCounter` then `kesPeriod`).
-> intentional. The APDU wire protocol sends `kesPeriod` first (historical convention), but the opcert body that is actually signed must be `KES public key || issueCounter || kesPeriod` per the Cardano spec (see `doc/spec_pool_registration.md` section 3.3.4 and the cardano-crypto.js verification snippet). The parse order and the serialization order are deliberately different.

* Mismatched test counts in generator output (WARNING: Mismatch between in-memory generation and file parsing).
-> intentional validation redundancy. The unit test generator (`generate_unit_tests_from_ragger.py`) intentionally uses multiple methods to count generated test cases (in-memory tracking vs. regex parsing of generated C files) as a sanity check. Any mismatch is manually investigated during development. The generator does not live on its own and is only used to create testing data, so this warning is safe to ignore in automated runs unless explicitly debugging coverage.

* L13. `format_pool_margin` potential overflow at `10000 * numerator + denominator/2` (`src/ui/ui_formatters.c:239`).
-> not a bug. The assert at line 236 enforces `numerator <= UINT64_MAX / 10000`, so `10000 * numerator <= UINT64_MAX - 9999`. The parser additionally enforces `numerator <= MARGIN_DENOMINATOR_MAX = 10^15`, giving `10000 * numerator <= 10^19`. Adding `denominator/2 <= MARGIN_DENOMINATOR_MAX/2 = 5*10^14` yields at most `~1.005 * 10^19`, well within `UINT64_MAX (~1.8 * 10^19)`. No overflow is possible with the parse-time bounds in place.

* L2. `num_witnesses == 0` accepted (`src/handler/sign_tx.c:313-316`).
-> not a bug. The transaction still goes through full parsing, policy checks, and user review, so the app verifies that the transaction is well-formed and acceptable. If the client requests zero witnesses, the app simply signs nothing; we do not require wallets/clients to ask for witnesses.

* No lower-bound (zero) checks for lovelace amounts and counts where the Cardano node enforces a minimum: output ADA amount (`tx_parse_outputs.c`), Conway certificate deposits (`tx_parse_certificates.c`), `numPoolOwners` in pool registration (`tx_parse_certificates.c`).
-> not a bug. The CDDL defines `coin = uint` (allowing 0) and `pool_owners : set<addr_keyhash>` where `set<a0> = #6.258([* a0]) / [* a0]` (`*` = zero or more), so zero is wire-format valid. The app enforces upper bounds (`LOVELACE_MAX_SUPPLY`, `uint16_t` counts) but does not duplicate node-level policy restrictions such as minimum UTxO values, minimum deposits, or the requirement that a pool has at least one owner — those are enforced by the Cardano ledger at submission time. Adding wallet-local minimums would risk false rejections as protocol parameters change, with no security benefit for the signing device.

* Empty URL accepted for pool metadata (`tx_parse_certificates.c`) and governance anchors (`cardano_parsers.c`) when the enclosing field is present.
-> not a bug. The CDDL defines `url = text .size (0 .. 128)`, explicitly permitting zero-length URLs. Rejecting length-0 URLs would be a wallet-local restriction beyond the wire format. This is why the shared URL validator `str_isPrintableAsciiWithoutSpaces(...)` intentionally accepts `bufferSize == 0` for these call sites. The hash is still verified to be present and well-formed, so the display is self-consistent.

* `ALL []` / `ANY []` complex native scripts with zero sub-scripts accepted (`derive_native_script_hash.c`).
-> not a bug. The CDDL defines `script_all = (1, [* native_script])` and `script_any = (2, [* native_script])` where `*` explicitly permits zero elements. `ALL []` is vacuously satisfied and `ANY []` is vacuously unsatisfiable, but both are syntactically valid on-chain scripts. The app hashes what it receives; semantic validity is a node concern.

* CIP-36 CVote auxiliary-data signing no longer shows the auxiliary-data hash during the dedicated CVote review flow.
-> not a bug. In the current flow, the CVote auxiliary-data hash is finalized only at the end, after all delegations are received and just before the response is produced. Re-introducing a separate hash-review step there would materially complicate the NBGL callback/state-machine flow. The hash remains user-visible as part of the subsequent transaction review, so this is an intentional UX/control-flow tradeoff rather than a security bug.
