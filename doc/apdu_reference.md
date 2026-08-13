# Cardano Ledger App — APDU Reference

This document describes the full APDU protocol of the Cardano Ledger app — the
low-level binary interface used by host software (wallets, CLI tools, test clients)
to communicate with the app running on a Ledger device.

Each section below covers one instruction (INS byte): its purpose, the exact byte
layout of its request and response, any multi-APDU sub-flows it uses, and the error
codes it can return.  A summary table in §2 lists all supported instructions at a glance.

---

## Table of Contents

1. [Protocol Fundamentals](#1-protocol-fundamentals)
2. [Instruction Summary](#2-instruction-summary)
3. [Simple Queries](#3-simple-queries)
   - 3.1 [GET\_VERSION — `0x00`](#31-get_version--0x00)
   - 3.2 [GET\_SERIAL — `0x01`](#32-get_serial--0x01)
   - 3.3 [GET\_APP\_NAME — `0x04`](#33-get_app_name--0x04)
4. [Key Export](#4-key-export)
   - 4.1 [GET\_PUBLIC\_KEY — `0x10`](#41-get_public_key--0x10)
5. [Address Derivation](#5-address-derivation)
   - 5.1 [DERIVE\_ADDRESS — `0x11`](#51-derive_address--0x11)
6. [Native Script Hash Derivation](#6-native-script-hash-derivation)
   - 6.1 [DERIVE\_NATIVE\_SCRIPT\_HASH — `0x12`](#61-derive_native_script_hash--0x12)
7. [Transaction Signing](#7-transaction-signing)
   - 7.1 [SIGN\_TX — `0x21` — Overview](#71-sign_tx--0x21--overview)
   - 7.2 [INIT — P1 `0x10`](#72-init--p1-0x10)
   - 7.3 [CHUNK — P1 `0x11`](#73-chunk--p1-0x11)
   - 7.4 [CONFIRM — P1 `0x12`](#74-confirm--p1-0x12)
   - 7.5 [AUX\_DATA: CVote Registration — P1 `0x13`](#75-aux_data-cvote-registration--p1-0x13)
   - 7.6 [SIGN\_WITNESS — P1 `0x0F`](#76-sign_witness--p1-0x0f)
8. [Operational Certificate](#8-operational-certificate)
   - 8.1 [SIGN\_OPCERT — `0x22`](#81-sign_opcert--0x22)
9. [CIP-36 Vote Cast Signing](#9-cip-36-vote-cast-signing)
   - 9.1 [SIGN\_CVOTE — `0x23`](#91-sign_cvote--0x23)
10. [CIP-8 Message Signing](#10-cip-8-message-signing)
    - 10.1 [SIGN\_MSG — `0x24`](#101-sign_msg--0x24)
11. [Status Words](#11-status-words)
12. [Debug Commands](#12-debug-commands)

---

## 1. Protocol Fundamentals

### Transport

All APDUs use the **short-form ISO 7816-4 structure** only:

```
┌──────┬─────┬────┬────┬────┬────────────────────┐
│  CLA │ INS │ P1 │ P2 │ Lc │ Command data       │
│  1 B │ 1 B │ 1B │ 1B │ 1B │ 0–255 bytes        │
└──────┴─────┴────┴────┴────┴────────────────────┘
```

- **CLA**: `0xD7` — Cardano app class byte (all APDUs)
- **Lc ≤ 255** — extended-length APDUs are not supported

All multi-byte integers are **big-endian** (BE) unless explicitly stated otherwise.

### Response structure

On success, the device returns command-specific data followed by `SW = 0x9000`.  
On error, it returns no data and a non-`0x9000` status word (see [§11](#11-status-words)).

### Instruction interleaving protection

The app maintains a single active-request state.  Sending a new instruction while a
multi-APDU flow is in progress either:
- **Resets** the previous flow and returns `SWO_STILL_IN_CALL_RESET_DONE` (`0x6E04`)
  when no UX confirmation is pending, so the host may immediately retry the new instruction; or
- **Returns** `SWO_COMMAND_NOT_ALLOWED` when a deferred UX confirmation is pending.

---

## 2. Instruction Summary

All values below are the **INS byte** of the APDU header (`CLA = 0xD7` for all).

| INS (dec) | INS (hex) | Constant | Flow | Description |
|-----------|-----------|----------|------|-------------|
| 0 | `0x00` | `INS_GET_VERSION` | Single | Returns major, minor, patch version and build flags |
| 1 | `0x01` | `INS_GET_SERIAL` | Single | Returns the 7-byte device serial number |
| 4 | `0x04` | `INS_GET_APP_NAME` | Single | Returns the app name as a UTF-8 string |
| 16 | `0x10` | `INS_GET_PUBLIC_KEY` | Single | Derives and exports an extended public key (pubkey + chain code) for a BIP44 path |
| 17 | `0x11` | `INS_DERIVE_ADDRESS` | Single + UI | Derives a Cardano address; optionally shows it on-screen before returning |
| 18 | `0x12` | `INS_DERIVE_NATIVE_SCRIPT_HASH` | Multi | Streams a native script tree node-by-node, computes its Blake2b-224 hash, and returns it |
| 33 | `0x21` | `INS_SIGN_TX` | Multi | Uploads and validates a transaction body, presents it for user review, then signs requested witnesses |
| 34 | `0x22` | `INS_SIGN_OPCERT` | Single | Signs a stake pool operational certificate body with the pool cold key |
| 35 | `0x23` | `INS_SIGN_CVOTE` | Multi | Streams a CIP-36 vote-cast payload, hashes it, and returns a witness signature |
| 36 | `0x24` | `INS_SIGN_MSG` | Multi | Signs an arbitrary message per CIP-8 (COSE Sig_structure over an Ed25519 key) |
| 240 | `0xF0` | `INS_DEBUG_SET_SETTINGS` | Single | *(Debug builds only)* Configures internal app settings for testing |

---

## 3. Simple Queries

### 3.1 GET\_VERSION — `0x00`

Returns the app version and build flags.

```
Command:  CLA=0xD7  INS=0x00  P1=0x00  P2=0x00  Lc=0x00
Response: MAJOR(1) ‖ MINOR(1) ‖ PATCH(1) ‖ FLAGS(1)
```

**Flags byte** (bitfield):

| Bit | Mask | Meaning |
|-----|------|---------|
| 0 | `0x01` | Debug build (`GET_VERSION_FLAG_DEBUG`) |

---

### 3.2 GET\_SERIAL — `0x01`

Returns the device serial number.

```
Command:  CLA=0xD7  INS=0x01  P1=0x00  P2=0x00  Lc=0x00
Response: serial(7)
```

The 7-byte serial is read directly from `os_serial()`.

---

### 3.3 GET\_APP\_NAME — `0x04`

Returns the app name as a raw UTF-8 string (no null terminator, no length prefix).

```
Command:  CLA=0xD7  INS=0x04  P1=0x00  P2=0x00  Lc=0x00
Response: name (variable, ≤ 64 bytes, no NUL)
```

---

## 4. Key Export

### 4.1 GET\_PUBLIC\_KEY — `0x10`

Derives and returns the extended public key (pubkey + chain code) for the requested BIP44 path.
Optionally prompts the user to confirm the export (controlled by `securityPolicy`).

```
Command:  CLA=0xD7  INS=0x10  P1=0x00  P2=0x00  Lc=Lc
Data:     BIP44 path

Response: pubkey(32) ‖ chain_code(32)
```

**Security policy:**

| Path type | Policy | User sees |
|-----------|--------|-----------|
| Standard account key (`m/44'/…`, `m/1852'/…`) | `POLICY_HIDE` | Nothing |
| Unusual derivation paths | `POLICY_SHOW` | "Export public key?" prompt |
| Denied paths | `POLICY_DENY` | `SWO_SECURITY_CONDITION_NOT_SATISFIED` |

---

## 5. Address Derivation

### 5.1 DERIVE\_ADDRESS — `0x11`

Derives a Cardano address from supplied address parameters.  
P1 controls whether to silently return the address or display it on-screen first.

```
Command:  CLA=0xD7  INS=0x11  P1={0x01|0x02}  P2=0x00  Lc=Lc
Data:     address_params (variable, see below)
```

| P1 | Name | Behaviour |
|----|------|-----------|
| `0x01` | `P1_ADDRESS_RETURN` | Derive and return address bytes directly |
| `0x02` | `P1_ADDRESS_DISPLAY` | Show address on device screen; returns empty body with SW=`0x9000` |

**Response (P1=`0x01`):**  raw address bytes (up to 128 bytes)  
**Response (P1=`0x02`):**  empty (user dismissed the display)

**`address_params` encoding** — see `src/addressUtils/addressUtilsShelley.h` /
`src/parsers/cardano_parsers.c::buffer_read_address_params()` for the full format.
At a high level it encodes: address type, spending credential, staking credential / pointer,
and network info.

---

## 6. Native Script Hash Derivation

### 6.1 DERIVE\_NATIVE\_SCRIPT\_HASH — `0x12`

Streams a native script tree to the device one node at a time, computes its
Blake2b-224 hash, optionally shows each node to the user, and returns the final hash.

#### Flow overview

```
Host                                    Device
  |                                        |
  |----  INIT (P1=0x00, empty)  ---------> |  Starts hash builder, opens UI
  | <--  SW=9000  ------------------------ |
  |                                        |
  |   For each node (depth-first):         |
  |----  START_COMPLEX (P1=0x01)  -------> |  All / Any / N-of-K
  | <--  SW=9000 (or deferred UX)  ------- |
  |----  ADD_SIMPLE (P1=0x02)  ----------> |  Pubkey / InvalidBefore / InvalidHereafter
  | <--  SW=9000 (or deferred UX)  ------- |
  |                                        |
  |----  FINISH (P1=0x03)  --------------> |  Computes + shows hash, defers UX
  | <--  SW=9000 (deferred)  ------------- |
  |                                        |  [User approves on device]
  | <--  script_hash(28) + SW=9000  ------ |
```

P1 values:

| P1                               | Hex    | Name                          |
|----------------------------------|--------|-------------------------------|
| `P1_NATIVE_SCRIPT_INIT`          | `0x00` | Begin streaming session       |
| `P1_NATIVE_SCRIPT_START_COMPLEX` | `0x01` | Open an ALL / ANY / N-of-K node |
| `P1_NATIVE_SCRIPT_ADD_SIMPLE`    | `0x02` | Add a leaf (pubkey or timelock) |
| `P1_NATIVE_SCRIPT_FINISH`        | `0x03` | Finalize and return hash      |

#### INIT — P1 `0x00`

```
Data:   (empty)
Response: SW=9000  (UI deferred — streaming begins)
```

#### START\_COMPLEX — P1 `0x01`

Opens a nested ALL, ANY, or N-of-K script. Must arrive while there is a slot open
at the current depth. The device tracks remaining children and auto-closes completed levels.

```
┌──────────────┬────────────────┬─────────────────────────────────────────────┐
│ script_type  │ total_scripts  │  required_scripts  (N-of-K only, 4 B BE)    │
│     1 B      │     4 B BE     │                                             │
└──────────────┴────────────────┴─────────────────────────────────────────────┘
```

| `script_type`           | Value  | Required extra field                                    |
|-------------------------|--------|---------------------------------------------------------|
| `NATIVE_SCRIPT_ALL`     | `0x01` | —                                                       |
| `NATIVE_SCRIPT_ANY`     | `0x02` | —                                                       |
| `NATIVE_SCRIPT_N_OF_K`  | `0x03` | `required_scripts` (4 B BE): must be ≤ `total_scripts`  |

**Maximum nesting depth:** 10 levels (`MAX_SCRIPT_DEPTH`).

#### ADD\_SIMPLE — P1 `0x02`

Adds a leaf script at the current depth.

```
┌──────────────┬──────────────────────────────────────────────────────┐
│ script_type  │  payload                                             │
│     1 B      │  variable (see below)                                │
└──────────────┴──────────────────────────────────────────────────────┘
```

| `script_type`                     | Value  | Payload                                                                    | Notes                                                    |
|-----------------------------------|--------|----------------------------------------------------------------------------|----------------------------------------------------------|
| `NATIVE_SCRIPT_PUBKEY`            | `0x00` | Ext Credential (`KEY_PATH` or `KEY_HASH` only, not `SCRIPT_HASH`)          | Device derives key hash from path or uses provided hash  |
| `NATIVE_SCRIPT_INVALID_BEFORE`    | `0x04` | 8 B BE uint64 (slot number)                                                | Lower time bound                                         |
| `NATIVE_SCRIPT_INVALID_HEREAFTER` | `0x05` | 8 B BE uint64 (slot number)                                                | Upper time bound                                         |

#### FINISH — P1 `0x03`

```
┌───────────────┐
│ display_format│
│     1 B       │
└───────────────┘
```

| `display_format`                       | Value  | Hash displayed as             |
|----------------------------------------|--------|-------------------------------|
| `DISPLAY_NATIVE_SCRIPT_HASH_BECH32`    | `0x01` | Bech32 (`script1…`)           |
| `DISPLAY_NATIVE_SCRIPT_HASH_POLICY_ID` | `0x02` | Hex (native asset policy ID)  |

**Response (after user confirms):**

| Field         | Size  | Description                         |
|---------------|-------|-------------------------------------|
| `script_hash` | 28 B  | Blake2b-224 hash of the script tree |

---

## 7. Transaction Signing

### 7.1 SIGN\_TX — `0x21` — Overview

Transaction signing in the new app uses a **streaming buffer architecture**.
The entire custom-format transaction body is first uploaded in chunks, then parsed
and validated in one pass (Phase 1), then re-walked for UI display (Phase 2).

> See [`doc/tx_raw_buffer.md`](tx_raw_buffer.md) for the custom binary format used
> inside the chunks, and [`doc/tx.md`](tx.md) for the full two-phase architecture.

#### Complete flow

```
Host                                              Device
  |                                                  |
  |----  INIT (P1=0x10)  --------------------------> |  Parse metadata, allocate buffer
  | <--  SW=9000  ---------------------------------- |
  |                                                  |
  |   [Only if AUX_DATA_TYPE_CVOTE_REGISTRATION in INIT:]
  |----  AUX_DATA INIT (P1=0x13)  -----------------> |  Parse CVote init, show UI page
  | <--  SW=9000 / deferred UX  -------------------- |
  |----  AUX_DATA DELEGATION (P1=0x13) x N  -------> |  Each delegation
  | <--  SW=9000 / deferred UX  -------------------- |
  |                                                  |
  |   [If deferred UX after last delegation:]        |
  |                    [User confirms CVote]         |
  | <--  auxDataHash(32) + regSig(64) + SW=9000  --- |
  |                                                  |
  |----  CHUNK (P1=0x11) x 0..N  ------------------> |  Raw TX body chunks (250 B each)
  | <--  SW=9000  ---------------------------------- |
  |                                                  |
  |----  CONFIRM (P1=0x12)  -----------------------> |  Final chunk, triggers validation
  |                             [User approves]      |
  | <--  tx_hash(32) + SW=9000  -------------------- |
  |                                                  |
  |----  SIGN_WITNESS (P1=0x0F) x num_witnesses  --> |  One BIP44 path per witness
  |                           [User approves]        |
  | <--  signature(64) + SW=9000  ------------------ |  Per witness
```

P1 values for `SIGN_TX`:

| P1 | Hex | Name | Description |
|----|-----|------|-------------|
| `P1_TX_INIT` | `0x10` | Init | Metadata + counts |
| `P1_TX_CHUNK` | `0x11` | Chunk | Non-final body data (exactly 250 bytes) |
| `P1_TX_CONFIRM` | `0x12` | Confirm | Final body chunk (1–250 bytes) |
| `P1_TX_AUX_DATA` | `0x13` | Aux data | CVote registration sub-flow |
| `P1_TX_SIGN_WITNESS` | `0x0F` | Witness | Sign hash with one BIP44 key |

---

### 7.2 INIT — P1 `0x10`

Declares all transaction metadata. Must be the first APDU in any `SIGN_TX` exchange.

```
Command:  CLA=0xD7  INS=0x21  P1=0x10  P2=0x00  Lc=Lc
```

**INIT payload** (all fields required, fixed order):

| Field | Size | Encoding | Description |
|-------|------|----------|-------------|
| `options` | 8 B | uint64 BE | Feature flags (see below) |
| `networkId` | 1 B | uint8 | Network identifier (0 = testnet, 1 = mainnet) |
| `protocolMagic` | 4 B | uint32 BE | Network protocol magic |
| `txSigningMode` | 1 B | uint8 | Signing mode (see below) |
| `num_inputs` | 2 B | uint16 BE | Number of TX inputs (field 0) |
| `num_outputs` | 2 B | uint16 BE | Number of TX outputs (field 1) |
| `includeTtl` | 1 B | flag | Is field 3 (TTL) present? |
| `num_certificates` | 2 B | uint16 BE | Number of certificates (field 4) |
| `num_withdrawals` | 2 B | uint16 BE | Number of withdrawals (field 5) |
| `includeAuxDataHash` | 1 B | flag | Is field 7 (aux data hash) present? |
| `auxDataType`¹ | 1 B | uint8 | Type: `0x00` = arbitrary hash, `0x01` = CVote |
| `auxDataHash`¹ | 32 B | bytes | Pre-computed hash (only for `0x00`) |
| `includeValidityIntervalStart` | 1 B | flag | Is field 8 present? |
| `num_mint_asset_groups` | 2 B | uint16 BE | Number of mint asset groups (field 9) |
| `includeScriptDataHash` | 1 B | flag | Is field 11 present? |
| `num_collateral_inputs` | 2 B | uint16 BE | Number of collateral inputs (field 13) |
| `num_required_signers` | 2 B | uint16 BE | Number of required signers (field 14) |
| `includeNetworkId` | 1 B | flag | Is field 15 (inline network ID) present? |
| `includeCollateralOutput` | 1 B | flag | Is field 16 present? |
| `includeTotalCollateral` | 1 B | flag | Is field 17 present? |
| `num_reference_inputs` | 2 B | uint16 BE | Number of reference inputs (field 18) |
| `num_voters` | 2 B | uint16 BE | Number of voting procedures (field 19) |
| `includeTreasury` | 1 B | flag | Is field 21 present? |
| `includeDonation` | 1 B | flag | Is field 22 present? |
| `num_witnesses` | 2 B | uint16 BE | Number of witnesses to sign |
| `raw_tx_total_length` | 2 B | uint16 BE | Total byte size of raw TX body chunks |

¹ `auxDataType` and `auxDataHash` are only present when `includeAuxDataHash = FLAG_INCLUDED_YES`.
  `auxDataHash` is only present when `auxDataType = 0x00` (arbitrary hash).

**`options` bitmask:**

| Bit | Mask | Name | Effect |
|-----|------|------|--------|
| 0 | `0x01` | `TX_OPTIONS_TAG_CBOR_SETS` | Use CBOR set tags (tag 258) in transaction hash |

All other bits must be zero.

**`txSigningMode` values:**

| Value | Name | Use case |
|-------|------|----------|
| `0x03` | `ORDINARY` | Standard single-account Shelley transaction |
| `0x04` | `POOL_REGISTRATION_OWNER` | Pool owner witnesses only |
| `0x05` | `POOL_REGISTRATION_OPERATOR` | Pool operator witnesses |
| `0x06` | `MULTISIG` | Multi-signature transaction (CIP-1854) |
| `0x07` | `PLUTUS` | Transaction with Plutus scripts |
| `0x08` | `AUTO` | Device auto-detects from Plutus indicators; returns `SWO_AMBIGUOUS_TX_SIGNING_MODE` if ambiguous |
| `0x09` | `UNRESTRICTED` | Relaxed policy; use only when instructed |
| `0x0A` | `POOL_REGISTRATION_PAYER` | Third party pays the fee for a pool registration; pool key and all owners given as hashes |
| `0x0B` | `POOL_RETIREMENT_PAYER` | Third party pays the fee for pool retirement(s); pool key given as a hash |

**Response:** `SW=9000` (no data)

> If `auxDataType = 0x01` (CVote registration), the device transitions to `TX_STATE_AUX_DATA`
> and expects `P1_TX_AUX_DATA` APDUs next (§7.5). If `auxDataType = 0x00` or absent, it
> transitions directly to `TX_STATE_CHUNKS` and expects `P1_TX_CHUNK` / `P1_TX_CONFIRM` next.

---

### 7.3 CHUNK — P1 `0x11`

Appends exactly `MAX_SIGN_TX_CHUNK_SIZE = 250` bytes to the internal raw TX buffer.
Each non-final chunk must be exactly 250 bytes.

```
Command:  CLA=0xD7  INS=0x21  P1=0x11  P2=0x00  Lc=0xFA (250)
Data:     250 bytes of raw TX body
Response: SW=9000
```

Repeat as many times as needed.
Total bytes across all CHUNK + CONFIRM APDUs must equal `raw_tx_total_length` declared in INIT.

**Buffer limits:**
- Minimum: 1 byte total
- Maximum: `MAX_TX_BUFFER_SIZE = 21,504 bytes` (21 KB)

---

### 7.4 CONFIRM — P1 `0x12`

Sends the final raw TX body chunk (1–250 bytes), triggers Phase 1 validation + hashing,
and presents the transaction review UI to the user.

```
Command:  CLA=0xD7  INS=0x21  P1=0x12  P2=0x00  Lc=Lc  (1 ≤ Lc ≤ 250)
Data:     final raw TX body bytes (Lc bytes)
```

**Response (after user approves):** `tx_hash(32)` — the Blake2b-256 hash of the
serialized transaction body (to be used by the host to assemble witnesses).

> If the transaction has ≥ 25 UI pairs (`LONG_TX_REVIEW_THRESHOLD`) and blind-signing
> is enabled, the device first offers a choice between full review and blind-signing mode.

---

### 7.5 AUX\_DATA: CVote Registration — P1 `0x13`

This sub-flow is only used when INIT declared `auxDataType = 0x01`
(`AUX_DATA_TYPE_CVOTE_REGISTRATION`).  It must complete before any CHUNK APDUs.

P2 distinguishes the two AUX\_DATA APDU types:

| P2 | Hex | Name |
|----|-----|------|
| `P2_AUX_DATA_INIT` | `0x36` | CVote registration init |
| `P2_AUX_DATA_DELEGATION` | `0x37` | One delegation entry |

#### AUX\_DATA INIT — P2 `0x36`

```
Command:  CLA=0xD7  INS=0x21  P1=0x13  P2=0x36  Lc=Lc
```

Payload is the raw CIP-36 registration init data (parsed internally — see `cvote_parser.c`).

**Response:**

- `SW=9000` if no delegations expected (device moves directly to confirmation UI), or
- Deferred (device shows first streaming page) while waiting for delegation APDUs.

#### AUX\_DATA DELEGATION — P2 `0x37`

Sent once per delegation entry declared in the init data.

```
Command:  CLA=0xD7  INS=0x21  P1=0x13  P2=0x37  Lc=Lc

┌──────────────────────────────────┬────────────┐
│  delegation_credential           │  weight    │
│  variable                        │  4 B BE    │
└──────────────────────────────────┴────────────┘
```

**Response (last delegation, after user confirms):**

```
aux_data_hash(32) ‖ registration_signature(64)
```

- `aux_data_hash` — Blake2b-256 hash of the CVote auxiliary data (becomes TX body field 7)
- `registration_signature` — Ed25519 signature of the CVote registration payload

---

### 7.6 SIGN\_WITNESS — P1 `0x0F`

Signs the previously confirmed `tx_hash` with a device-owned key identified by a BIP44 path.
Called once per witness declared in INIT.

```
Command:  CLA=0xD7  INS=0x21  P1=0x0F  P2=0x00  Lc=Lc
Data:     BIP44 path
```

**Response:** `Ed25519_signature(64)` — the raw signature over `tx_hash`.

The host is responsible for wrapping this into the appropriate Cardano witness format
(Shelley Vkey witness or Byron Daedalus witness) before submitting to the node.

**Security policy** for witnesses (enforced per signing mode):

| Signing mode | Allowed witness key paths |
|--------------|--------------------------|
| `ORDINARY` | `m/1852'/1815'/a'/{0,1}/i`, `m/1852'/1815'/a'/2/0`, `m/1855'/1815'/…` (mint) |
| `MULTISIG` | `m/1854'/1815'/…` |
| `POOL_REGISTRATION_OWNER` | `m/1852'/1815'/a'/2/0` |
| `POOL_REGISTRATION_OPERATOR` | `m/1853'/1815'/a'/0/0` (cold key) and `m/1852'/1815'/a'/{0,1}/i` (payment, for the inputs) |
| `POOL_REGISTRATION_PAYER` | `m/1852'/1815'/a'/{0,1}/i` (payment only) |
| `POOL_RETIREMENT_PAYER` | `m/1852'/1815'/a'/{0,1}/i` (payment only) |
| `PLUTUS` | All of the above |

Witnesses with paths violating these policies return `SWO_SECURITY_CONDITION_NOT_SATISFIED`.

---

## 8. Operational Certificate

### 8.1 SIGN\_OPCERT — `0x22`

Signs a stake pool operational certificate body in a single APDU.

```
Command:  CLA=0xD7  INS=0x22  P1=0x00  P2=0x00  Lc=Lc

┌──────────────────┬─────────────┬────────────────┬─────────────────┐
│ KES public key   │ KES period  │ issue counter  │ pool cold key   │
│    32 bytes      │  8 B BE u64 │   8 B BE u64   │ BIP44 path      │
└──────────────────┴─────────────┴────────────────┴─────────────────┘
```

The pool cold key path must be a valid CIP-1853 path (`m/1853'/1815'/…`).

**Signed body** (assembled on-device before signing):
```
KES_pubkey(32) ‖ issue_counter(8 BE) ‖ KES_period(8 BE)
```

> Note: the signed body follows the Cardano protocol's CBOR order (`issue_counter`
> before `KES_period`), which is the reverse of their order in the APDU input above.

**Response (after user confirms):**

| Field       | Size  | Description                                             |
|-------------|-------|---------------------------------------------------------|
| `signature` | 64 B  | Ed25519 signature over the assembled op-cert body bytes |

---

## 9. CIP-36 Vote Cast Signing

### 9.1 SIGN\_CVOTE — `0x23`

Signs a raw CIP-36 vote-cast payload, streaming it in chunks.

#### Flow overview

```
Host                                        Device
  |                                            |
  |----  INIT (P1=0x50)  --------------------> |  Parse header, begin hash
  | <--  SW=9000  ---------------------------- |
  |                                            |
  |----  CHUNK (P1=0x51) x 0..N  ------------> |  Remaining votecast bytes
  | <--  SW=9000  ---------------------------- |
  |                                            |
  |----  CONFIRM (P1=0x52)  -----------------> |  Witness path + show UI
  |                        [User approves]     |
  | <--  hash(32) + sig(64) + SW=9000  ------- |
```

P1 values:

| P1 | Hex | Name |
|----|-----|------|
| `P1_CVOTE_INIT` | `0x50` | Begin votecast |
| `P1_CVOTE_CHUNK` | `0x51` | Additional votecast data |
| `P1_CVOTE_CONFIRM` | `0x52` | Witness path + confirmation |

#### INIT — P1 `0x50`

```
Command:  CLA=0xD7  INS=0x23  P1=0x50  P2=0x00  Lc=Lc

┌──────────────────────────┬──────────────────┬───────────────┬──────────────────┬────────────────────────┐
│ total_votecast_length    │  vote_plan_id    │proposal_index │payload_type_tag  │  first_chunk_bytes     │
│  4 B BE uint32           │    32 bytes      │    1 byte     │    1 byte        │  remaining APDU bytes  │
└──────────────────────────┴──────────────────┴───────────────┴──────────────────┴────────────────────────┘
```

- `total_votecast_length`: total byte count of the full votecast payload.
- `vote_plan_id`, `proposal_index`, `payload_type_tag`: extracted and displayed to user.
- The remaining bytes of this APDU are treated as the first chunk of the votecast data
  (up to `MAX_VOTECAST_CHUNK_SIZE = 250` bytes, including the header fields above).

**Response:** `SW=9000`

#### CHUNK — P1 `0x51`

```
Command:  CLA=0xD7  INS=0x23  P1=0x51  P2=0x00  Lc=Lc
Data:     votecast bytes chunk (exactly min(remaining, 250) bytes)
Response: SW=9000
```

Each chunk must be exactly `min(remaining_votecast_bytes, MAX_VOTECAST_CHUNK_SIZE)`.

#### CONFIRM — P1 `0x52`

```
Command:  CLA=0xD7  INS=0x23  P1=0x52  P2=0x00  Lc=Lc
Data:     BIP44 path  ← witness signing path
```

**Response (after user confirms):**

| Field               | Size  | Description                                                    |
|---------------------|-------|----------------------------------------------------------------|
| `votecast_hash`     | 32 B  | Blake2b-256 hash of the entire votecast payload               |
| `witness_signature` | 64 B  | Ed25519 signature of `votecast_hash` with the supplied key path|

---

## 10. CIP-8 Message Signing

### 10.1 SIGN\_MSG — `0x24`

Signs an arbitrary message according to [CIP-8](https://cips.cardano.org/cip/CIP-0008).
CIP-8 uses **COSE** (CBOR Object Signing and Encryption, RFC 9052): the device
constructs a `Sig_structure` — a CBOR array containing the protected header,
optional external AAD, and payload — then signs its hash with the requested Ed25519 key.

#### Flow overview

```
Host                                        Device
  |                                            |
  |----  INIT (P1=0x01)  --------------------> |  Metadata + signing path
  | <--  SW=9000  ---------------------------- |
  |                                            |
  |----  CHUNK (P1=0x02) x 0..N  ------------> |  Message data (250 B each)
  | <--  SW=9000  ---------------------------- |
  |                                            |
  |----  CONFIRM (P1=0x03, empty)  ----------> |  Trigger UI review
  |                        [User approves]     |
  | <--  sig(64) + pubkey(32) + addrLen(4) + addr(var) + SW=9000
```

P1 values:

| P1 | Hex | Name |
|----|-----|------|
| `P1_SIGN_MSG_INIT` | `0x01` | Begin message signing |
| `P1_SIGN_MSG_CHUNK` | `0x02` | Message data chunk |
| `P1_SIGN_MSG_CONFIRM` | `0x03` | Confirm (empty APDU) |

#### INIT — P1 `0x01`

```
Command:  CLA=0xD7  INS=0x24  P1=0x01  P2=0x00  Lc=Lc

┌─────────────────┬───────────────┬─────────────┬──────────┬──────────────────────────┬──────────────────┐
│  msg_length     │  signing_path │ hash_payload│ is_ascii │  address_field_type      │  address_params  │
│  4 B BE uint32  │  BIP44 path   │   flag      │  flag    │  1 byte (see below)      │  (if type=0x01)  │
└─────────────────┴───────────────┴─────────────┴──────────┴──────────────────────────┴──────────────────┘
```

| `address_field_type` | Value | Meaning | Extra payload |
|----------------------|-------|---------|---------------|
| `CIP8_ADDRESS_FIELD_ADDRESS` | `0x01` | Full address in COSE header | `address_params` (variable) |
| `CIP8_ADDRESS_FIELD_KEYHASH` | `0x02` | Signing key hash in COSE header | — |

- `hash_payload` flag: if `FLAG_INCLUDED_YES`, the payload in the COSE Sig\_structure is
  Blake2b-224(`message`) rather than the raw message.
- `is_ascii` flag: if `FLAG_INCLUDED_YES`, the device validates the message is printable ASCII
  and displays it as text; otherwise displayed as hex.
- `msg_length = 0` is valid (empty message); CHUNK stage is skipped.

**Response:** `SW=9000`

#### CHUNK — P1 `0x02`

```
Command:  CLA=0xD7  INS=0x24  P1=0x02  P2=0x00  Lc=Lc

┌──────────────┬──────────────────────────────────┐
│  chunk_size  │  chunk_data                       │
│  4 B BE u32  │  chunk_size bytes                 │
└──────────────┴──────────────────────────────────┘
```

Each chunk size must be exactly `min(remaining_bytes, MAX_CIP8_MSG_CHUNK_SIZE = 250)`.

**Response:** `SW=9000`

#### CONFIRM — P1 `0x03`

Must be sent with an empty data field (`Lc = 0`).

```
Command:  CLA=0xD7  INS=0x24  P1=0x03  P2=0x00  Lc=0x00
```

**Response (after user approves):**

```
signature(64) ‖ witness_pubkey(32) ‖ address_field_size(4 BE) ‖ address_field(variable)
```

| Field | Size | Description |
|-------|------|-------------|
| `signature` | 64 B | Ed25519 signature over the COSE Sig\_structure |
| `witness_pubkey` | 32 B | Public key of the signing path |
| `address_field_size` | 4 B BE | Byte length of `address_field` |
| `address_field` | variable (≤ 128 B) | Full address bytes or 28-byte key hash, depending on `address_field_type` |

**What is signed:** The assembled `Sig_structure` is:
```
[
  "Signature1",
  CBOR({ 1: -8, "address": address_field }),  ← protected header
  h'',                                          ← empty external AAD
  payload                                       ← hash(msg) or raw msg
]
```
and signs it with the key at `signing_path`.

---

## 11. Status Words

Every APDU response ends with a 2-byte status word (SW).  `0x9000` means success; any
other value signals an error with no response data.  The tables below list all values
the app can return, grouped by origin and category.

### SDK standard words (reused from ISO 7816-4)

| SW | Name | Meaning |
|----|------|---------|
| `0x9000` | `SWO_SUCCESS` | Command succeeded |
| `0x6982` | `SWO_SECURITY_CONDITION_NOT_SATISFIED` | Security policy denied the operation |
| `0x6980` | `SWO_COMMAND_NOT_ALLOWED` | Command not allowed in current state |
| `0x6a84` | `SWO_INSUFFICIENT_MEMORY` | Device out of memory |
| `0x6a86` | `SWO_INCORRECT_P1_P2` | P1 or P2 incorrect |
| `0x6a87` | `SWO_WRONG_DATA_LENGTH` | Data field wrong length |
| `0x6d00` | `SWO_INVALID_INS` | Unknown instruction byte |
| `0x6E04` | `SWO_STILL_IN_CALL_RESET_DONE` | Stale request reset; host may retry |

### Cardano app-specific errors (`0x6BXX`)

#### Transaction init / structure

| SW | Name | Meaning |
|----|------|---------|
| `0x6B00` | `SWO_INVALID_TX_LENGTH` | TX length out of range or mismatch |
| `0x6B01` | `SWO_TX_PARSING_FAIL` | Generic TX parse failure |
| `0x6B02` | `SWO_WRONG_TX_INIT_APDU_DATA` | Malformed INIT APDU structure |
| `0x6B3C` | `SWO_INVALID_TX_SIGNING_MODE` | Unknown signing mode byte |
| `0x6B3D` | `SWO_AMBIGUOUS_TX_SIGNING_MODE` | AUTO mode cannot be resolved |
| `0x6B37` | `SWO_INVALID_NETWORK_ID` | Network ID out of range |
| `0x6B38` | `SWO_INVALID_PROTOCOL_MAGIC` | Protocol magic inconsistent with network ID |
| `0x6B39` | `SWO_TX_PARSING_FAIL_INCLUSION_FLAG` | Bad inclusion flag value |
| `0x6B3A` | `SWO_TX_PARSING_FAIL_BUFFER_NOT_FULLY_CONSUMED` | Extra bytes in TX body |
| `0x6B3B` | `SWO_TX_PARSING_FAIL_CANONICAL_ORDER` | CBOR map keys not in canonical order |

#### Transaction body field parsing (keyed by CBOR map key)

| SW | CBOR key | Field name |
|----|----------|------------|
| `0x6B20` | 0 | inputs |
| `0x6B21` | 1 | outputs |
| `0x6B22` | 2 | fee |
| `0x6B23` | 3 | TTL |
| `0x6B24` | 4 | certificates |
| `0x6B25` | 5 | withdrawals |
| `0x6B28` | 8 | validity interval start |
| `0x6B29` | 9 | mint |
| `0x6B2B` | 11 | script data hash |
| `0x6B2D` | 13 | collateral inputs |
| `0x6B2E` | 14 | required signers |
| `0x6B30` | 16 | collateral output |
| `0x6B31` | 17 | total collateral |
| `0x6B32` | 18 | reference inputs |
| `0x6B33` | 19 | voting procedures |
| `0x6B35` | 21 | treasury |
| `0x6B36` | 22 | donation |

#### BIP44 and address

| SW | Name | Meaning |
|----|------|---------|
| `0x6B05` | `SWO_BIP44_PATH_PARSING_FAIL` | BIP44 path malformed |
| `0x6B06` | `SWO_DERIVE_ADDRESS_PARSING_FAIL_ADDRESS_PARAMS` | Address params malformed |

#### Operational certificate

| SW | Name | Meaning |
|----|------|---------|
| `0x6B10` | `SWO_OPCERT_PARSING_FAIL_KES_KEY` | KES public key parse failure |
| `0x6B11` | `SWO_OPCERT_PARSING_FAIL_KES_PERIOD` | KES period parse failure |
| `0x6B12` | `SWO_OPCERT_PARSING_FAIL_ISSUE_COUNTER` | Issue counter parse failure |
| `0x6B13` | `SWO_OPCERT_PARSING_FAIL_POOL_KEY_PATH` | Pool cold key path parse failure |
| `0x6B14` | `SWO_INVALID_OPCERT_LENGTH` | Op-cert byte count out of range |

#### Native script

| SW | Name | Meaning |
|----|------|---------|
| `0x6B41` | `SWO_NATIVE_SCRIPT_PARSING_FAIL_PUBKEY_CREDENTIAL` | Bad pubkey credential in script |
| `0x6B42` | `SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_TYPE` | Unknown script type byte |
| `0x6B43` | `SWO_NATIVE_SCRIPT_PARSING_FAIL_NESTING` | Script provided when none expected |
| `0x6B44` | `SWO_NATIVE_SCRIPT_PARSING_FAIL_TIMELOCK` | Timelock slot number parse failure |
| `0x6B45` | `SWO_NATIVE_SCRIPT_PARSING_FAIL_DEPTH_UNSUPPORTED` | Nesting depth > 10 |
| `0x6B46` | `SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_COUNT` | required > total in N-of-K |
| `0x6B47` | `SWO_NATIVE_SCRIPT_PARSING_FAIL_DISPLAY_FORMAT` | Unknown display format byte |

#### CVote auxiliary data (§7.5 TX sub-flow)

| SW | Name | Meaning |
|----|------|---------|
| `0x6B50` | `SWO_CVOTE_AUX_DATA_PARSING_FAIL` | CVote registration init or delegation parse failure |

#### CIP-36 vote cast (§9.1 SIGN\_CVOTE)

| SW | Name | Meaning |
|----|------|---------|
| `0x6B51` | `SWO_CVOTE_PARSING_FAIL_VOTE_PLAN_ID` | Vote plan ID missing |
| `0x6B52` | `SWO_CVOTE_PARSING_FAIL_PROPOSAL_INDEX` | Proposal index missing |
| `0x6B53` | `SWO_CVOTE_PARSING_FAIL_PAYLOAD_TYPE_TAG` | Payload type tag missing |
| `0x6B54` | `SWO_CVOTE_PARSING_FAIL_REMAINING_VOTECAST_BYTES` | Total length field missing |

#### CIP-8 message signing

| SW | Name | Meaning |
|----|------|---------|
| `0x6B60` | `SWO_SIGN_MSG_PARSING_FAIL_MSG_LENGTH` | Message length field missing |
| `0x6B61` | `SWO_SIGN_MSG_PARSING_FAIL_SIGNING_PATH` | Signing path parse failure |
| `0x6B62` | `SWO_SIGN_MSG_PARSING_FAIL_HASH_PAYLOAD` | Hash-payload flag missing |
| `0x6B63` | `SWO_SIGN_MSG_PARSING_FAIL_IS_ASCII` | isAscii flag missing |
| `0x6B64` | `SWO_SIGN_MSG_PARSING_FAIL_ADDRESS_FIELD_TYPE` | Address field type byte missing |
| `0x6B65` | `SWO_SIGN_MSG_PARSING_FAIL_ADDRESS_PARAMS` | Address params parse failure |
| `0x6B66` | `SWO_SIGN_MSG_PARSING_FAIL_CHUNK_SIZE` | Chunk size field missing |
| `0x6B67` | `SWO_SIGN_MSG_PARSING_FAIL_CHUNK_DATA` | Chunk data truncated |
| `0x6B68` | `SWO_SIGN_MSG_INVALID_CHUNK_SIZE` | Chunk size ≠ expected |
| `0x6B69` | `SWO_SIGN_MSG_INVALID_ASCII` | Message fails ASCII validation |
| `0x6B6A` | `SWO_SIGN_MSG_INVALID_ADDRESS_FIELD_TYPE` | Unknown address field type byte |
| `0x6B6B` | `SWO_SIGN_MSG_CONFIRM_MUST_BE_EMPTY` | CONFIRM APDU must carry no data |

#### Swap / library mode

| SW | Name | Meaning |
|----|------|---------|
| `0x6001` | `SWO_SWAP_CHECKING_FAIL` | Swap parameter validation failed |

---

## 12. Debug Commands

### DEBUG\_SET\_SETTINGS — `0xF0`

Available **only in debug builds** (`#ifdef DEBUG`).  Allows tests to manipulate
app settings (e.g. expert mode, blind signing) without physical button presses.

```
Command:  CLA=0xD7  INS=0xF0  P1=0x00  P2=0x00  Lc=Lc
Data:     settings payload (see src/handler/debug_settings.c)
Response: SW=9000
```

This instruction is not present in production builds and must never be relied upon
in production integrations.

