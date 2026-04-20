/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

// SDK status words (ISO 7816-4 standard)
#include <status_words.h>

typedef enum {
    // Success: returned by parse_* functions to indicate no error.
    // Any nonzero value is a specific error code.
    SWO_OK = 0x0000,

    // Cardano app-specific status words (primarily 0x6BXX range)
    // ISO 7816-4 compliant: 0x6BXX is standard "proprietary" range for wrong parameters
    SWO_INVALID_TX_LENGTH = 0x6B00,
    SWO_TX_PARSING_FAIL = 0x6B01,
    SWO_WRONG_TX_INIT_APDU_DATA = 0x6B02,  // malformed TX INIT APDU structure
    SWO_BIP44_PATH_PARSING_FAIL = 0x6B05,
    SWO_DERIVE_ADDRESS_PARSING_FAIL_ADDRESS_PARAMS = 0x6B06,  // failed to parse address params
    SWO_OPCERT_PARSING_FAIL_KES_KEY = 0x6B10,
    SWO_OPCERT_PARSING_FAIL_KES_PERIOD = 0x6B11,
    SWO_OPCERT_PARSING_FAIL_ISSUE_COUNTER = 0x6B12,
    SWO_OPCERT_PARSING_FAIL_POOL_KEY_PATH = 0x6B13,
    SWO_INVALID_OPCERT_LENGTH = 0x6B14,
    // Native script parsing errors
    SWO_NATIVE_SCRIPT_PARSING_FAIL_PUBKEY_CREDENTIAL = 0x6B41,  // pubkey credential parsing
    SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_TYPE = 0x6B42,        // invalid script type value
    SWO_NATIVE_SCRIPT_PARSING_FAIL_NESTING = 0x6B43,            // unexpected script depth/nesting
    SWO_NATIVE_SCRIPT_PARSING_FAIL_TIMELOCK = 0x6B44,           // timelock parsing
    SWO_NATIVE_SCRIPT_PARSING_FAIL_DEPTH_UNSUPPORTED = 0x6B45,  // supported depth exceeded
    SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_COUNT = 0x6B46,       // invalid script count/structure
    SWO_NATIVE_SCRIPT_PARSING_FAIL_DISPLAY_FORMAT = 0x6B47,     // invalid display format value
    // Transaction body field parsing errors
    // Organized by CBOR key as per Cardano CDDL: error = 0x6B20 + CBOR_KEY
    SWO_TX_PARSING_FAIL_INPUTS = 0x6B20,                   // key 0
    SWO_TX_PARSING_FAIL_OUTPUTS = 0x6B21,                  // key 1
    SWO_TX_PARSING_FAIL_FEE = 0x6B22,                      // key 2
    SWO_TX_PARSING_FAIL_TTL = 0x6B23,                      // key 3
    SWO_TX_PARSING_FAIL_CERTIFICATES = 0x6B24,             // key 4
    SWO_TX_PARSING_FAIL_WITHDRAWALS = 0x6B25,              // key 5
    SWO_TX_PARSING_FAIL_VALIDITY_INTERVAL_START = 0x6B28,  // key 8
    SWO_TX_PARSING_FAIL_MINT = 0x6B29,                     // key 9
    SWO_TX_PARSING_FAIL_SCRIPT_DATA_HASH = 0x6B2B,         // key 11
    SWO_TX_PARSING_FAIL_COLLATERAL_INPUTS = 0x6B2D,        // key 13
    SWO_TX_PARSING_FAIL_REQUIRED_SIGNERS = 0x6B2E,         // key 14
    SWO_TX_PARSING_FAIL_COLLATERAL_OUTPUT = 0x6B30,        // key 16
    SWO_TX_PARSING_FAIL_TOTAL_COLLATERAL = 0x6B31,         // key 17
    SWO_TX_PARSING_FAIL_REFERENCE_INPUTS = 0x6B32,         // key 18
    SWO_TX_PARSING_FAIL_VOTING_PROCEDURES = 0x6B33,        // key 19
    SWO_TX_PARSING_FAIL_TREASURY = 0x6B35,                 // key 21
    SWO_TX_PARSING_FAIL_DONATION = 0x6B36,                 // key 22

    // CVote auxiliary data parsing errors
    SWO_CVOTE_AUX_DATA_PARSING_FAIL = 0x6B50,  // CVote aux data (init or delegation) parsing error

    // Network/Protocol validation errors
    SWO_INVALID_NETWORK_ID = 0x6B37,      // network ID mismatch
    SWO_INVALID_PROTOCOL_MAGIC = 0x6B38,  // protocol magic mismatch

    // Transaction structure errors
    SWO_TX_PARSING_FAIL_INCLUSION_FLAG = 0x6B39,             // optional field flag error
    SWO_TX_PARSING_FAIL_BUFFER_NOT_FULLY_CONSUMED = 0x6B3A,  // extra data in buffer
    SWO_TX_PARSING_FAIL_CANONICAL_ORDER = 0x6B3B,            // CBOR canonical ordering
    SWO_INVALID_TX_SIGNING_MODE = 0x6B3C,    // unknown or unsupported tx signing mode
    SWO_AMBIGUOUS_TX_SIGNING_MODE = 0x6B3D,  // AUTO mode cannot determine signing mode from tx

    SWO_CVOTE_PARSING_FAIL_REMAINING_VOTECAST_BYTES =
        0x6B54,                                        // failed to read remaining votecast bytes
    SWO_CVOTE_PARSING_FAIL_VOTE_PLAN_ID = 0x6B51,      // failed to read vote plan id
    SWO_CVOTE_PARSING_FAIL_PROPOSAL_INDEX = 0x6B52,    // failed to read proposal index
    SWO_CVOTE_PARSING_FAIL_PAYLOAD_TYPE_TAG = 0x6B53,  // failed to read payload type tag

    // Message signing (CIP-8) parsing/validation errors (0x6B60-0x6B6F range)
    SWO_SIGN_MSG_PARSING_FAIL_MSG_LENGTH = 0x6B60,          // failed to parse message length
    SWO_SIGN_MSG_PARSING_FAIL_SIGNING_PATH = 0x6B61,        // failed to parse signing path
    SWO_SIGN_MSG_PARSING_FAIL_HASH_PAYLOAD = 0x6B62,        // failed to parse hash payload flag
    SWO_SIGN_MSG_PARSING_FAIL_IS_ASCII = 0x6B63,            // failed to parse isAscii flag
    SWO_SIGN_MSG_PARSING_FAIL_ADDRESS_FIELD_TYPE = 0x6B64,  // failed to parse address field type
    SWO_SIGN_MSG_PARSING_FAIL_ADDRESS_PARAMS = 0x6B65,      // failed to parse address params
    SWO_SIGN_MSG_PARSING_FAIL_CHUNK_SIZE = 0x6B66,          // failed to parse chunk size
    SWO_SIGN_MSG_PARSING_FAIL_CHUNK_DATA = 0x6B67,          // failed to parse chunk data
    SWO_SIGN_MSG_INVALID_CHUNK_SIZE = 0x6B68,               // chunk size validation failed
    SWO_SIGN_MSG_INVALID_ASCII = 0x6B69,                    // ASCII validation failed
    SWO_SIGN_MSG_INVALID_ADDRESS_FIELD_TYPE = 0x6B6A,       // invalid address field type
    SWO_SIGN_MSG_CONFIRM_MUST_BE_EMPTY = 0x6B6B,            // confirm APDU must be empty

    // Swap validation errors
    SWO_SWAP_CHECKING_FAIL = 0x6001,  // swap parameter validation failed

    // Stale-call recovery: a new instruction arrived while a previous (non-UX) request was still
    // in progress. The dispatcher has reset the app to idle before returning this status; the host
    // may safely retry the first APDU of the new operation once. Must NOT be emitted when a
    // deferred UX response is still pending — that case continues to return
    // SWO_COMMAND_NOT_ALLOWED. Value and semantics match the old Cardano app's ERR_STILL_IN_CALL,
    // so LedgerJS' existing retry-once wrapper works unchanged.
    SWO_STILL_IN_CALL_RESET_DONE = 0x6E04,
} cardano_status_word_t;
