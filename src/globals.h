/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "os.h"
#include "ux.h"
#include "cardano_constants.h"
#include "bip32.h"
#include "securityWarnings.h"
#include "securityPolicyType.h"
#include "cvote_types.h"
#include "cvote_parser.h"
#include "tx.h"
#include "opcert_types.h"
#include "deriveNativeScriptHash_types.h"
#include "dispatcher.h"
#include "derive_native_script_hash.h"
#include "keyDerivation.h"
#include "addressUtilsShelley.h"
#include "cvote/vote_cast_hash_builder.h"
#include "messageSigning.h"
#include "hash.h"
#include "ui_constants.h"
#include "tx_processing.h"
/**
 * State machine for transaction processing.
 * Tracks the progression through receiving, parsing, hashing, UI preparation, and approval.
 */
typedef enum {
    TX_STATE_NONE,       /// idle
    TX_STATE_AUX_DATA,   /// receiving CVote aux data
    TX_STATE_CHUNKS,     /// receiving transaction chunks
    TX_STATE_RECEIVED,   /// all chunks received, waiting to parse
    TX_STATE_HASHED,     /// hash computed, UI plan ready
    TX_STATE_UI_REVIEW,  /// transaction review in progress (full or streaming)
    TX_STATE_APPROVED    /// user approved, waiting for witnesses
} tx_state_e;

/**
 * State machine for operational certificate signing.
 * Tracks the progression through parsing, validation, and approval phases.
 */
typedef enum {
    OPCERT_STATE_NONE,       /// idle
    OPCERT_STATE_PARSED,     /// parsed from bytes, waiting for policy validation
    OPCERT_STATE_VALIDATED,  /// parsed and security policy validated, waiting for approval
    OPCERT_STATE_APPROVED    /// user approved, waiting for signature
} opcert_state_e;

/**
 * State machine for address derivation operation.
 * Tracks the progression through parsing, validation, and derivation phases.
 */
typedef enum {
    DERIVE_ADDRESS_STATE_NONE,       /// idle
    DERIVE_ADDRESS_STATE_PARSED,     /// parameters parsed, waiting for policy validation
    DERIVE_ADDRESS_STATE_VALIDATED,  /// parameters parsed, security policy validated
    DERIVE_ADDRESS_STATE_PREPARED    /// address derived and ready
} derive_address_state_e;

/**
 * State machine for CVote votecast operation.
 * Tracks the progression through initialization, reception, and confirmation phases.
 */
typedef enum {
    VOTECAST_STATE_NONE = 0,
    VOTECAST_STATE_INIT,
    VOTECAST_STATE_CHUNK,
    VOTECAST_STATE_CONFIRM,
} cvote_state_e;

/**
 * State machine for CIP-8 message signing operation.
 * Tracks the progression through initialization, message chunk reception, and confirmation phases.
 */
typedef enum {
    SIGN_MSG_STATE_NONE = 0,
    SIGN_MSG_STATE_INIT,
    SIGN_MSG_STATE_CHUNK,
    SIGN_MSG_STATE_CONFIRM,
} sign_msg_state_e;

/**
 * State machine for extended public key export operation.
 * Tracks parsing, policy validation and export finalization.
 */
typedef enum {
    PUBKEY_STATE_NONE = 0,
    PUBKEY_STATE_PARSED,
    PUBKEY_STATE_VALIDATED,
    PUBKEY_STATE_APPROVED,
} pubkey_state_e;

/**
 * Tracks stored account metadata for the single-account security model.
 */
typedef struct {
    bool isStored;
    bool isByron;
    uint32_t accountNumber;
} single_account_data_t;

/**
 * Transaction context (covers raw tx buffer + witness bookkeeping).
 */
typedef struct {
    tx_params_t tx_params;
    uint8_t tx_hash[TX_HASH_LENGTH];

    uint16_t num_witnesses;  /// Total witnesses requested by host; not decremented during signing.
    uint16_t raw_tx_total_length;  /// Advertised raw tx size from INIT APDU (must survive AUX_DATA
                                   /// stage).

    /**
     * Fields that must survive across all stages (body + witnesses).
     * Set during body processing, read during witness policy checks.
     */
    bool pool_owner_path_present;
    bip44_path_t pool_owner_path;
    single_account_data_t single_account_data;

    /**
     * Per-stage context. Only one slot is valid at a time, gated by tx_state:
     *   TX_STATE_AUX_DATA                          -> aux_data
     *   TX_STATE_CHUNKS .. TX_STATE_UI_REVIEW    -> body
     *   TX_STATE_APPROVED                          -> witness
     *
     * Access exclusively via tx_aux_data_ctx() / tx_body_ctx() / tx_witness_ctx()
     * in sign_tx_ctx.h, which assert the correct state.
     */
    union {
        /// Valid during TX_STATE_AUX_DATA. Zeroed atomically at tx init.
        struct {
            uint8_t *raw_cvote_init_data;  /// Raw APDU buffer for CVote init
            size_t raw_cvote_init_data_len;
            cvote_aux_data_t cvote_aux_data;    /// Parsed CVote data
            warning_bits_t cvote_warning_bits;  /// CVote AUX_DATA warnings only
        } aux_data;

        /// Valid during TX_STATE_CHUNKS .. TX_STATE_UI_REVIEW. Zeroed atomically at tx init.
        struct {
            uint8_t *raw_tx;
            size_t raw_tx_current_length;  /// Actual received length so far
            warning_bits_t warning_bits;   /// Transaction warnings
            /// Scratch copy of warning_bits used by the render pass so it cannot mutate
            /// the canonical warnings; request-scoped so no stack address escapes into
            /// processing_state (see tx_render_ui_chunk).
            warning_bits_t render_run_warnings;
            uint16_t total_ui_pairs;
            uint16_t rendered_ui_pairs;  /// Number of pairs rendered so far (start of next chunk)
            bool streaming_mode;         /// True when using streaming NBGL API
            tx_ui_review_mode_e review_mode;  /// Current ui review mode
            /// Mutable parse state; lives in globals to keep tx_hash_builder_t off the stack.
            tx_processing_state_t processing_state;
        } body;

        /// Valid during TX_STATE_APPROVED. Initialized at witness stage entry.
        struct {
            uint16_t current_witness;  /// Number of witnesses already processed.
            bip44_path_t witness_path;
            char witness_path_str[MAX_BIP44_PATH_STRING_LENGTH + UI_BUFFER_SAFETY_MARGIN];
            uint8_t witness_signature[ED25519_SIGNATURE_LENGTH];
        } witness;
    };
} transaction_ctx_t;

/**
 * Operational certificate context.
 */
#define MAX_OPCERT_LENGTH                                                         \
    (KES_PUBLIC_KEY_LENGTH + OPCERT_KES_PERIOD_SIZE + OPCERT_ISSUE_COUNTER_SIZE + \
     BIP44_MAX_PATH_SIZE)

typedef struct {
    uint8_t raw_opcert[MAX_OPCERT_LENGTH];
    size_t raw_opcert_len;
    parsed_opcert_t opcert;
    warning_bits_t warnings;
    uint8_t signature[ED25519_SIGNATURE_LENGTH];
} sign_opcert_ctx_t;

/*
    Derive native script hash context.
*/
typedef struct {
    uint8_t level;
    // stores information about a complex script at the index level
    complex_native_script_t complexScripts[MAX_SCRIPT_DEPTH];

    uint8_t scriptHashBuffer[SCRIPT_HASH_LENGTH];
    native_script_hash_builder_t hashBuilder;

    native_script_content_t scriptContent;

    // ui native script state
    ui_native_script_type ui_scriptType;
} derive_native_script_hash_ctx_t;

/**
 * Exposed context for public-key exports.
 */
typedef struct {
    bool silentExport;
    bip44_path_t path;
    char path_str[MAX_BIP44_PATH_STRING_LENGTH +
                  UI_BUFFER_SAFETY_MARGIN];  // Static buffer for NBGL UI
    extendedPublicKey_t extPubKey;
} pubkey_ctx_t;

/**
 * Structure for derive address information context.
 * hashStorage buffers own copies of any script/key hashes that originally
 * pointed into a transient APDU buffer.
 */
typedef struct {
    address_params_t address_params;
    address_params_hashes_storage_t hashStorage;
    bool should_export_address;
    struct {
        uint8_t buffer[MAX_ADDRESS_LENGTH];
        size_t length;
    } address;
    // Persistent human-readable address buffer for NBGL flows that keep pointers.
    char humanAddress[MAX_HUMAN_ADDRESS_LENGTH];
} derive_address_ctx_t;

#define MAX_VOTECAST_CHUNK_SIZE 250
#define VOTE_PLAN_ID_SIZE       32
#define VOTECAST_HASH_LENGTH    32

/**
 * Context for signing a CVote votecast.
 */
typedef struct {
    uint32_t remaining_votecast_bytes;
    votecast_hash_builder_t votecast_hash_builder;
    uint8_t vote_plan_id[VOTE_PLAN_ID_SIZE];
    uint8_t proposal_index;
    uint8_t payload_type_tag;
    bip44_path_t witness_path;
    uint8_t witness_signature[ED25519_SIGNATURE_LENGTH];
} cvote_ctx_t;

// CIP-8 message signing constants
#define CIP8_MSG_HASH_LENGTH 28

/**
 * Context for CIP-8 message signing.
 * hashStorage buffers own copies of any script/key hashes that originally
 * pointed into the INIT APDU buffer (which is gone by CONFIRM stage).
 */
typedef struct {
    bip44_path_t signingPath;
    cip8_address_field_type_t addressFieldType;
    address_params_t address_params;
    address_params_hashes_storage_t hashStorage;

    bool isAscii;
    bool hashPayload;

    uint16_t msgLength;
    uint16_t remainingBytes;

    // Dynamically allocated buffer accumulating all received chunks.
    // Allocated in INIT with size msgLength via APP_MEM_CALLOC.
    uint8_t *msgBuffer;
    uint16_t msgBufferSize;

    blake2b_224_context_t msgHashCtx;
    uint8_t msgHash[CIP8_MSG_HASH_LENGTH];
    uint8_t *sigStructureBuffer;
    uint16_t sigStructureSize;
    uint8_t signature[ED25519_SIGNATURE_LENGTH];
    uint8_t witnessKey[PUBLIC_KEY_LENGTH];
    uint8_t addressField[MAX_ADDRESS_LENGTH];
    size_t addressFieldSize;

    security_policy_t signing_policy;
    warning_bits_t warnings;
} sign_msg_ctx_t;

/**
 * Global context for user requests.
 */
typedef struct {
    union {
        tx_state_e tx_state;
        opcert_state_e opcert_state;
        derive_address_state_e derive_address_state;
        cvote_state_e cvote_state;
        sign_msg_state_e sign_msg_state;
        pubkey_state_e pubkey_state;
    } state;

    union {
        pubkey_ctx_t pk_info;
        transaction_ctx_t tx_info;
        sign_opcert_ctx_t opcert_info;
        derive_address_ctx_t derive_address_info;
        derive_native_script_hash_ctx_t derive_native_script_hash_info;
        cvote_ctx_t cvote_info;
        sign_msg_ctx_t sign_msg_info;
    };

    request_type_e req_type;
} global_ctx_t;

extern global_ctx_t G_context;

/**
 * Global structure for NVM data storage.
 */
typedef struct internal_storage_t {
    uint8_t expert_mode_enabled;
    uint8_t silent_pubkey_export_enabled;
    uint8_t blind_signing_enabled;
    uint8_t initialized;
} internal_storage_t;

extern const internal_storage_t N_storage_real;
#define N_storage (*(volatile internal_storage_t *) PIC(&N_storage_real))
