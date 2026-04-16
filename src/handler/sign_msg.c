/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "utils.h"
#include "buffer.h"
#include "sign_msg.h"
#include "cardano_swo.h"
#include "globals.h"
#include "addressUtilsShelley.h"
#include "securityPolicy.h"
#include "assert.h"
#include "app_context.h"
#include "io.h"
#include "cardano_parsers.h"
#include "cardano_buffer.h"
#include "messageSigning.h"
#include "ui_sign_msg.h"
#include "keyDerivation.h"
#include "textUtils.h"
#include "cbor.h"
#include "nbgl_use_case.h"
#include "app_mem_utils.h"

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_HANDLERS to trace handler-level flow.
 */
#ifdef TRACE_HANDLERS
#define TRACE_MODULE(...) TRACE("[sign_msg] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif

// Overhead for Sig_structure CBOR encoding:
// - 1 byte array(4) header
// - 1 + 10 bytes "Signature1" text
// - up to 3 + (MAX_ADDRESS_LENGTH + 32) bytes protectedHeader as bstr
// - 1 byte empty external_aad
// - up to 5 bytes payload bstr length header
// Conservative fixed overhead (covers all CBOR tokens + protectedHeader).
#define SIG_STRUCTURE_OVERHEAD 256
// Keep a compile-time margin tied to MAX_ADDRESS_LENGTH to catch future growth.
#define SIG_STRUCTURE_OVERHEAD_MIN_REQUIRED (MAX_ADDRESS_LENGTH + 40)
STATIC_ASSERT(SIG_STRUCTURE_OVERHEAD >= SIG_STRUCTURE_OVERHEAD_MIN_REQUIRED,
              "SIG_STRUCTURE_OVERHEAD is too small");

static bool ensure_sign_msg_request_type(request_type_e required_request_type) {
    if (G_context.req_type != required_request_type) {
        TRACE_MODULE("Rejecting sign_msg command for req_type %d (expected %d)",
                     G_context.req_type,
                     required_request_type);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }
    return true;
}

static bool ensure_sign_msg_state(sign_msg_state_e required_state) {
    if (G_context.state.sign_msg_state != required_state) {
        TRACE_MODULE("Rejecting sign_msg command in state %d (expected %d)",
                     G_context.state.sign_msg_state,
                     required_state);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }
    return true;
}

static bool is_msg_length_valid_for_sign_msg_init(uint32_t message_length,
                                                  bool hash_payload,
                                                  bool is_ascii) {
    // msgBuffer allocation in INIT uses uint16_t-sized APP_MEM_CALLOC.
    // Caller already checked message_length <= UINT16_MAX before setting ctx->msgLength (uint16_t).
    LEDGER_ASSERT(message_length <= UINT16_MAX, "message_length > UINT16_MAX");

    // UI formatting allocates max_len + UI_BUFFER_SAFETY_MARGIN where safety margin is 2 bytes.
    // Keep these guards in sync with UI_ADD_FORMAT2 allocation constraints.
    if (is_ascii) {
        // ASCII messages are displayed as-is: max_len = message_length.
        const size_t ui_ascii_display_allocation_size = (size_t) message_length + 2;
        if (ui_ascii_display_allocation_size > UINT16_MAX) {
            return false;
        }
    } else {
        // Non-ASCII messages are displayed as hex: max_len = 2 * message_length + 1.
        const size_t max_hex_display_length = 2 * (size_t) message_length + 1;
        const size_t ui_hex_display_allocation_size = max_hex_display_length + 2;
        if (ui_hex_display_allocation_size > UINT16_MAX) {
            return false;
        }
    }

    // Non-hashed payload uses raw message bytes as Sig_structure payload.
    if (!hash_payload) {
        const size_t sig_structure_max_size = SIG_STRUCTURE_OVERHEAD + (size_t) message_length;
        if (sig_structure_max_size > UINT16_MAX) {
            return false;
        }
    }

    return true;
}

// ============================== INIT ==============================

static void signMsg_handle_init(buffer_t *cdata) {
    ASSERT(cdata != NULL);
    ASSERT(G_context.state.sign_msg_state == SIGN_MSG_STATE_INIT);

    sign_msg_ctx_t *ctx = &G_context.sign_msg_info;

    // Parse INIT APDU payload:
    // [4 bytes: msgLength] [BIP44 path] [1 byte: hashPayload] [1 byte: isAscii]
    // [1 byte: addressFieldType] [address_params if addressFieldType == ADDRESS]

    uint32_t msg_length_from_wire = 0;
    if (!buffer_read_u32(cdata, &msg_length_from_wire, BE)) {
        TRACE("Failed to read msgLength");
        send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_MSG_LENGTH);
        return;
    }
    TRACE_MODULE("Message length = %u", msg_length_from_wire);
    if (msg_length_from_wire > UINT16_MAX) {
        TRACE("Message length out of uint16 range: %u", msg_length_from_wire);
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }
    ctx->msgLength = (uint16_t) msg_length_from_wire;

    if (!buffer_read_bip44_path(cdata, &ctx->signingPath)) {
        TRACE("Failed to read signing path");
        send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_SIGNING_PATH);
        return;
    }
    TRACE_MODULE("Signing path:");
#ifdef TRACE_HANDLERS
    BIP44_PRINTF(&ctx->signingPath);
#endif

    if (!buffer_read_flag_included(cdata, &ctx->hashPayload)) {
        TRACE("Failed to read hashPayload");
        send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_HASH_PAYLOAD);
        return;
    }
    TRACE_MODULE("Hash payload = %d", ctx->hashPayload);

    if (!buffer_read_flag_included(cdata, &ctx->isAscii)) {
        TRACE("Failed to read isAscii");
        send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_IS_ASCII);
        return;
    }
    TRACE_MODULE("Is ASCII = %d", ctx->isAscii);

    uint8_t addressFieldType_byte;
    if (!buffer_read_u8(cdata, &addressFieldType_byte)) {
        TRACE("Failed to read addressFieldType");
        send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_ADDRESS_FIELD_TYPE);
        return;
    }
    TRACE_MODULE("Address field type = %d", addressFieldType_byte);

    switch (addressFieldType_byte) {
        case CIP8_ADDRESS_FIELD_ADDRESS:
            ctx->addressFieldType = CIP8_ADDRESS_FIELD_ADDRESS;
            if (!buffer_read_address_params(cdata, &ctx->address_params)) {
                TRACE("Failed to parse address params");
                send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_ADDRESS_PARAMS);
                return;
            }
            // Copy any hash pointers into context-owned storage: the INIT APDU buffer
            // will be overwritten before CONFIRM stage when deriveAddress is called.
            address_params_copyHashesToStorage(&ctx->address_params, &ctx->hashStorage);
            break;
        case CIP8_ADDRESS_FIELD_KEYHASH:
            ctx->addressFieldType = CIP8_ADDRESS_FIELD_KEYHASH;
            // No additional data to parse
            break;
        default:
            TRACE("Invalid address field type");
            send_swo_and_reset(SWO_SIGN_MSG_INVALID_ADDRESS_FIELD_TYPE);
            return;
    }

    if (!is_msg_length_valid_for_sign_msg_init(ctx->msgLength, ctx->hashPayload, ctx->isAscii)) {
        TRACE("Message length rejected at INIT: len=%u hashPayload=%d isAscii=%d",
              ctx->msgLength,
              ctx->hashPayload,
              ctx->isAscii);
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }

    // Verify APDU fully consumed
    if (deny_unconsumed_bytes(cdata, SWO_WRONG_DATA_LENGTH)) {
        TRACE("INIT APDU not fully consumed");
        return;
    }
    // Check security policy and collect warnings
    ctx->warnings = 0;
    security_policy_t policy = policyForSignMsg(&ctx->signingPath,
                                                ctx->addressFieldType,
                                                &ctx->address_params,
                                                &ctx->warnings);
    ctx->signing_policy = policy;
    TRACE_MODULE("Policy: %d", (int) policy);
    if (policy == POLICY_DENY) {
        TRACE("Policy denied");
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    // Initialize hash context (always compute hash even for non-hashed payload)
    blake2b_224_init(&ctx->msgHashCtx);

    // Derive and store witness public key (needed for response and possibly address field)
    extendedPublicKey_t extPubKey = {0};
    deriveExtendedPublicKey(&ctx->signingPath, &extPubKey);
    STATIC_ASSERT(SIZEOF(extPubKey.pubKey) == SIZEOF(ctx->witnessKey), "wrong witness key size");
    memmove(ctx->witnessKey, extPubKey.pubKey, SIZEOF(extPubKey.pubKey));
    explicit_bzero(&extPubKey, SIZEOF(extPubKey));

    // Initialize chunk tracking
    ctx->remainingBytes = ctx->msgLength;

    // Dynamically allocate message buffer to accumulate all chunks
    if (ctx->msgLength > 0) {
        if (!APP_MEM_CALLOC((void **) &ctx->msgBuffer, (uint16_t) ctx->msgLength)) {
            // LCOV_EXCL_START
            // Requires allocator failure — not reachable in unit tests.
            TRACE("Failed to allocate %u byte message buffer", ctx->msgLength);
            send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
            return;
            // LCOV_EXCL_STOP
        }
        ctx->msgBufferSize = ctx->msgLength;
    }

    // Show spinner to indicate message processing
    TRACE_MODULE("Calling nbgl_useCaseSpinner(\"Processing\")");
    nbgl_useCaseSpinner("Processing");

    // Transition: skip CHUNK stage for empty messages
    if (ctx->msgLength == 0) {
        G_context.state.sign_msg_state = SIGN_MSG_STATE_CONFIRM;
    } else {
        G_context.state.sign_msg_state = SIGN_MSG_STATE_CHUNK;
    }

    apdu_response_send_sw(SWO_SUCCESS);
}

// ============================== CHUNK ==============================

static void signMsg_handle_chunk(buffer_t *cdata) {
    ASSERT(cdata != NULL);
    ASSERT(G_context.state.sign_msg_state == SIGN_MSG_STATE_CHUNK);

    sign_msg_ctx_t *ctx = &G_context.sign_msg_info;

    // Parse chunk: [4 bytes: chunkSize] [chunkSize bytes: data]
    uint32_t chunkSize_u32;
    if (!buffer_read_u32(cdata, &chunkSize_u32, BE)) {
        TRACE("Failed to read chunk size");
        send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_CHUNK_SIZE);
        return;
    }
    TRACE_MODULE("Chunk size = %u", chunkSize_u32);

    // Validate chunk size doesn't exceed remaining bytes
    if (chunkSize_u32 > ctx->remainingBytes) {
        TRACE("Chunk size exceeds remaining bytes");
        send_swo_and_reset(SWO_SIGN_MSG_INVALID_CHUNK_SIZE);
        return;
    }

    // Each chunk must be exactly min(remaining, MAX_CIP8_MSG_CHUNK_SIZE)
    uint32_t expectedChunkSize = MIN(ctx->remainingBytes, MAX_CIP8_MSG_CHUNK_SIZE);
    if (chunkSize_u32 != expectedChunkSize) {
        TRACE("Chunk size mismatch: expected %u, got %u", expectedChunkSize, chunkSize_u32);
        send_swo_and_reset(SWO_SIGN_MSG_INVALID_CHUNK_SIZE);
        return;
    }

    // Validate buffer has enough data
    if (!buffer_can_read(cdata, chunkSize_u32)) {
        TRACE("Insufficient data in buffer");
        send_swo_and_reset(SWO_SIGN_MSG_PARSING_FAIL_CHUNK_DATA);
        return;
    }

    if (chunkSize_u32 > 0) {
        // Compute write offset into the accumulated message buffer
        const uint32_t writeOffset = ctx->msgLength - ctx->remainingBytes;
        ASSERT(ctx->msgBuffer != NULL);
        ASSERT(writeOffset + chunkSize_u32 <= ctx->msgBufferSize);

        // Read chunk data directly into accumulated message buffer
        bool chunk_data_read =
            buffer_read_bytes(cdata, ctx->msgBuffer + writeOffset, chunkSize_u32);
        ASSERT(chunk_data_read);

        // Add chunk to hash
        blake2b_224_append(&ctx->msgHashCtx, ctx->msgBuffer + writeOffset, chunkSize_u32);
    }

    if (deny_unconsumed_bytes(cdata, SWO_WRONG_DATA_LENGTH)) {
        TRACE("Unconsumed bytes after chunk data");
        return;
    }

    // Update remaining bytes
    ctx->remainingBytes -= chunkSize_u32;

    // Transition to CONFIRM if all bytes received
    if (ctx->remainingBytes == 0) {
        if (ctx->isAscii && ctx->msgLength > 0) {
            ASSERT(ctx->msgBuffer != NULL);
            if (!str_isUnambiguousAscii(ctx->msgBuffer, ctx->msgLength)) {
                TRACE("ASCII validation failed for full message");
                send_swo_and_reset(SWO_SIGN_MSG_INVALID_ASCII);
                return;
            }
        }
        G_context.state.sign_msg_state = SIGN_MSG_STATE_CONFIRM;
    }

    apdu_response_send_sw(SWO_SUCCESS);
}

// ============================== CONFIRM ==============================

// Helper: prepare address field (derive address or compute key hash)
static void prepare_address_field(sign_msg_ctx_t *ctx) {
    switch (ctx->addressFieldType) {
        case CIP8_ADDRESS_FIELD_ADDRESS: {
            ctx->addressFieldSize =
                deriveAddress(&ctx->address_params, ctx->addressField, SIZEOF(ctx->addressField));
            ASSERT(ctx->addressFieldSize > 0 && ctx->addressFieldSize <= SIZEOF(ctx->addressField));
            break;
        }

        case CIP8_ADDRESS_FIELD_KEYHASH: {
            STATIC_ASSERT(SIZEOF(ctx->addressField) >= ADDRESS_KEY_HASH_LENGTH,
                          "wrong address field size");
            keyPathToKeyHash(&ctx->signingPath, ctx->addressField, ADDRESS_KEY_HASH_LENGTH);
            ctx->addressFieldSize = ADDRESS_KEY_HASH_LENGTH;
            break;
        }

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }
}

// Helper: create CBOR-encoded protected header
static size_t create_protected_header(sign_msg_ctx_t *ctx,
                                      uint8_t *protectedHeaderBuffer,
                                      size_t maxSize) {
    // protectedHeader = {
    //     1 : -8,                         // set algorithm to EdDSA
    //     "address" : address_bytes       // raw address or key hash
    // }
    buffer_t buffer = buffer_create(protectedHeaderBuffer, maxSize);

    // Map with 2 entries
    ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_MAP, 2));

    // Key: 1 (unsigned)
    ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_UNSIGNED, 1));

    // Value: -8 (algorithm EdDSA)
    // cbor_writeToken expects the actual negative value, not the CBOR-encoded form
    uint64_t negValueAsU64 = cbor_token_value_from_negative_i64(-8);
    ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_NEGATIVE, negValueAsU64));

    // Key: "address" (text string)
    const char *address_key = "address";
    const size_t address_key_len = strlen(address_key);
    ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_TEXT, address_key_len));
    ASSERT(buffer_write_bytes(&buffer, (const uint8_t *) address_key, address_key_len));

    // Value: address bytes prepared during CONFIRM handling.
    ASSERT(ctx->addressFieldSize > 0);

    ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_BYTES, ctx->addressFieldSize));
    ASSERT(buffer_write_bytes(&buffer, ctx->addressField, ctx->addressFieldSize));

    const size_t protectedHeaderSize = buffer.offset;
    ASSERT(protectedHeaderSize > 0 && protectedHeaderSize <= maxSize);

    return protectedHeaderSize;
}

// Helper: build Sig_structure and store it in context for signing after user confirmation.
// Returns false on allocation failures, true on success.
static bool build_sig_structure(sign_msg_ctx_t *ctx) {
    // Sig_structure = [
    //     context : "Signature1",
    //     body_protected : CBOR_encode(protectedHeader),
    //     external_aad : bstr,            // empty buffer
    //     payload : bstr                  // message hash or raw message
    // ]

    // Compute payload size for allocation
    const size_t payloadSize = ctx->hashPayload ? SIZEOF(ctx->msgHash) : ctx->msgLength;

    const size_t sigStructureMaxSize = SIG_STRUCTURE_OVERHEAD + payloadSize;

    // Dynamically allocate Sig_structure buffer
    uint8_t *sigStructure = NULL;
    // For non-hashed payloads, is_msg_length_valid_for_sign_msg_init() already guaranteed
    // sigStructureMaxSize <= UINT16_MAX at INIT time. For hashed payloads the size is
    // SIG_STRUCTURE_OVERHEAD + sizeof(msgHash) which is always well within limits.
    ASSERT(sigStructureMaxSize <= UINT16_MAX);
    if (!APP_MEM_CALLOC((void **) &sigStructure, (uint16_t) sigStructureMaxSize)) {
        // LCOV_EXCL_START
        // Requires allocator failure — not reachable in unit tests.
        TRACE("Failed to allocate %u byte Sig_structure buffer", (unsigned) sigStructureMaxSize);
        return false;
        // LCOV_EXCL_STOP
    }

    buffer_t buffer = buffer_create(sigStructure, sigStructureMaxSize);

    // Array with 4 elements
    ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_ARRAY, 4));

    // Element 1: "Signature1" (text string)
    const char *context = "Signature1";
    const size_t context_len = strlen(context);
    ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_TEXT, context_len));
    ASSERT(buffer_write_bytes(&buffer, (const uint8_t *) context, context_len));

    // Element 2: CBOR-encoded protectedHeader (as bytes)
    uint8_t protectedHeaderBuffer[MAX_ADDRESS_LENGTH + 32];
    const size_t protectedHeaderSize =
        create_protected_header(ctx, protectedHeaderBuffer, SIZEOF(protectedHeaderBuffer));

    ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_BYTES, protectedHeaderSize));
    ASSERT(buffer_write_bytes(&buffer, protectedHeaderBuffer, protectedHeaderSize));

    // Element 3: empty external_aad (empty byte string)
    ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_BYTES, 0));

    // Element 4: payload (message hash or raw message)
    if (ctx->hashPayload) {
        // Payload is the hash
        ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_BYTES, SIZEOF(ctx->msgHash)));
        ASSERT(buffer_write_bytes(&buffer, ctx->msgHash, SIZEOF(ctx->msgHash)));
    } else {
        // Payload is the raw message from accumulated buffer
        ASSERT(ctx->remainingBytes == 0);
        ASSERT(buffer_write_cbor_token(&buffer, CBOR_TYPE_BYTES, ctx->msgLength));
        if (ctx->msgLength > 0) {
            ASSERT(buffer_write_bytes(&buffer, ctx->msgBuffer, ctx->msgLength));
        }
    }

    const size_t sigStructureSize = buffer.offset;
    TRACE_MODULE("Sig_structure size = %u", (unsigned) sigStructureSize);

    // CIP-8/COSE Sig_structure has fixed semantics and no extra app-defined domain-separation
    // field for Cardano witness-vs-message separation. Adding a custom prefix/tag here would
    // break interoperability, so we sign the standard CBOR Sig_structure bytes as defined.
    // This check only guards against the degenerate 32-byte ambiguity with raw tx hashes.
    ASSERT(sigStructureSize != TX_HASH_LENGTH);

    ASSERT(sigStructureSize <= UINT16_MAX);
    ctx->sigStructureBuffer = sigStructure;
    ctx->sigStructureSize = (uint16_t) sigStructureSize;

    return true;
}

static void finalize_message_hash_to_context(sign_msg_ctx_t *ctx) {
    STATIC_ASSERT(SIZEOF(ctx->msgHash) * 8 == 224, "inconsistent message hash size");
    ASSERT(ctx->remainingBytes == 0);
    blake2b_224_finalize(&ctx->msgHashCtx, ctx->msgHash, SIZEOF(ctx->msgHash));
}

static void signMsg_handle_confirm(buffer_t *cdata) {
    ASSERT(G_context.state.sign_msg_state == SIGN_MSG_STATE_CONFIRM);
    ASSERT(cdata != NULL);

    sign_msg_ctx_t *ctx = &G_context.sign_msg_info;

    // CONFIRM APDU must be empty
    if (deny_unconsumed_bytes(cdata, SWO_SIGN_MSG_CONFIRM_MUST_BE_EMPTY)) {
        TRACE("CONFIRM APDU must be empty");
        return;
    }

    // Prepare address field and hash for review UI and later signing.
    prepare_address_field(ctx);
    ASSERT(ctx->addressFieldSize > 0);
    finalize_message_hash_to_context(ctx);

    // Build Sig_structure before UI confirmation so finalize path is infallible.
    if (!build_sig_structure(ctx)) {
        // LCOV_EXCL_START
        // Requires allocator failure — not reachable in unit tests.
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
        // LCOV_EXCL_STOP
    }

    switch (ctx->signing_policy) {
        case POLICY_SHOW:
            // Display UI for user confirmation
            apdu_response_deferred();
            ui_display_sign_msg(ctx->signing_policy, ctx->warnings);
            return;

        // LCOV_EXCL_START
        case POLICY_HIDE:
            // policyForSignMsg currently never returns POLICY_HIDE;
            // if it ever does, replace the assert with: finalize_sign_msg(); return;
            ASSERT(false);
            return;
        // LCOV_EXCL_STOP

        // LCOV_EXCL_START
        case POLICY_DENY:
        default:
            ASSERT(false);
            return;
            // LCOV_EXCL_STOP
    }
}

void finalize_sign_msg(void) {
    ASSERT(G_context.req_type == REQUEST_SIGN_MSG);
    ASSERT(G_context.state.sign_msg_state == SIGN_MSG_STATE_CONFIRM);

    sign_msg_ctx_t *ctx = &G_context.sign_msg_info;

    // User confirmed - sign already prepared Sig_structure.
    ASSERT(ctx->sigStructureBuffer != NULL);
    ASSERT(ctx->sigStructureSize > 0);
    signRawMessageWithPath(&ctx->signingPath,
                           ctx->sigStructureBuffer,
                           ctx->sigStructureSize,
                           ctx->signature,
                           SIZEOF(ctx->signature));
    APP_MEM_FREE(ctx->sigStructureBuffer);
    ctx->sigStructureBuffer = NULL;
    ctx->sigStructureSize = 0;

    // Send response.
    // Response format (matching legacy app-cardano repository):
    // [64 bytes: signature] [32 bytes: witnessKey] [4 bytes: addressFieldSize BE]
    // [addressFieldSize bytes: addressField]
    uint8_t response_buffer[ED25519_SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + 4 + MAX_ADDRESS_LENGTH];
    buffer_t response = buffer_create(response_buffer, SIZEOF(response_buffer));

    ASSERT(buffer_write_bytes(&response, ctx->signature, SIZEOF(ctx->signature)));
    ASSERT(buffer_write_bytes(&response, ctx->witnessKey, SIZEOF(ctx->witnessKey)));
    ASSERT(buffer_write_u32(&response, ctx->addressFieldSize, BE));
    ASSERT(buffer_write_bytes(&response, ctx->addressField, ctx->addressFieldSize));

    const size_t response_size = response.offset;
    TRACE_MODULE("Response size = %u", response_size);

    apdu_response_send_data(response_buffer, response_size, SWO_SUCCESS);
    reset_app_context();
}

// ============================== MAIN HANDLER ==============================

void handler_sign_msg(buffer_t *cdata, uint8_t p1) {
    ASSERT(cdata != NULL);
#ifdef TRACE_HANDLERS
    TRACE_BUFFER_T(cdata);
#endif

    switch (p1) {
        case P1_SIGN_MSG_INIT: {
            TRACE_MODULE("P1_SIGN_MSG_INIT");
            if (!ensure_sign_msg_request_type(REQUEST_NONE)) {
                return;
            }
            if (!ensure_sign_msg_state(SIGN_MSG_STATE_NONE)) {
                return;  // LCOV_EXCL_LINE — req_type==REQUEST_NONE implies state==NONE
            }
            G_context.req_type = REQUEST_SIGN_MSG;
            explicit_bzero(&G_context.sign_msg_info, sizeof(G_context.sign_msg_info));
            G_context.state.sign_msg_state = SIGN_MSG_STATE_INIT;
            signMsg_handle_init(cdata);
            break;
        }
        case P1_SIGN_MSG_CHUNK: {
            TRACE_MODULE("P1_SIGN_MSG_CHUNK");
            if (!ensure_sign_msg_request_type(REQUEST_SIGN_MSG)) {
                return;
            }
            if (!ensure_sign_msg_state(SIGN_MSG_STATE_CHUNK)) {
                return;
            }
            signMsg_handle_chunk(cdata);
            break;
        }
        case P1_SIGN_MSG_CONFIRM: {
            TRACE_MODULE("P1_SIGN_MSG_CONFIRM");
            if (!ensure_sign_msg_request_type(REQUEST_SIGN_MSG)) {
                return;
            }
            if (!ensure_sign_msg_state(SIGN_MSG_STATE_CONFIRM)) {
                return;
            }
            signMsg_handle_confirm(cdata);
            break;
        }
        // LCOV_EXCL_START
        default:
            TRACE("Bad P1 value");
            ASSERT(false);
            break;
            // LCOV_EXCL_STOP
    }
}
