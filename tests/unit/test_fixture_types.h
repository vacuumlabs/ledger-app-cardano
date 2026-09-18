/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "securityWarnings.h"

typedef struct {
    const uint8_t *payload;
    size_t payload_len;
} aux_data_payload_t;

typedef enum {
    BLIND_SIGNING_MODE_DISABLED = 0,
    BLIND_SIGNING_MODE_ENABLED_NO_PROMPT = 1,
    BLIND_SIGNING_MODE_PROMPT_REVIEW_HASH = 2,
    BLIND_SIGNING_MODE_PROMPT_REVIEW_FULL = 3,
} blind_signing_mode_t;

typedef struct {
    const uint8_t *payload;
    size_t payload_len;
    warning_bits_t expected_warning_bits;
    const uint8_t *expected_signature;
} witness_payload_t;

typedef struct {
    const char *name;
    const uint8_t *raw_tx;
    size_t raw_tx_len;
    const char *tx_body_cbor_hex;
    const char *expected_hash_hex;
    uint16_t num_inputs;
    uint16_t num_outputs;
    uint16_t num_witnesses;
    const witness_payload_t *witness_payloads;
    size_t witness_payload_count;
    uint16_t num_certificates;
    uint16_t num_withdrawals;
    uint16_t num_mint_asset_groups;
    bool include_ttl;
    bool include_validity_interval_start;
    bool include_aux_data_hash;
    uint8_t aux_data_type;
    const uint8_t *aux_data_init_payload;
    size_t aux_data_init_payload_len;
    const aux_data_payload_t *aux_data_delegations;
    size_t aux_data_delegation_count;
    bool include_script_data_hash;
    uint16_t num_collateral_inputs;
    uint16_t num_required_signers;
    bool include_network_id;
    bool include_collateral_output;
    bool include_total_collateral;
    uint16_t num_reference_inputs;
    uint16_t num_voters;
    uint16_t num_proposal_procedures;
    bool include_treasury;
    // Treasury and donation values are encoded inside raw_tx / tx_body_cbor_hex.
    // These fixture fields are metadata for readability and source parity only.
    uint64_t treasury;
    bool include_donation;
    uint64_t donation;
    const char *aux_data_hash_hex;
    uint64_t options;
    uint8_t signing_mode;
    uint8_t network_id;
    uint32_t protocol_magic;
    uint8_t blind_signing_mode;
    warning_bits_t expected_warning_bits;
} tx_fixture_t;

typedef struct {
    const char *name;
    uint8_t p1;
    const uint8_t *data;
    size_t data_len;
    uint16_t check_expected;
    const uint8_t *expected_address;
    size_t expected_address_len;
} derive_address_fixture_t;

typedef struct {
    const char *name;
    const uint8_t *data;
    size_t data_len;
    uint16_t check_expected;
    const uint8_t *expected_response;
    size_t expected_response_len;
    bool silent_export_enabled;
    uint8_t expected_policy;
} pubkey_fixture_t;

typedef struct {
    const uint8_t *data;
    size_t data_len;
} sign_msg_chunk_t;

typedef struct {
    const uint8_t *signature;
    size_t signature_len;
    const uint8_t *public_key;
    size_t public_key_len;
    const uint8_t *address_field;
    size_t address_field_len;
} sign_msg_expected_t;

typedef struct {
    const char *name;
    const uint8_t *init_data;
    size_t init_data_len;
    const sign_msg_chunk_t *chunks;
    size_t chunk_count;
    const uint8_t *confirm_data;
    size_t confirm_data_len;
    uint16_t check_expected;
    warning_bits_t expected_warning_bits;
    const sign_msg_expected_t *expected;
} sign_msg_fixture_t;

typedef struct {
    const char *name;
    const uint8_t *payload;
    size_t payload_len;
    warning_bits_t expected_warning_bits;
    const uint8_t *expected_signature;
    size_t expected_signature_len;
} opcert_fixture_t;

typedef struct {
    const char *name;
    const uint8_t *payload;
    size_t payload_len;
    uint16_t expected_swo;
} opcert_deny_fixture_t;

typedef struct {
    const uint8_t *data;
    size_t data_len;
} cvote_chunk_t;

typedef struct {
    const char *name;
    const uint8_t *init_data;
    size_t init_data_len;
    const cvote_chunk_t *chunks;
    size_t chunk_count;
    const uint8_t *confirm_data;
    size_t confirm_data_len;
    warning_bits_t expected_warning_bits;
    const uint8_t *expected_votecast_hash;
    size_t expected_votecast_hash_len;
    const uint8_t *expected_witness_signature;
    size_t expected_witness_signature_len;
} cvote_fixture_t;

typedef enum {
    CVOTE_DENY_PHASE_INIT = 0,     // malformed INIT payload → error at INIT
    CVOTE_DENY_PHASE_CHUNK = 1,    // CHUNK before INIT → SWO_COMMAND_NOT_ALLOWED
    CVOTE_DENY_PHASE_CONFIRM = 2,  // valid INIT, then malformed CONFIRM → error at CONFIRM
} cvote_deny_phase_e;

typedef struct {
    const char *name;
    cvote_deny_phase_e phase;
    // For INIT/CHUNK phases: the single APDU body to send (init or empty chunk).
    // For CONFIRM phase: the valid INIT body (same data as a happy-path test case).
    const uint8_t *apdu_data;
    size_t apdu_data_len;
    // For CONFIRM phase: intermediate chunk APDUs to send after INIT (may be NULL/0).
    const cvote_chunk_t *chunks;
    size_t chunk_count;
    // Used only for CONFIRM phase: the bad CONFIRM payload.
    const uint8_t *confirm_data;
    size_t confirm_data_len;
    uint16_t expected_swo;
} cvote_deny_fixture_t;

// Native script types (matching CBOR encoding)
typedef enum {
    NATIVE_SCRIPT_TYPE_PUBKEY_DEVICE_OWNED = 0x00,
    NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY = 0xF0,
    NATIVE_SCRIPT_TYPE_ALL = 0x01,
    NATIVE_SCRIPT_TYPE_ANY = 0x02,
    NATIVE_SCRIPT_TYPE_N_OF_K = 0x03,
    NATIVE_SCRIPT_TYPE_INVALID_BEFORE = 0x04,
    NATIVE_SCRIPT_TYPE_INVALID_HEREAFTER = 0x05,
} native_script_type_e;

typedef struct native_script_s native_script_t;
// SIMPLE script structure (leaf node)
typedef struct {
    const uint8_t *apdu_payload;  // Raw APDU data from command_builder.derive_script_add_complex:
    size_t apdu_payload_length;   // Length of APDU payload
} native_script_simple_t;

// COMPLEX script structure (internal node with children)
typedef struct {
    union {
        struct {
            const native_script_t **scripts;
            uint32_t scripts_count;
        } all;
        struct {
            const native_script_t **scripts;
            uint32_t scripts_count;
        } any;
        struct {
            uint32_t required_count;
            const native_script_t **scripts;
            uint32_t scripts_count;
        } n_of_k;
    } params;
} native_script_complex_t;

// Generic native script (can be simple or complex)
struct native_script_s {
    native_script_type_e type;
    union {
        native_script_simple_t simple;
        native_script_complex_t complex;
    } impl;
};

// Test case structure
typedef struct {
    const char *name;
    const native_script_t *root_script;  // Root of script tree
    const uint16_t expected_response;
    const uint8_t *expected_hash;
    const uint8_t *finish_apdu_payload;  // Raw APDU data from command_builder.derive_script_finish
    size_t finish_apdu_payload_length;   // Length of finish APDU payload
} native_script_test_case_t;
