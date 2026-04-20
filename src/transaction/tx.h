/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cardano_constants.h"
#include "bip44.h"
#include "tx_credential_types.h"

typedef enum {
    AUX_DATA_TYPE_ARBITRARY_HASH = 0,
    AUX_DATA_TYPE_CVOTE_REGISTRATION = 1,
} aux_data_type_t;
#include "tx_certificate_types.h"
#include "tx_output_types.h"
#include "tx_voting_procedure_types.h"

// Mint token limits
// Note: No artificial limits on asset groups or tokens per mint.
// The wire format uses uint16_t for counts, so the natural limit is UINT16_MAX.
// Memory allocation is dynamic, so we can handle any count up to that limit.
#define MAX_MINT_ASSET_NAME_LENGTH 32

typedef struct {
    const uint8_t* txHash;
    uint32_t index;
} tx_input_t;

typedef struct {
    const uint8_t* policyId;  // set by caller from outer asset group context, not parsed here
    const uint8_t* assetName;
    uint8_t assetNameLen;
    int64_t amount;
} mint_token_t;

typedef struct {
    const uint8_t* policyId;
    uint16_t numTokens;
} mint_asset_group_t;

typedef enum {
    SIGN_TX_SIGNINGMODE_ORDINARY_TX = 3,
    SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER = 4,
    SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR = 5,
    SIGN_TX_SIGNINGMODE_MULTISIG_TX = 6,
    SIGN_TX_SIGNINGMODE_PLUTUS_TX = 7,
    // AUTO is a client-side hint: the device infers the concrete mode from the
    // tx body fields present in the init APDU.  It is replaced by a concrete
    // mode before any security-policy check runs; no policy function ever sees
    // this value.
    SIGN_TX_SIGNINGMODE_AUTO = 8,
} sign_tx_signingmode_t;

// Transaction parameters parsed from SIGN_TX INIT APDU.
// These are known before tx body parsing starts.
typedef struct {
    sign_tx_signingmode_t txSigningMode;
    uint8_t networkId;
    uint32_t protocolMagic;
    bool tagCborSets;
    uint16_t num_inputs;
    uint16_t num_outputs;
    bool includeTtl;
    uint16_t num_certificates;
    uint16_t num_withdrawals;
    bool includeAuxDataHash;
    aux_data_type_t auxDataType;
    uint8_t auxDataHash[AUX_DATA_HASH_LENGTH];
    bool includeValidityIntervalStart;
    uint16_t num_mint_asset_groups;
    bool includeScriptDataHash;
    uint16_t num_collateral_inputs;
    uint16_t num_required_signers;
    bool includeNetworkId;
    bool includeCollateralOutput;
    bool includeTotalCollateral;
    uint16_t num_reference_inputs;
    uint16_t num_voters;
    bool includeTreasury;
    bool includeDonation;
} tx_params_t;

typedef enum {
    TX_OPTIONS_TAG_CBOR_SETS = 1,  // Whether to tag CBOR sets in transaction hash
} tx_options_e;

typedef struct {
    ext_credential_t stakeCredential;
    uint64_t amount;
} withdrawal_t;

typedef enum {
    REQUIRED_SIGNER_WITH_PATH = 0,
    REQUIRED_SIGNER_WITH_HASH = 1,
} required_signer_type_t;

typedef struct {
    required_signer_type_t type;
    union {
        bip44_path_t keyPath;
        const uint8_t* keyHash;
    };
} required_signer_t;

// Certificate data structure supporting multiple certificate types.
// Fields are used selectively depending on certificate type:
// - STAKE_REGISTRATION/DEREGISTRATION: stakeCredential
// - STAKE_REGISTRATION_CONWAY/DEREGISTRATION_CONWAY: stakeCredential, deposit
// - STAKE_DELEGATION: stakeCredential, poolKeyHash
// - STAKE_POOL_RETIREMENT: poolCredential, retirementEpoch
// - STAKE_POOL_REGISTRATION: poolId, poolRegistration
// - VOTE_DELEGATION: stakeCredential, drep
// - AUTHORIZE_COMMITTEE_HOT: coldCredential, hotCredential
// - RESIGN_COMMITTEE_COLD: coldCredential, anchor
// - DREP_REGISTRATION/UPDATE: dRepCredential, deposit (reg only), anchor
// - DREP_DEREGISTRATION: dRepCredential, deposit
// - (Future) STAKE_POOL_AND_DREP_DELEGATION: stakeCredential, drep, combinedDelegPoolKeyHash
typedef struct {
    certificate_type_t type;
    ext_credential_t stakeCredential;
    ext_credential_t coldCredential;
    ext_credential_t dRepCredential;
    ext_credential_t poolCredential;
    pool_id_t poolId;
    ext_credential_t hotCredential;
    const uint8_t* poolKeyHash;
    const uint8_t* combinedDelegPoolKeyHash;
    ext_drep_t drep;
    uint64_t deposit;
    uint64_t retirementEpoch;
    anchor_t anchor;  // For committee resign, DRep registration/update
    pool_registration_data_t
        poolRegistration;  // valid only when type == CERTIFICATE_STAKE_POOL_REGISTRATION
} certificate_data_t;
