/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "tx_hash_builder.h"
#include "hash.h"
#include "cbor.h"
#include "write.h"
#include "assert.h"
#include "utils.h"
#include <string.h>

/*
 * Optional tracing for debugging tx hash serialization.
 * Enabled via -DTRACE_TX_HASH_BUILDER to capture the exact CBOR bytes
 * being hashed.
 */
#ifdef TRACE_TX_HASH_BUILDER
static uint8_t tx_body_trace_buffer[4 * 1024];
static size_t tx_body_trace_size = 0;

static void trace_record_bytes(const uint8_t *buffer, size_t size) {
    if (tx_body_trace_size + size > sizeof(tx_body_trace_buffer)) {
        return;
    }
    memcpy(tx_body_trace_buffer + tx_body_trace_size, buffer, size);
    tx_body_trace_size += size;
}
#define TRACE_BODY(buffer, size) trace_record_bytes(buffer, size)
#define _TRACE(...)              TRACE(__VA_ARGS__)
#else
#define TRACE_BODY(buffer, size) (void) 0
#define _TRACE(...)
#endif  // TRACE_TX_HASH_BUILDER

/*
The following macros and functions have dual purpose:
1. syntactic sugar for neat recording of hash computations;
2. tracing of hash computations
*/

#define BUILDER_APPEND_CBOR(type, value) \
    blake2b_256_append_cbor_tx_body(&builder->txHash, type, value)

#define BUILDER_APPEND_DATA(buffer, bufferSize) \
    blake2b_256_append_buffer_tx_body(&builder->txHash, buffer, bufferSize)

// bufferSize == 0 is safe: blake2b_update() is a no-op for inlen == 0,
// so callers may pass buffer == NULL when bufferSize == 0 (e.g. empty pool metadata URL).
static void blake2b_256_append_buffer_tx_body(blake2b_256_context_t *hashCtx,
                                              const uint8_t *buffer,
                                              size_t bufferSize) {
    TRACE_BODY(buffer, bufferSize);
    blake2b_256_append(hashCtx, buffer, bufferSize);
}

static void blake2b_256_append_cbor_tx_body(blake2b_256_context_t *hashCtx,
                                            uint8_t type,
                                            uint64_t value) {
    uint8_t buffer[10] = {0};
    size_t size = 0;
    LEDGER_ASSERT(cbor_writeToken(type, value, buffer, SIZEOF(buffer), &size),
                  "Failed to write CBOR token");
    TRACE_BODY(buffer, size);
    blake2b_256_append(hashCtx, buffer, size);
}

#define BUILDER_TAG_CBOR_SET()                            \
    if (builder->tagCborSets) {                           \
        TRACE("appending set tag 258");                   \
        BUILDER_APPEND_CBOR(CBOR_TYPE_TAG, CBOR_TAG_SET); \
    }

static void _append_cbor_token(uint8_t *buffer,
                               size_t bufferLen,
                               size_t *offset,
                               uint8_t type,
                               uint64_t value) {
    ASSERT(buffer != NULL);
    ASSERT(offset != NULL);
    LEDGER_ASSERT(*offset < bufferLen, "CBOR buffer overflow");

    size_t tokenSize = 0;
    LEDGER_ASSERT(cbor_writeToken(type, value, buffer + *offset, bufferLen - *offset, &tokenSize),
                  "Failed to write CBOR token");
    *offset += tokenSize;
}

static void _append_map_key_bytes(uint8_t *buffer,
                                  size_t bufferLen,
                                  size_t *offset,
                                  const uint8_t *data,
                                  size_t dataLen) {
    ASSERT(buffer != NULL && offset != NULL && data != NULL);
    LEDGER_ASSERT(bufferLen >= *offset, "Map bytes invalid offset");
    LEDGER_ASSERT(bufferLen - *offset >= dataLen, "Map bytes overflow");

    memcpy(buffer + *offset, data, dataLen);
    *offset += dataLen;
}

static const uint8_t *_voter_key_data_with_size(const voter_t *voter, size_t *out_size) {
    ASSERT(voter != NULL);
    ASSERT(out_size != NULL);

    switch (voter->type) {
        case VOTER_COMMITTEE_HOT_KEY_HASH:
        case VOTER_DREP_KEY_HASH:
        case VOTER_STAKE_POOL_KEY_HASH:
            *out_size = ADDRESS_KEY_HASH_LENGTH;
            return voter->keyHash;
        case VOTER_COMMITTEE_HOT_SCRIPT_HASH:
        case VOTER_DREP_SCRIPT_HASH:
            *out_size = SCRIPT_HASH_LENGTH;
            return voter->scriptHash;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            return NULL;
            // LCOV_EXCL_STOP
    }
}

size_t txHashBuilder_serializeVoterKey(const voter_t *voter, uint8_t *buffer, size_t bufferLen) {
    ASSERT(voter != NULL);
    ASSERT(buffer != NULL);
    size_t offset = 0;
    size_t keyLen = 0;
    const uint8_t *keyBytes = _voter_key_data_with_size(voter, &keyLen);
    ASSERT(keyBytes != NULL);

    _append_cbor_token(buffer, bufferLen, &offset, CBOR_TYPE_ARRAY, 2);
    _append_cbor_token(buffer, bufferLen, &offset, CBOR_TYPE_UNSIGNED, voter->type);
    _append_cbor_token(buffer, bufferLen, &offset, CBOR_TYPE_BYTES, keyLen);
    _append_map_key_bytes(buffer, bufferLen, &offset, keyBytes, keyLen);

    return offset;
}

size_t txHashBuilder_serializeGovActionKey(const gov_action_id_t *govActionId,
                                           uint8_t *buffer,
                                           size_t bufferLen) {
    ASSERT(govActionId != NULL);
    ASSERT(buffer != NULL);
    ASSERT(govActionId != NULL && govActionId->txHash != NULL);
    size_t offset = 0;
    _append_cbor_token(buffer, bufferLen, &offset, CBOR_TYPE_ARRAY, 2);
    _append_cbor_token(buffer, bufferLen, &offset, CBOR_TYPE_BYTES, TX_HASH_LENGTH);
    _append_map_key_bytes(buffer, bufferLen, &offset, govActionId->txHash, TX_HASH_LENGTH);
    _append_cbor_token(buffer, bufferLen, &offset, CBOR_TYPE_UNSIGNED, govActionId->govActionIndex);

    return offset;
}

/* End of hash computation utilities. */

static void cbor_append_txInput(tx_hash_builder_t *builder,
                                const uint8_t *utxoHashBuffer,
                                size_t utxoHashSize,
                                uint32_t utxoIndex) {
    // Array(2)[
    //    Bytes[hash],
    //    Unsigned[index]
    // ]
    BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
    {
        ASSERT(utxoHashSize == TX_HASH_LENGTH);
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, utxoHashSize);
        BUILDER_APPEND_DATA(utxoHashBuffer, utxoHashSize);
    }
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, utxoIndex);
    }
}

static void cbor_append_txOutput_array(tx_hash_builder_t *builder,
                                       const tx_output_description_t *output) {
    ASSERT(output->format == ARRAY_LEGACY);

    // Array(2 + includeDatumHash)[
    //   Bytes[address]
    //   // value = coin / [coin,multiasset<uint>] --- added below
    //   // ? datum_hash = $hash32 --- added later
    // ]
    BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2 + output->includeDatum);
    {
        ASSERT(output->destination.type == DESTINATION_THIRD_PARTY);
        ASSERT(output->destination.address.length < BUFFER_SIZE_PARANOIA);
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, output->destination.address.length);
        BUILDER_APPEND_DATA(output->destination.address.buffer, output->destination.address.length);
    }

    if (output->numAssetGroups == 0) {
        // value = Unsigned[amount]
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, output->amount);
    } else {
        // value = Array(2)[
        //   Unsigned[amount]
        //   Map(numAssetGroups)[
        //     // entries added later, { * policy_id => { * asset_name => uint } }
        //   ]
        // ]
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, output->amount);
            BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, output->numAssetGroups);
        }
    }
}

static void cbor_append_txOutput_map(tx_hash_builder_t *builder,
                                     const tx_output_description_t *output) {
    ASSERT(output->format == MAP_BABBAGE);

    // Map(2 + includeDatum + includeRefScript)[
    //   Unsigned[0] ; map entry key
    //   Bytes[address]
    //
    //   Unsigned[1] ; map entry key
    //   value = coin / [coin,multiasset<uint>] --- entry added below
    //
    //   ? datum_option = [ 0, $hash32 // 1, data ] --- entry added later
    //
    //   ? script_ref = #6.24(bytes .cbor script) --- entry added later
    // ]
    BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, 2 + output->includeDatum + output->includeRefScript);
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_OUTPUT_KEY_ADDRESS);

        ASSERT(output->destination.type == DESTINATION_THIRD_PARTY);
        ASSERT(output->destination.address.length < BUFFER_SIZE_PARANOIA);
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, output->destination.address.length);
        BUILDER_APPEND_DATA(output->destination.address.buffer, output->destination.address.length);
    }
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_OUTPUT_KEY_VALUE);
        if (output->numAssetGroups == 0) {
            // value = Unsigned[amount]
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, output->amount);
        } else {
            // value = Array(2)[
            //   Unsigned[amount]
            //   Map(numAssetGroups)[
            //     // entries added later, { * policy_id => { * asset_name => uint } }
            //   ]
            // ]
            BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
            {
                BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, output->amount);
                BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, output->numAssetGroups);
            }
        }
    }
}

// adds top level data: address, ADA amount, starts multiasset map; tokens are added later
static void processOutputTopLevel(tx_hash_builder_t *builder,
                                  const tx_output_description_t *output) {
    builder->outputData.serializationFormat = output->format;
    builder->outputData.includeDatum = output->includeDatum;
    builder->outputData.includeRefScript = output->includeRefScript;
    builder->outputData.multiassetData.remainingAssetGroups = output->numAssetGroups;

    switch (output->format) {
        case ARRAY_LEGACY:
            cbor_append_txOutput_array(builder, output);
            break;
        case MAP_BABBAGE:
            cbor_append_txOutput_map(builder, output);
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }
}

static void assertCanLeaveCurrentOutput(tx_hash_builder_t *builder) {
    switch (builder->outputData.outputState) {
        case TX_OUTPUT_INIT:
        case TX_OUTPUT_TOP_LEVEL_DATA:
            // no tokens
            TRACE("%u", builder->outputData.multiassetData.remainingAssetGroups);
            ASSERT(builder->outputData.multiassetData.remainingAssetGroups == 0);
            // no datum or script reference
            ASSERT(!builder->outputData.includeDatum);
            ASSERT(!builder->outputData.includeRefScript);
            break;

        case TX_OUTPUT_ASSET_GROUP:
            // no remaining minting policies or tokens
            ASSERT(builder->outputData.multiassetData.remainingAssetGroups == 0);
            ASSERT(builder->outputData.multiassetData.remainingTokens == 0);

            // no datum or script reference
            ASSERT(!builder->outputData.includeDatum);
            ASSERT(!builder->outputData.includeRefScript);
            break;

        case TX_OUTPUT_DATUM_HASH:
            // if no reference script, we are done
            ASSERT(!builder->outputData.includeRefScript);
            break;

        case TX_OUTPUT_DATUM_INLINE:
            // if all chunks were received and no reference script follows, we are done
            ASSERT(builder->outputData.datumData.remainingBytes == 0);
            ASSERT(!builder->outputData.includeRefScript);
            break;

        case TX_OUTPUT_SCRIPT_REFERENCE_CHUNKS:
            // if all chunks were received, we are done
            ASSERT(builder->outputData.referenceScriptData.remainingBytes == 0);
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }
}

// ============================== TX HASH BUILDER STATE INITIALIZATION
// ==============================

void txHashBuilder_init(tx_hash_builder_t *builder, const tx_params_t *txParams) {
    ASSERT(builder != NULL);
    ASSERT(txParams != NULL);

    // Clear the entire structure to prevent stale data in unions
    explicit_bzero(builder, sizeof(tx_hash_builder_t));

    TRACE("tagCborSets = %u", txParams->tagCborSets);
    TRACE("numInputs = %u", txParams->num_inputs);
    TRACE("numOutputs = %u", txParams->num_outputs);
    TRACE("includeTtl = %u", txParams->includeTtl);
    TRACE("numCertificates = %u", txParams->num_certificates);
    TRACE("numWithdrawals  = %u", txParams->num_withdrawals);
    TRACE("includeAuxDataHash = %u", txParams->includeAuxDataHash);
    TRACE("includeValidityIntervalStart = %u", txParams->includeValidityIntervalStart);
    TRACE("numMintAssetGroups = %u", txParams->num_mint_asset_groups);
    TRACE("includeScriptDataHash = %u", txParams->includeScriptDataHash);
    TRACE("numCollateralInputs = %u", txParams->num_collateral_inputs);
    TRACE("numRequiredSigners = %u", txParams->num_required_signers);
    TRACE("includeNetworkId = %u", txParams->includeNetworkId);
    TRACE("includeCollateralOutput = %u", txParams->includeCollateralOutput);
    TRACE("includeTotalCollateral = %u", txParams->includeTotalCollateral);
    TRACE("numReferenceInputs = %u", txParams->num_reference_inputs);
    TRACE("numVoters = %u", txParams->num_voters);
    TRACE("includeTreasury = %u", txParams->includeTreasury);
    TRACE("includeDonation = %u", txParams->includeDonation);

#ifdef TRACE_TX_HASH_BUILDER
    tx_body_trace_size = 0;
#endif

    builder->tagCborSets = txParams->tagCborSets;

    blake2b_256_init(&builder->txHash);

    {
        size_t numItems = 0;

        builder->remainingInputs = txParams->num_inputs;
        numItems++;  // an array that is always included (even if empty)

        builder->remainingOutputs = txParams->num_outputs;
        numItems++;  // an array that is always included (even if empty)

        // fee always included
        numItems++;

        builder->includeTtl = txParams->includeTtl;
        if (txParams->includeTtl) numItems++;

        builder->remainingCertificates = txParams->num_certificates;
        if (txParams->num_certificates > 0) numItems++;

        builder->remainingWithdrawals = txParams->num_withdrawals;
        if (txParams->num_withdrawals > 0) numItems++;

        builder->includeAuxData = txParams->includeAuxDataHash;
        if (txParams->includeAuxDataHash) numItems++;

        builder->includeValidityIntervalStart = txParams->includeValidityIntervalStart;
        if (txParams->includeValidityIntervalStart) numItems++;

        // Derive includeMint from num_mint_asset_groups
        builder->includeMint = (txParams->num_mint_asset_groups > 0);
        if (txParams->num_mint_asset_groups > 0) numItems++;

        builder->includeScriptDataHash = txParams->includeScriptDataHash;
        if (txParams->includeScriptDataHash) numItems++;

        builder->remainingCollateralInputs = txParams->num_collateral_inputs;
        if (txParams->num_collateral_inputs > 0) numItems++;

        builder->remainingRequiredSigners = txParams->num_required_signers;
        if (txParams->num_required_signers > 0) numItems++;

        builder->includeNetworkId = txParams->includeNetworkId;
        if (txParams->includeNetworkId) numItems++;

        builder->includeCollateralOutput = txParams->includeCollateralOutput;
        if (txParams->includeCollateralOutput) numItems++;

        builder->includeTotalCollateral = txParams->includeTotalCollateral;
        if (txParams->includeTotalCollateral) numItems++;

        builder->remainingReferenceInputs = txParams->num_reference_inputs;
        if (txParams->num_reference_inputs > 0) numItems++;

        builder->remainingVoters = txParams->num_voters;
        if (txParams->num_voters > 0) numItems++;

        builder->remainingProposalProcedures = txParams->num_proposal_procedures;
        if (txParams->num_proposal_procedures > 0) numItems++;

        builder->includeTreasury = txParams->includeTreasury;
        if (txParams->includeTreasury) numItems++;

        builder->includeDonation = txParams->includeDonation;
        if (txParams->includeDonation) numItems++;

        ASSERT((3 <= numItems) && (numItems <= 20));

        _TRACE("Serializing tx body with %u items", numItems);
        BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, numItems);
    }
    builder->state = TX_HASH_BUILDER_INIT;
}

static void txHashBuilder_assertCanLeaveInit(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    ASSERT(builder->state == TX_HASH_BUILDER_INIT);
}

// ============================== INPUTS ==============================

void txHashBuilder_enterInputs(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveInit(builder);
    {
        // Enter inputs
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_INPUTS);
        BUILDER_TAG_CBOR_SET();
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->remainingInputs);
    }
    builder->state = TX_HASH_BUILDER_IN_INPUTS;
}

void txHashBuilder_addInput(tx_hash_builder_t *builder, const tx_input_t *input) {
    _TRACE("state = %d, remainingInputs = %u", builder->state, builder->remainingInputs);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_INPUTS);
    ASSERT(builder->remainingInputs > 0);
    builder->remainingInputs--;

    cbor_append_txInput(builder, input->txHash, TX_HASH_LENGTH, input->index);
}

static void txHashBuilder_assertCanLeaveInputs(tx_hash_builder_t *builder) {
    _TRACE("state = %d, remainingInputs = %u", builder->state, builder->remainingInputs);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_INPUTS);
    ASSERT(builder->remainingInputs == 0);
}

// ============================== OUTPUTS ==============================

void txHashBuilder_enterOutputs(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveInputs(builder);
    {
        // Enter outputs
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_OUTPUTS);
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->remainingOutputs);
    }
    builder->state = TX_HASH_BUILDER_IN_OUTPUTS;
    builder->outputData.outputState = TX_OUTPUT_INIT;
}

void txHashBuilder_addOutput_topLevelData(tx_hash_builder_t *builder,
                                          const tx_output_description_t *output) {
    _TRACE("state = %d, outputState = %d, remainingOutputs = %u",
           builder->state,
           builder->outputData.outputState,
           builder->remainingOutputs);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_OUTPUTS);
    ASSERT(builder->remainingOutputs > 0);
    builder->remainingOutputs--;

    assertCanLeaveCurrentOutput(builder);

    processOutputTopLevel(builder, output);

    builder->outputData.outputState = TX_OUTPUT_TOP_LEVEL_DATA;
}

static void addTokenGroup(tx_hash_builder_t *builder,
                          const uint8_t *policyIdBuffer,
                          size_t policyIdSize,
                          uint16_t numTokens) {
    _TRACE("state = %d, outputState = %d, remainingAssetGroups = %u",
           builder->state,
           builder->outputData.outputState,
           builder->outputData.multiassetData.remainingAssetGroups);

    switch (builder->outputData.outputState) {
        case TX_OUTPUT_ASSET_GROUP:
            // we have been adding tokens into the previous asset group
            ASSERT(builder->outputData.multiassetData.remainingTokens == 0);
            break;

        case TX_OUTPUT_TOP_LEVEL_DATA:
            // nothing to check, top level data has been added instantaneously
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    ASSERT(builder->outputData.multiassetData.remainingAssetGroups > 0);
    builder->outputData.multiassetData.remainingAssetGroups--;

    ASSERT(policyIdSize == MINTING_POLICY_ID_LENGTH);

    ASSERT(numTokens > 0);
    builder->outputData.multiassetData.remainingTokens = numTokens;

    {
        // Bytes[policyId]
        // Map(numTokens)[
        //   // entries added later { * asset_name => uint }
        // ]
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, policyIdSize);
            BUILDER_APPEND_DATA(policyIdBuffer, policyIdSize);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, numTokens);
        }
    }

    builder->outputData.outputState = TX_OUTPUT_ASSET_GROUP;
}

static void addToken(tx_hash_builder_t *builder,
                     const uint8_t *assetNameBuffer,
                     size_t assetNameSize,
                     uint64_t amount,
                     cbor_type_tag_t typeTag) {
    _TRACE("state = %d, outputState = %d, remainingTokens = %u",
           builder->state,
           builder->outputData.outputState,
           builder->outputData.multiassetData.remainingTokens);

    switch (builder->outputData.outputState) {
        case TX_OUTPUT_ASSET_GROUP:
            // we have been adding tokens into an asset group
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    ASSERT(builder->outputData.multiassetData.remainingTokens > 0);
    builder->outputData.multiassetData.remainingTokens--;

    ASSERT(assetNameSize <= MAX_ASSET_NAME_LENGTH);
    {
        // add a map entry:
        // Bytes[asset_name]
        // Unsigned[Amount]
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, assetNameSize);
            BUILDER_APPEND_DATA(assetNameBuffer, assetNameSize);
        }
        {
            BUILDER_APPEND_CBOR(typeTag, amount);
        }
    }

    builder->outputData.outputState = TX_OUTPUT_ASSET_GROUP;
}

void txHashBuilder_addOutput_tokenGroup(tx_hash_builder_t *builder,
                                        const uint8_t *policyIdBuffer,
                                        size_t policyIdSize,
                                        uint16_t numTokens) {
    ASSERT(builder->state == TX_HASH_BUILDER_IN_OUTPUTS);

    addTokenGroup(builder, policyIdBuffer, policyIdSize, numTokens);
}

void txHashBuilder_addOutput_token(tx_hash_builder_t *builder,
                                   const uint8_t *assetNameBuffer,
                                   size_t assetNameSize,
                                   uint64_t amount) {
    ASSERT(builder->state == TX_HASH_BUILDER_IN_OUTPUTS);

    addToken(builder, assetNameBuffer, assetNameSize, amount, CBOR_TYPE_UNSIGNED);
}

void txHashBuilder_addOutput_datum(tx_hash_builder_t *builder,
                                   datum_type_t datumType,
                                   const uint8_t *buffer,
                                   size_t bufferSize) {
    ASSERT(builder->outputData.includeDatum);

    TRACE("%d", builder->outputData.outputState);

    switch (builder->outputData.outputState) {
        case TX_OUTPUT_TOP_LEVEL_DATA:
            // top level data has been added instantaneously
            // so we only check there are no asset groups left out
            ASSERT(builder->outputData.multiassetData.remainingAssetGroups == 0);
            break;

        case TX_OUTPUT_ASSET_GROUP:
            // we have been adding tokens into an asset group
            ASSERT(builder->outputData.multiassetData.remainingTokens == 0);
            ASSERT(builder->outputData.multiassetData.remainingAssetGroups == 0);
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    // the babbage output format serializes some preliminary stuff
    if (builder->outputData.serializationFormat == MAP_BABBAGE) {
        //   datum_option = [ 0, $hash32 // 1, data ]

        //   Unsigned[2] ; map entry key
        //   Array(2)[
        //     Unsigned[datumType]
        //     Bytes[buffer] / #6.24(Bytes[buffer])
        //   ]

        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_OUTPUT_KEY_DATUM_OPTION);
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, datumType);
        }
    }

    switch (datumType) {
        case DATUM_HASH:
            ASSERT(bufferSize == OUTPUT_DATUM_HASH_LENGTH);
            builder->outputData.datumData.remainingBytes = bufferSize;
            {
                BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, bufferSize);
                BUILDER_APPEND_DATA(buffer, bufferSize);
            }
            //  Hash is transmitted in one chunk, and datumType stage is finished
            builder->outputData.outputState = TX_OUTPUT_DATUM_HASH;
            break;

        case DATUM_INLINE:
            // inline datum only supported since Babbage
            ASSERT(builder->outputData.serializationFormat == MAP_BABBAGE);
            ASSERT(bufferSize < BUFFER_SIZE_PARANOIA);
            // bufferSize is total size of datum
            builder->outputData.datumData.remainingBytes = bufferSize;
            {
                BUILDER_APPEND_CBOR(CBOR_TYPE_TAG, CBOR_TAG_EMBEDDED_CBOR_BYTE_STRING);
                BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, bufferSize);
                // byte chunks will be added later
            }
            builder->outputData.outputState = TX_OUTPUT_DATUM_INLINE;
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }
}

void txHashBuilder_addOutput_datum_inline_chunk(tx_hash_builder_t *builder,
                                                const uint8_t *buffer,
                                                size_t bufferSize) {
    ASSERT(builder->outputData.outputState == TX_OUTPUT_DATUM_INLINE);
    ASSERT(bufferSize <= builder->outputData.datumData.remainingBytes);
    builder->outputData.datumData.remainingBytes -= bufferSize;
    {
        BUILDER_APPEND_DATA(buffer, bufferSize);
    }
}

void txHashBuilder_addOutput_referenceScript(tx_hash_builder_t *builder, size_t scriptSize) {
    ASSERT(builder->outputData.includeRefScript);

    switch (builder->outputData.outputState) {
        case TX_OUTPUT_TOP_LEVEL_DATA:
            // top level data has been added instantaneously
            // so we only check there are no asset groups left out
            ASSERT(builder->outputData.multiassetData.remainingAssetGroups == 0);
            break;

        case TX_OUTPUT_ASSET_GROUP:
            // we have been adding tokens into an asset group
            ASSERT(builder->outputData.multiassetData.remainingTokens == 0);
            ASSERT(builder->outputData.multiassetData.remainingAssetGroups == 0);
            break;

        case TX_OUTPUT_DATUM_HASH:
            // nothing to check, datum hash is added instantaneously
            break;

        case TX_OUTPUT_DATUM_INLINE:
            ASSERT(builder->outputData.datumData.remainingBytes == 0);
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    //   Unsigned[3] ; map entry key
    //   #6.24(Bytes[buffer])
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_OUTPUT_KEY_SCRIPT_REF);
    }
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_TAG, CBOR_TAG_EMBEDDED_CBOR_BYTE_STRING);
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, scriptSize);
        // byte chunks will be added later
    }
    builder->outputData.referenceScriptData.remainingBytes = scriptSize;
    builder->outputData.outputState = TX_OUTPUT_SCRIPT_REFERENCE_CHUNKS;
}

void txHashBuilder_addOutput_referenceScript_dataChunk(tx_hash_builder_t *builder,
                                                       const uint8_t *buffer,
                                                       size_t bufferSize) {
    ASSERT(builder->outputData.outputState == TX_OUTPUT_SCRIPT_REFERENCE_CHUNKS);
    ASSERT(bufferSize <= builder->outputData.referenceScriptData.remainingBytes);
    builder->outputData.referenceScriptData.remainingBytes -= bufferSize;
    {
        BUILDER_APPEND_DATA(buffer, bufferSize);
    }
}

static void txHashBuilder_assertCanLeaveOutputs(tx_hash_builder_t *builder) {
    _TRACE("state = %d, remainingOutputs = %u", builder->state, builder->remainingOutputs);

    // we need to check this first to make sure the subsequent checks are meaningful
    ASSERT(builder->state == TX_HASH_BUILDER_IN_OUTPUTS);
    ASSERT(builder->remainingOutputs == 0);

    assertCanLeaveCurrentOutput(builder);
}

// ============================== FEE ==============================

void txHashBuilder_addFee(tx_hash_builder_t *builder, uint64_t fee) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveOutputs(builder);

    // add fee item into the main tx body map
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_FEE);
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, fee);

    builder->state = TX_HASH_BUILDER_IN_FEE;
}

static void txHashBuilder_assertCanLeaveFee(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_FEE);
}

// ============================== TTL ==============================

void txHashBuilder_addTtl(tx_hash_builder_t *builder, uint64_t ttl) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveFee(builder);
    ASSERT(builder->includeTtl);

    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_TTL);
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, ttl);

    builder->state = TX_HASH_BUILDER_IN_TTL;
}

static void txHashBuilder_assertCanLeaveTtl(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    switch (builder->state) {
        case TX_HASH_BUILDER_IN_TTL:
            // TTL was added, we can move on
            break;

        default:
            // make sure TTL was not expected
            ASSERT(!builder->includeTtl);
            // assert we can leave the previous state
            txHashBuilder_assertCanLeaveFee(builder);
            break;
    }
}

// ============================== CERTIFICATES ==============================

void txHashBuilder_enterCertificates(tx_hash_builder_t *builder) {
    _TRACE("state = %d, remaining certificates = %u",
           builder->state,
           builder->remainingCertificates);

    txHashBuilder_assertCanLeaveTtl(builder);
    ASSERT(builder->remainingCertificates > 0);

    {
        // Enter certificates
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_CERTIFICATES);
        BUILDER_TAG_CBOR_SET();
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->remainingCertificates);
    }

    builder->poolCertificateData.remainingOwners = 0;
    builder->poolCertificateData.remainingRelays = 0;

    builder->state = TX_HASH_BUILDER_IN_CERTIFICATES;
}

static void _initNewCertificate(tx_hash_builder_t *builder) {
    _TRACE("state = %d, remainingCertificates = %u",
           builder->state,
           builder->remainingCertificates);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES);
    ASSERT(builder->remainingCertificates > 0);
    builder->remainingCertificates--;
}

static const uint8_t *_getCredentialHashBuffer(const credential_t *credential) {
    switch (credential->type) {
        case CREDENTIAL_KEY_HASH:
            return credential->keyHash;
        case CREDENTIAL_SCRIPT_HASH:
            return credential->scriptHash;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }
}

static size_t _getCredentialHashSize(const credential_t *credential) {
    switch (credential->type) {
        case CREDENTIAL_KEY_HASH:
            return SIZEOF(credential->keyHash);
        case CREDENTIAL_SCRIPT_HASH:
            return SIZEOF(credential->scriptHash);
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }
}

static void _appendCredential(tx_hash_builder_t *builder, const credential_t *credential) {
    BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, credential->type);
    }
    {
        const size_t size = _getCredentialHashSize(credential);
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, size);
        BUILDER_APPEND_DATA(_getCredentialHashBuffer(credential), size);
    }
}

static void _appendDRep(tx_hash_builder_t *builder, const drep_t *drep) {
    ASSERT(drep != NULL);
    {
        switch (drep->type) {
            case DREP_KEY_HASH: {
                BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
                BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, DREP_KEY_HASH);
                BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, SIZEOF(drep->keyHash));
                BUILDER_APPEND_DATA(drep->keyHash, SIZEOF(drep->keyHash));
                break;
            }
            case DREP_SCRIPT_HASH: {
                BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
                BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, DREP_SCRIPT_HASH);
                BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, SIZEOF(drep->scriptHash));
                BUILDER_APPEND_DATA(drep->scriptHash, SIZEOF(drep->scriptHash));
                break;
            }
            case DREP_ABSTAIN:
            case DREP_NO_CONFIDENCE: {
                BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 1);
                BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, drep->type);
                break;
            }
            // LCOV_EXCL_START
            default:
                ASSERT(false);
                // LCOV_EXCL_STOP
        }
    }
}

// stake key certificate registration or deregistration
// will be deprecated after Conway
void txHashBuilder_addCertificate_stakingOld(tx_hash_builder_t *builder,
                                             const certificate_type_t certificateType,
                                             const credential_t *stakeCredential) {
    _initNewCertificate(builder);

    ASSERT((certificateType == CERTIFICATE_STAKE_REGISTRATION) ||
           (certificateType == CERTIFICATE_STAKE_DEREGISTRATION));

    // Array(2)[
    //   Unsigned[certificateType]
    //   Array(2)[
    //     Unsigned[0]
    //     Bytes[stakingKeyHash]
    //   ]
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, certificateType);
        }
        {
            _appendCredential(builder, stakeCredential);
        }
    }
}

// stake key certificate registration or deregistration
// exists since Conway
void txHashBuilder_addCertificate_staking(tx_hash_builder_t *builder,
                                          const certificate_type_t certificateType,
                                          const credential_t *stakeCredential,
                                          uint64_t deposit) {
    _initNewCertificate(builder);

    ASSERT((certificateType == CERTIFICATE_STAKE_REGISTRATION_CONWAY) ||
           (certificateType == CERTIFICATE_STAKE_DEREGISTRATION_CONWAY));

    // Array(3)[
    //   Unsigned[certificateType]
    //   Array(2)[
    //     Unsigned[0]
    //     Bytes[stakingKeyHash]
    //   ]
    //   Unsigned[deposit]
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, certificateType);
        }
        {
            _appendCredential(builder, stakeCredential);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, deposit);
        }
    }
}

void txHashBuilder_addCertificate_stakeDelegation(tx_hash_builder_t *builder,
                                                  const credential_t *stakeCredential,
                                                  const uint8_t *poolKeyHash,
                                                  size_t poolKeyHashSize) {
    _initNewCertificate(builder);

    ASSERT(poolKeyHashSize == POOL_KEY_HASH_LENGTH);

    // Array(3)[
    //   Unsigned[2]
    //   Array(2)[
    //     Unsigned[0]
    //     Bytes[stakingKeyHash]
    //   ]
    //   Bytes[poolKeyHash]
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, CERTIFICATE_STAKE_DELEGATION);
        }
        {
            _appendCredential(builder, stakeCredential);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, poolKeyHashSize);
            BUILDER_APPEND_DATA(poolKeyHash, poolKeyHashSize);
        }
    }
}

void txHashBuilder_addCertificate_voteDelegation(tx_hash_builder_t *builder,
                                                 const credential_t *stakeCredential,
                                                 const drep_t *drep) {
    _initNewCertificate(builder);

    // Array(3)[
    //   Unsigned[9]
    //   Array(2)[
    //     Unsigned[0]
    //     Bytes[stakingKeyHash]
    //   ]
    //   Array(1 or 2)[
    //     Unsigned[drep_type]
    //     ?Bytes[key/script hash] // optional
    //   ]
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, CERTIFICATE_VOTE_DELEGATION);
        }
        {
            _appendCredential(builder, stakeCredential);
        }
        {
            _appendDRep(builder, drep);
        }
    }
}

void txHashBuilder_addCertificate_stakePoolAndDRepDelegation(tx_hash_builder_t *builder,
                                                             const credential_t *stakeCredential,
                                                             const uint8_t *poolKeyHash,
                                                             size_t poolKeyHashSize,
                                                             const drep_t *drep) {
    _initNewCertificate(builder);
    ASSERT(poolKeyHashSize == POOL_KEY_HASH_LENGTH);

    // Array(4)[
    //   Unsigned[10]
    //   Array(2)[
    //     Unsigned[0]
    //     Bytes[stakingKeyHash]
    //   ]
    //   Bytes[poolKeyHash]
    //   Array(1 or 2)[ Unsigned[drep_type], ?Bytes[hash] ]
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 4);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION);
        }
        {
            _appendCredential(builder, stakeCredential);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, poolKeyHashSize);
            BUILDER_APPEND_DATA(poolKeyHash, poolKeyHashSize);
        }
        {
            _appendDRep(builder, drep);
        }
    }
}

void txHashBuilder_addCertificate_accountRegistrationDelegationToStakePool(
    tx_hash_builder_t *builder,
    const credential_t *stakeCredential,
    const uint8_t *poolKeyHash,
    size_t poolKeyHashSize,
    uint64_t deposit) {
    _initNewCertificate(builder);
    ASSERT(poolKeyHashSize == POOL_KEY_HASH_LENGTH);

    // Array(4)[
    //   Unsigned[11]
    //   Array(2)[ credential ]
    //   Bytes[poolKeyHash]
    //   Unsigned[deposit]
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 4);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED,
                                CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL);
        }
        {
            _appendCredential(builder, stakeCredential);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, poolKeyHashSize);
            BUILDER_APPEND_DATA(poolKeyHash, poolKeyHashSize);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, deposit);
        }
    }
}

void txHashBuilder_addCertificate_accountRegistrationDelegationToDRep(
    tx_hash_builder_t *builder,
    const credential_t *stakeCredential,
    const drep_t *drep,
    uint64_t deposit) {
    _initNewCertificate(builder);

    // Array(4)[
    //   Unsigned[12]
    //   Array(2)[ credential ]
    //   Array(1 or 2)[ drep ]
    //   Unsigned[deposit]
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 4);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED,
                                CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP);
        }
        {
            _appendCredential(builder, stakeCredential);
        }
        {
            _appendDRep(builder, drep);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, deposit);
        }
    }
}

void txHashBuilder_addCertificate_accountRegistrationDelegationToStakePoolAndDRep(
    tx_hash_builder_t *builder,
    const credential_t *stakeCredential,
    const uint8_t *poolKeyHash,
    size_t poolKeyHashSize,
    const drep_t *drep,
    uint64_t deposit) {
    _initNewCertificate(builder);
    ASSERT(poolKeyHashSize == POOL_KEY_HASH_LENGTH);

    // Array(5)[
    //   Unsigned[13]
    //   Array(2)[ credential ]
    //   Bytes[poolKeyHash]
    //   Array(1 or 2)[ drep ]
    //   Unsigned[deposit]
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 5);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED,
                                CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP);
        }
        {
            _appendCredential(builder, stakeCredential);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, poolKeyHashSize);
            BUILDER_APPEND_DATA(poolKeyHash, poolKeyHashSize);
        }
        {
            _appendDRep(builder, drep);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, deposit);
        }
    }
}

void txHashBuilder_addCertificate_committeeAuthHot(tx_hash_builder_t *builder,
                                                   const credential_t *coldCredential,
                                                   const credential_t *hotCredential) {
    _initNewCertificate(builder);

    // Array(3)[
    //   Unsigned[14]
    //   Array(2)[
    //     Unsigned[0 or 1]
    //     Bytes[stakingKeyHash]
    //   ]
    //   Array(2)[
    //     Unsigned[0 or 1]
    //     Bytes[stakingKeyHash]
    //   ]
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, CERTIFICATE_AUTHORIZE_COMMITTEE_HOT);
        }
        {
            _appendCredential(builder, coldCredential);
        }
        {
            _appendCredential(builder, hotCredential);
        }
    }
}

static void _appendAnchor(tx_hash_builder_t *builder, const anchor_t *anchor) {
    if (anchor->isIncluded) {
        // Array(2)[
        //   Tstr[url]
        //   Bytes[32]
        // ]
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_TEXT, anchor->urlLength);
            BUILDER_APPEND_DATA(anchor->url, anchor->urlLength);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, ANCHOR_HASH_LENGTH);
            BUILDER_APPEND_DATA(anchor->hash, ANCHOR_HASH_LENGTH);
        }
    } else {
        // Null
        BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
    }
}

void txHashBuilder_addCertificate_committeeResign(tx_hash_builder_t *builder,
                                                  const credential_t *coldCredential,
                                                  const anchor_t *anchor) {
    _initNewCertificate(builder);

    // Array(3)[
    //   Unsigned[15]
    //   Array(2)[
    //     Unsigned[0 or 1]
    //     Bytes[stakingKeyHash]
    //   ]
    //   Null / ...anchor
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, CERTIFICATE_RESIGN_COMMITTEE_COLD);
        }
        {
            _appendCredential(builder, coldCredential);
        }
        {
            _appendAnchor(builder, anchor);
        }
    }
}

void txHashBuilder_addCertificate_dRepRegistration(tx_hash_builder_t *builder,
                                                   const credential_t *dRepCredential,
                                                   uint64_t deposit,
                                                   const anchor_t *anchor) {
    _initNewCertificate(builder);

    // Array(4)[
    //   Unsigned[16]
    //   Array(2)[
    //     Unsigned[0/1]
    //     Bytes[key/script hash]
    //   ]
    //   Unsigned[deposit]
    //   Null / ...anchor
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 4);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, CERTIFICATE_DREP_REGISTRATION);
        }
        {
            _appendCredential(builder, dRepCredential);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, deposit);
        }
        {
            _appendAnchor(builder, anchor);
        }
    }
}

void txHashBuilder_addCertificate_dRepDeregistration(tx_hash_builder_t *builder,
                                                     const credential_t *dRepCredential,
                                                     uint64_t deposit) {
    _initNewCertificate(builder);

    // Array(3)[
    //   Unsigned[17]
    //   Array(2)[
    //     Unsigned[0/1]
    //     Bytes[key/script hash]
    //   ]
    //   Unsigned[deposit]
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, CERTIFICATE_DREP_DEREGISTRATION);
        }
        {
            _appendCredential(builder, dRepCredential);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, deposit);
        }
    }
}

void txHashBuilder_addCertificate_dRepUpdate(tx_hash_builder_t *builder,
                                             const credential_t *dRepCredential,
                                             const anchor_t *anchor) {
    _initNewCertificate(builder);

    // Array(3)[
    //   Unsigned[18]
    //   Array(2)[
    //     Unsigned[0/1]
    //     Bytes[key/script hash]
    //   ]
    //   Null / ...anchor
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, CERTIFICATE_DREP_UPDATE);
        }
        {
            _appendCredential(builder, dRepCredential);
        }
        {
            _appendAnchor(builder, anchor);
        }
    }
}

void txHashBuilder_addCertificate_poolRetirement(tx_hash_builder_t *builder,
                                                 const uint8_t *poolKeyHash,
                                                 size_t poolKeyHashSize,
                                                 uint64_t epoch) {
    _initNewCertificate(builder);

    ASSERT(poolKeyHashSize == POOL_KEY_HASH_LENGTH);

    // Array(3)[
    //   Unsigned[4]
    //   Bytes[poolKeyHash]
    //   Unsigned[epoch]
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, CERTIFICATE_STAKE_POOL_RETIREMENT);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, poolKeyHashSize);
            BUILDER_APPEND_DATA(poolKeyHash, poolKeyHashSize);
        }
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, epoch);
    }
}

void txHashBuilder_poolRegistrationCertificate_enter(tx_hash_builder_t *builder,
                                                     uint16_t numOwners,
                                                     uint16_t numRelays) {
    _initNewCertificate(builder);

    ASSERT(builder->poolCertificateData.remainingOwners == 0);
    builder->poolCertificateData.remainingOwners = numOwners;
    ASSERT(builder->poolCertificateData.remainingRelays == 0);
    builder->poolCertificateData.remainingRelays = numRelays;

    // Array(10)[
    //   Unsigned[3]

    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 10);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, CERTIFICATE_STAKE_POOL_REGISTRATION);
        }
    }

    builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_INIT;
}

void txHashBuilder_poolRegistrationCertificate_poolKeyHash(tx_hash_builder_t *builder,
                                                           const uint8_t *poolKeyHash,
                                                           size_t poolKeyHashSize) {
    _TRACE("state = %d", builder->state);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_INIT);

    ASSERT(poolKeyHashSize == POOL_KEY_HASH_LENGTH);

    //   Bytes[pool_keyhash]          // also called operator in CDDL specs and pool id in user
    //   interfaces
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, poolKeyHashSize);
        BUILDER_APPEND_DATA(poolKeyHash, poolKeyHashSize);
    }

    builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_KEY_HASH;
}

void txHashBuilder_poolRegistrationCertificate_vrfKeyHash(tx_hash_builder_t *builder,
                                                          const uint8_t *vrfKeyHash,
                                                          size_t vrfKeyHashSize) {
    _TRACE("state = %d", builder->state);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_KEY_HASH);

    ASSERT(vrfKeyHashSize == VRF_KEY_HASH_LENGTH);

    //   Bytes[vrf_keyhash]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, vrfKeyHashSize);
        BUILDER_APPEND_DATA(vrfKeyHash, vrfKeyHashSize);
    }

    builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_VRF;
}

void txHashBuilder_poolRegistrationCertificate_financials(tx_hash_builder_t *builder,
                                                          uint64_t pledge,
                                                          uint64_t cost,
                                                          uint64_t marginNumerator,
                                                          uint64_t marginDenominator) {
    _TRACE("state = %d", builder->state);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_VRF);

    //   Unsigned[pledge]
    //   Unsigned[cost]
    //   Tag(30) Array(2)[
    //     Unsigned[marginDenominator]
    //     Unsigned[marginNumerator]
    //   ]
    {
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, pledge);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, cost);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_TAG, CBOR_TAG_UNIT_INTERVAL);
            BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
            {
                BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, marginNumerator);
            }
            {
                BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, marginDenominator);
            }
        }
    }

    builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_FINANCIALS;
}

void txHashBuilder_poolRegistrationCertificate_rewardAccount(tx_hash_builder_t *builder,
                                                             const uint8_t *rewardAccount,
                                                             size_t rewardAccountSize) {
    _TRACE("state = %d", builder->state);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_FINANCIALS);

    ASSERT(rewardAccountSize == REWARD_ACCOUNT_LENGTH);

    //   Bytes[rewardAccount]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, rewardAccountSize);
        BUILDER_APPEND_DATA(rewardAccount, rewardAccountSize);
    }

    builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_REWARD_ACCOUNT;
}

void txHashBuilder_addPoolRegistrationCertificate_enterOwners(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_REWARD_ACCOUNT);

    {
        BUILDER_TAG_CBOR_SET();
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->poolCertificateData.remainingOwners);
    }

    builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS;
}

void txHashBuilder_addPoolRegistrationCertificate_addOwner(tx_hash_builder_t *builder,
                                                           const uint8_t *stakingKeyHash,
                                                           size_t stakingKeyHashSize) {
    _TRACE("state = %d, remainingOwners = %u",
           builder->state,
           builder->poolCertificateData.remainingOwners);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS);
    ASSERT(builder->poolCertificateData.remainingOwners > 0);
    builder->poolCertificateData.remainingOwners--;

    ASSERT(stakingKeyHashSize == ADDRESS_KEY_HASH_LENGTH);

    // Bytes[poolKeyHash]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, stakingKeyHashSize);
        BUILDER_APPEND_DATA(stakingKeyHash, stakingKeyHashSize);
    }
}

void txHashBuilder_addPoolRegistrationCertificate_enterRelays(tx_hash_builder_t *builder) {
    _TRACE("state = %d, remainingOwners = %u",
           builder->state,
           builder->poolCertificateData.remainingOwners);

    // enter empty owners if none were received (and none were expected)
    if (builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_REWARD_ACCOUNT) {
        ASSERT(builder->poolCertificateData.remainingOwners == 0);
        txHashBuilder_addPoolRegistrationCertificate_enterOwners(builder);
    }

    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS);
    ASSERT(builder->poolCertificateData.remainingOwners == 0);

    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->poolCertificateData.remainingRelays);
    }

    builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS;
}

static void _relay_addPort(tx_hash_builder_t *builder, const ipport_t *port) {
    _TRACE("state = %d, remainingRelays = %u",
           builder->state,
           builder->poolCertificateData.remainingRelays);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS);

    //   Unsigned[port] / Null
    if (port->isNull) {
        BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
    } else {
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, port->number);
    }
}

static void _relay_addIpv4(tx_hash_builder_t *builder, const ipv4_t *ipv4) {
    _TRACE("state = %d, remainingRelays = %u",
           builder->state,
           builder->poolCertificateData.remainingRelays);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS);

    //   Bytes[ipv4] / Null
    if (ipv4->isNull) {
        BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
    } else {
        ASSERT(ipv4->ip != NULL);
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, IPV4_LENGTH);
        BUILDER_APPEND_DATA(ipv4->ip, IPV4_LENGTH);
    }
}

static void _relay_addIpv6(tx_hash_builder_t *builder, const ipv6_t *ipv6) {
    _TRACE("state = %d, remainingRelays = %u",
           builder->state,
           builder->poolCertificateData.remainingRelays);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS);

    //   Bytes[ipv6] / Null
    if (ipv6->isNull) {
        BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
    } else {
        ASSERT(ipv6->ip != NULL);
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, IPV6_LENGTH);

        // The IPv6 address is stored as 4 little-endian uint32 words (Cardano's encoding).
        // Serialize each word as big-endian to produce the correct CBOR byte string.
        STATIC_ASSERT(IPV6_LENGTH == 4 * sizeof(uint32_t), "wrong ipv6 size");
        for (size_t i = 0; i < 4; i++) {
            uint32_t word;
            memcpy(&word, ipv6->ip + i * sizeof(uint32_t), sizeof(uint32_t));
            uint8_t chunk[4] = {0};
            write_u32_be(chunk, 0, word);
            BUILDER_APPEND_DATA(chunk, 4);
        }
    }
}

static void _relay_addDnsName(tx_hash_builder_t *builder, const pool_relay_t *relay) {
    _TRACE("state = %d, remainingRelays = %u",
           builder->state,
           builder->poolCertificateData.remainingRelays);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS);

    ASSERT(relay->dnsNameSize <= MAX_DNS_NAME_LENGTH);

    //   Text[dnsName]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_TEXT, relay->dnsNameSize);
        BUILDER_APPEND_DATA(relay->dnsName, relay->dnsNameSize);
    }
}

void txHashBuilder_addPoolRegistrationCertificate_addRelay(tx_hash_builder_t *builder,
                                                           const pool_relay_t *relay) {
    _TRACE("state = %d, remainingRelays = %u",
           builder->state,
           builder->poolCertificateData.remainingRelays);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS);
    ASSERT(builder->poolCertificateData.remainingRelays > 0);
    builder->poolCertificateData.remainingRelays--;

    switch (relay->format) {
        case RELAY_SINGLE_HOST_IP: {
            // Array(4)[
            //   Unsigned[0]
            //   Unsigned[port] / Null
            //   Bytes[ipv4] / Null
            //   Bytes[ipv6] / Null
            // ]
            {
                BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 4);
                {
                    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 0);
                }
                _relay_addPort(builder, &relay->port);
                _relay_addIpv4(builder, &relay->ipv4);
                _relay_addIpv6(builder, &relay->ipv6);
            }
            break;
        }
        case RELAY_SINGLE_HOST_NAME: {
            // Array(3)[
            //   Unsigned[1]
            //   Unsigned[port] / Null
            //   Text[dnsName]
            // ]
            {
                BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
                {
                    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 1);
                }
                _relay_addPort(builder, &relay->port);
                _relay_addDnsName(builder, relay);
            }
            break;
        }
        case RELAY_MULTIPLE_HOST_NAME: {
            // Array(2)[
            //   Unsigned[2]
            //   Text[dnsName]
            // ]
            {
                BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
                {
                    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, 2);
                }
                _relay_addDnsName(builder, relay);
            }
            break;
        }
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }
}

// enter empty owners or relays if none were received
static void addPoolMetadata_updateState(tx_hash_builder_t *builder) {
    switch (builder->state) {
        case TX_HASH_BUILDER_IN_CERTIFICATES_POOL_REWARD_ACCOUNT:
            // skipping owners is only possible if none were expected
            ASSERT(builder->poolCertificateData.remainingOwners == 0);
            txHashBuilder_addPoolRegistrationCertificate_enterOwners(builder);

            __attribute__((fallthrough));
        case TX_HASH_BUILDER_IN_CERTIFICATES_POOL_OWNERS:
            // skipping relays is only possible if none were expected
            ASSERT(builder->poolCertificateData.remainingRelays == 0);
            txHashBuilder_addPoolRegistrationCertificate_enterRelays(builder);

            __attribute__((fallthrough));
        case TX_HASH_BUILDER_IN_CERTIFICATES_POOL_RELAYS:
            // all relays should have been received
            ASSERT(builder->poolCertificateData.remainingRelays == 0);
            break;  // we want to be here

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    builder->state = TX_HASH_BUILDER_IN_CERTIFICATES_POOL_METADATA;
}

void txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata(tx_hash_builder_t *builder,
                                                                  const uint8_t *url,
                                                                  size_t urlSize,
                                                                  const uint8_t *metadataHash,
                                                                  size_t metadataHashSize) {
    _TRACE("state = %d", builder->state);

    // we allow this to be called immediately after pool params have been added
    // if there are no owners or relays in the tx
    addPoolMetadata_updateState(builder);
    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_METADATA);

    ASSERT(metadataHashSize == POOL_METADATA_HASH_LENGTH);

    // Array(2)[
    //   Tstr[url]
    //   Bytes[metadataHash]
    // ]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_TEXT, urlSize);
            BUILDER_APPEND_DATA(url, urlSize);
        }
        {
            BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, metadataHashSize);
            BUILDER_APPEND_DATA(metadataHash, metadataHashSize);
        }
    }
    builder->state = TX_HASH_BUILDER_IN_CERTIFICATES;
}

void txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata_null(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    addPoolMetadata_updateState(builder);
    ASSERT(builder->state == TX_HASH_BUILDER_IN_CERTIFICATES_POOL_METADATA);
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
    }
    builder->state = TX_HASH_BUILDER_IN_CERTIFICATES;
}

static void txHashBuilder_assertCanLeaveCertificates(tx_hash_builder_t *builder) {
    _TRACE("state = %d, remainingCertificates = %u",
           builder->state,
           builder->remainingCertificates);

    // No certificates may remain: the same invariant whether this state was entered or
    // skipped entirely. Only walking back through the previous state is conditional.
    ASSERT(builder->remainingCertificates == 0);
    if (builder->state != TX_HASH_BUILDER_IN_CERTIFICATES) {
        txHashBuilder_assertCanLeaveTtl(builder);
    }
}

// ============================== WITHDRAWALS ==============================

void txHashBuilder_enterWithdrawals(tx_hash_builder_t *builder) {
    _TRACE("state = %d, remainingWithdrawals = %u", builder->state, builder->remainingWithdrawals);

    txHashBuilder_assertCanLeaveCertificates(builder);
    ASSERT(builder->remainingWithdrawals > 0);

    {
        // enter withdrawals
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_WITHDRAWALS);
        BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, builder->remainingWithdrawals);
    }

    builder->state = TX_HASH_BUILDER_IN_WITHDRAWALS;
}

void txHashBuilder_addWithdrawal(tx_hash_builder_t *builder,
                                 const uint8_t *rewardAddressBuffer,
                                 size_t rewardAddressSize,
                                 uint64_t amount) {
    _TRACE("state = %d, remainingWithdrawals = %u", builder->state, builder->remainingWithdrawals);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_WITHDRAWALS);
    ASSERT(builder->remainingWithdrawals > 0);
    builder->remainingWithdrawals--;

    ASSERT(rewardAddressSize == REWARD_ACCOUNT_LENGTH);

    // map entry
    //   Bytes[address]
    //   Unsigned[amount]
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, rewardAddressSize);
        BUILDER_APPEND_DATA(rewardAddressBuffer, rewardAddressSize);
    }
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, amount);
    }
}

static void txHashBuilder_assertCanLeaveWithdrawals(tx_hash_builder_t *builder) {
    _TRACE("state = %d, remainingWithdrawals = %u", builder->state, builder->remainingWithdrawals);

    // No withdrawals may remain: the same invariant whether this state was entered or
    // skipped entirely. Only walking back through the previous state is conditional.
    ASSERT(builder->remainingWithdrawals == 0);
    if (builder->state != TX_HASH_BUILDER_IN_WITHDRAWALS) {
        txHashBuilder_assertCanLeaveCertificates(builder);
    }
}

// ============================== AUXILIARY DATA ==============================

void txHashBuilder_addAuxData(tx_hash_builder_t *builder,
                              const uint8_t *auxDataHashBuffer,
                              size_t auxDataHashBufferSize) {
    _TRACE("state = %d, remainingWithdrawals = %u", builder->state, builder->remainingWithdrawals);

    txHashBuilder_assertCanLeaveWithdrawals(builder);
    ASSERT(builder->includeAuxData);

    ASSERT(auxDataHashBufferSize == AUX_DATA_HASH_LENGTH);
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_AUX_DATA);
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, auxDataHashBufferSize);
        BUILDER_APPEND_DATA(auxDataHashBuffer, auxDataHashBufferSize);
    }
    builder->state = TX_HASH_BUILDER_IN_AUX_DATA;
}

static void txHashBuilder_assertCanLeaveAuxData(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    switch (builder->state) {
        case TX_HASH_BUILDER_IN_AUX_DATA:
            // aux data was added, we can move on
            break;

        default:
            // make sure aux data was not expected
            ASSERT(!builder->includeAuxData);
            // assert we can leave the previous state
            txHashBuilder_assertCanLeaveWithdrawals(builder);
            break;
    }
}

// ============================== VALIDITY INTERVAL START ==============================

void txHashBuilder_addValidityIntervalStart(tx_hash_builder_t *builder,
                                            uint64_t validityIntervalStart) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveAuxData(builder);
    ASSERT(builder->includeValidityIntervalStart);

    // add validity interval start item into the main tx body map
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_VALIDITY_INTERVAL_START);
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, validityIntervalStart);

    builder->state = TX_HASH_BUILDER_IN_VALIDITY_INTERVAL_START;
}

static void txHashBuilder_assertCanLeaveValidityIntervalStart(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    switch (builder->state) {
        case TX_HASH_BUILDER_IN_VALIDITY_INTERVAL_START:
            // validity interval start was added, we can move on
            break;

        default:
            // make sure validity interval start was not expected
            ASSERT(!builder->includeValidityIntervalStart);
            // assert we can leave the previous state
            txHashBuilder_assertCanLeaveAuxData(builder);
            break;
    }
}

// ============================== MINT ==============================

void txHashBuilder_enterMint(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveValidityIntervalStart(builder);
    ASSERT(builder->includeMint);

    {
        // Enter mint
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_MINT);
    }
    builder->state = TX_HASH_BUILDER_IN_MINT;
}

void txHashBuilder_addMint_topLevelData(tx_hash_builder_t *builder, uint16_t numAssetGroups) {
    _TRACE("state = %u", builder->state);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_MINT);

    ASSERT(numAssetGroups > 0);
    builder->outputData.multiassetData.remainingAssetGroups = numAssetGroups;

    // Map(numAssetGroups)[
    //   { * policy_id => { * asset_name => uint } }
    // ]
    BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, numAssetGroups);

    builder->outputData.outputState = TX_OUTPUT_TOP_LEVEL_DATA;
}

void txHashBuilder_addMint_tokenGroup(tx_hash_builder_t *builder,
                                      const uint8_t *policyIdBuffer,
                                      size_t policyIdSize,
                                      uint16_t numTokens) {
    ASSERT(builder->state == TX_HASH_BUILDER_IN_MINT);

    addTokenGroup(builder, policyIdBuffer, policyIdSize, numTokens);
}

void txHashBuilder_addMint_token(tx_hash_builder_t *builder,
                                 const uint8_t *assetNameBuffer,
                                 size_t assetNameSize,
                                 int64_t amount) {
    ASSERT(builder->state == TX_HASH_BUILDER_IN_MINT);

    addToken(builder,
             assetNameBuffer,
             assetNameSize,
             amount,
             amount < 0 ? CBOR_TYPE_NEGATIVE : CBOR_TYPE_UNSIGNED);
}

static void txHashBuilder_assertCanLeaveMint(tx_hash_builder_t *builder) {
    _TRACE("state = %u, remainingMintAssetGroups = %u, remainingMintTokens = %u",
           builder->state,
           builder->outputData.multiassetData.remainingAssetGroups,
           builder->outputData.multiassetData.remainingTokens);

    switch (builder->state) {
        case TX_HASH_BUILDER_IN_MINT:
            ASSERT(builder->outputData.outputState == TX_OUTPUT_ASSET_GROUP);
            ASSERT(builder->outputData.multiassetData.remainingAssetGroups == 0);
            ASSERT(builder->outputData.multiassetData.remainingTokens == 0);
            break;

        default:
            // make sure mint was not expected
            ASSERT(!builder->includeMint);
            // assert we can leave the previous state
            txHashBuilder_assertCanLeaveValidityIntervalStart(builder);
            break;
    }
}

// ========================= SCRIPT DATA HASH ==========================

void txHashBuilder_addScriptDataHash(tx_hash_builder_t *builder,
                                     const uint8_t *scriptHashData,
                                     size_t scriptHashDataSize) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveMint(builder);
    ASSERT(builder->includeScriptDataHash);

    ASSERT(scriptHashDataSize == SCRIPT_DATA_HASH_LENGTH);
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_SCRIPT_HASH_DATA);
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, scriptHashDataSize);
        BUILDER_APPEND_DATA(scriptHashData, scriptHashDataSize);
    }
    builder->state = TX_HASH_BUILDER_IN_SCRIPT_DATA_HASH;
}

static void txHashBuilder_assertCanLeaveScriptDataHash(tx_hash_builder_t *builder) {
    _TRACE("state = %u", builder->state);

    switch (builder->state) {
        case TX_HASH_BUILDER_IN_SCRIPT_DATA_HASH:
            // script data hash was added, we can move on
            break;

        default:
            // make sure script data hash was not expected
            ASSERT(!builder->includeScriptDataHash);
            // assert we can leave the previous state
            txHashBuilder_assertCanLeaveMint(builder);
            break;
    }
}

// ========================= COLLATERAL INPUTS ==========================

void txHashBuilder_enterCollateralInputs(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveScriptDataHash(builder);
    // we don't allow an empty list for an optional item
    ASSERT(builder->remainingCollateralInputs > 0);

    {
        // Enter collateral inputs
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_COLLATERAL_INPUTS);
        BUILDER_TAG_CBOR_SET();
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->remainingCollateralInputs);
    }
    builder->state = TX_HASH_BUILDER_IN_COLLATERAL_INPUTS;
}

void txHashBuilder_addCollateralInput(tx_hash_builder_t *builder, const tx_input_t *collInput) {
    _TRACE("state = %d, remainingCollateralInputs = %u",
           builder->state,
           builder->remainingCollateralInputs);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_COLLATERAL_INPUTS);
    ASSERT(builder->remainingCollateralInputs > 0);
    builder->remainingCollateralInputs--;

    cbor_append_txInput(builder, collInput->txHash, TX_HASH_LENGTH, collInput->index);
}

static void txHashBuilder_assertCanLeaveCollateralInputs(tx_hash_builder_t *builder) {
    _TRACE("state = %u", builder->state);

    // No collateral inputs may remain: the same invariant whether this state was entered or
    // skipped entirely. Only walking back through the previous state is conditional.
    ASSERT(builder->remainingCollateralInputs == 0);
    if (builder->state != TX_HASH_BUILDER_IN_COLLATERAL_INPUTS) {
        txHashBuilder_assertCanLeaveScriptDataHash(builder);
    }
}

// ========================= REQUIRED SIGNERS ==========================

void txHashBuilder_enterRequiredSigners(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveCollateralInputs(builder);
    // we don't allow an empty list for an optional item
    ASSERT(builder->remainingRequiredSigners > 0);

    {
        // Enter required signers
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_REQUIRED_SIGNERS);
        BUILDER_TAG_CBOR_SET();
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->remainingRequiredSigners);
    }
    builder->state = TX_HASH_BUILDER_IN_REQUIRED_SIGNERS;
}

void txHashBuilder_addRequiredSigner(tx_hash_builder_t *builder,
                                     const uint8_t *vkeyBuffer,
                                     size_t vkeySize) {
    _TRACE("state = %d, remainingRequiredSigners = %u",
           builder->state,
           builder->remainingRequiredSigners);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_REQUIRED_SIGNERS);
    ASSERT(builder->remainingRequiredSigners > 0);
    builder->remainingRequiredSigners--;

    ASSERT(vkeySize < BUFFER_SIZE_PARANOIA);

    // Bytes[hash]
    {
        ASSERT(vkeySize == ADDRESS_KEY_HASH_LENGTH);
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, vkeySize);
        BUILDER_APPEND_DATA(vkeyBuffer, vkeySize);
    }
}

static void txHashBuilder_assertCanLeaveRequiredSigners(tx_hash_builder_t *builder) {
    _TRACE("state = %u", builder->state);

    // No required signers may remain: the same invariant whether this state was entered or
    // skipped entirely. Only walking back through the previous state is conditional.
    ASSERT(builder->remainingRequiredSigners == 0);
    if (builder->state != TX_HASH_BUILDER_IN_REQUIRED_SIGNERS) {
        txHashBuilder_assertCanLeaveCollateralInputs(builder);
    }
}

// ========================= NETWORK ID ==========================

void txHashBuilder_addNetworkId(tx_hash_builder_t *builder, uint8_t networkId) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveRequiredSigners(builder);
    ASSERT(builder->includeNetworkId);

    // add network id item into the main tx body map
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_NETWORK_ID);
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, networkId);

    builder->state = TX_HASH_BUILDER_IN_NETWORK_ID;
}

static void txHashBuilder_assertCanLeaveNetworkId(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    switch (builder->state) {
        case TX_HASH_BUILDER_IN_NETWORK_ID:
            // network id was added, we can move on
            break;

        default:
            // make sure network id was not expected
            ASSERT(!builder->includeNetworkId);
            // assert we can leave the previous state
            txHashBuilder_assertCanLeaveRequiredSigners(builder);
            break;
    }
}

// ========================= COLLATERAL RETURN OUTPUT ==========================

void txHashBuilder_addCollateralOutput(tx_hash_builder_t *builder,
                                       const tx_output_description_t *output) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveNetworkId(builder);
    ASSERT(builder->includeCollateralOutput);

    {
        // Enter collateral output
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_COLLATERAL_OUTPUT);
    }
    processOutputTopLevel(builder, output);

    builder->outputData.outputState = TX_OUTPUT_TOP_LEVEL_DATA;
    builder->state = TX_HASH_BUILDER_IN_COLLATERAL_OUTPUT;
}

void txHashBuilder_addCollateralOutput_tokenGroup(tx_hash_builder_t *builder,
                                                  const uint8_t *policyIdBuffer,
                                                  size_t policyIdSize,
                                                  uint16_t numTokens) {
    ASSERT(builder->state == TX_HASH_BUILDER_IN_COLLATERAL_OUTPUT);

    addTokenGroup(builder, policyIdBuffer, policyIdSize, numTokens);
}

void txHashBuilder_addCollateralOutput_token(tx_hash_builder_t *builder,
                                             const uint8_t *assetNameBuffer,
                                             size_t assetNameSize,
                                             uint64_t amount) {
    ASSERT(builder->state == TX_HASH_BUILDER_IN_COLLATERAL_OUTPUT);

    addToken(builder, assetNameBuffer, assetNameSize, amount, CBOR_TYPE_UNSIGNED);
}

static void txHashBuilder_assertCanLeaveCollateralOutput(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    switch (builder->state) {
        case TX_HASH_BUILDER_IN_COLLATERAL_OUTPUT:
            assertCanLeaveCurrentOutput(builder);
            // collateral return output was added, we can move on
            break;

        default:
            // make sure collateral return was not expected
            ASSERT(!builder->includeCollateralOutput);
            // assert we can leave the previous state
            txHashBuilder_assertCanLeaveNetworkId(builder);
            break;
    }
}

// ========================= TOTAL COLLATERAL ==========================

void txHashBuilder_addTotalCollateral(tx_hash_builder_t *builder, uint64_t txColl) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveCollateralOutput(builder);
    ASSERT(builder->includeTotalCollateral);

    // add TotalCollateral item into the main tx body map
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_TOTAL_COLLATERAL);
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, txColl);

    builder->state = TX_HASH_BUILDER_IN_TOTAL_COLLATERAL;
}

static void txHashBuilder_assertCanLeaveTotalCollateral(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    switch (builder->state) {
        case TX_HASH_BUILDER_IN_TOTAL_COLLATERAL:
            // total collateral was added, we can move on
            break;

        default:
            // make sure total collateral was not expected
            ASSERT(!builder->includeTotalCollateral);
            // assert we can leave the previous state
            txHashBuilder_assertCanLeaveCollateralOutput(builder);
            break;
    }
}

// ========================= REFERENCE INPUTS ==========================

void txHashBuilder_enterReferenceInputs(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveTotalCollateral(builder);
    // we don't allow an empty list for an optional item
    ASSERT(builder->remainingReferenceInputs > 0);

    {
        // Enter reference inputs
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_REFERENCE_INPUTS);
        BUILDER_TAG_CBOR_SET();
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->remainingReferenceInputs);
    }
    builder->state = TX_HASH_BUILDER_IN_REFERENCE_INPUTS;
}

void txHashBuilder_addReferenceInput(tx_hash_builder_t *builder, const tx_input_t *refInput) {
    _TRACE("state = %d, remainingReferenceInputs = %u",
           builder->state,
           builder->remainingReferenceInputs);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_REFERENCE_INPUTS);
    ASSERT(builder->remainingReferenceInputs > 0);
    builder->remainingReferenceInputs--;

    cbor_append_txInput(builder, refInput->txHash, TX_HASH_LENGTH, refInput->index);
}

static void txHashBuilder_assertCanLeaveReferenceInputs(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    // No reference inputs may remain: the same invariant whether this state was entered or
    // skipped entirely. Only walking back through the previous state is conditional.
    ASSERT(builder->remainingReferenceInputs == 0);
    if (builder->state != TX_HASH_BUILDER_IN_REFERENCE_INPUTS) {
        txHashBuilder_assertCanLeaveTotalCollateral(builder);
    }
}

// ========================= VOTING PROCEDURES ==========================

void txHashBuilder_enterVotingProcedures(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveReferenceInputs(builder);
    // we don't allow an empty map for an optional item
    ASSERT(builder->remainingVoters > 0);

    {
        // Enter voting procedures
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_VOTING_PROCEDURES);
        BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, builder->remainingVoters);
    }
    builder->state = TX_HASH_BUILDER_IN_VOTING_PROCEDURES;
}

void txHashBuilder_addVoter(tx_hash_builder_t *builder, const voter_t *voter, uint16_t numVotes) {
    _TRACE("state = %d, remainingVoters = %u, numVotes = %u",
           builder->state,
           builder->remainingVoters,
           numVotes);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_VOTING_PROCEDURES);
    ASSERT(builder->remainingVoters > 0);
    ASSERT(builder->remainingVotesPerVoter == 0);
    ASSERT(numVotes > 0);

    // Assert no KEY_PATH variants (must be converted before calling)
    builder->remainingVoters--;
    builder->remainingVotesPerVoter = numVotes;

    // voter - Array(2)[Unsigned[voter type], Bytes[key or script hash]]
    BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, voter->type);

    switch (voter->type) {
        case VOTER_COMMITTEE_HOT_KEY_HASH:
        case VOTER_DREP_KEY_HASH:
        case VOTER_STAKE_POOL_KEY_HASH: {
            BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, SIZEOF(voter->keyHash));
            BUILDER_APPEND_DATA(voter->keyHash, SIZEOF(voter->keyHash));
            break;
        }
        case VOTER_COMMITTEE_HOT_SCRIPT_HASH:
        case VOTER_DREP_SCRIPT_HASH: {
            BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, SIZEOF(voter->scriptHash));
            BUILDER_APPEND_DATA(voter->scriptHash, SIZEOF(voter->scriptHash));
            break;
        }
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    // Start the map of gov_action_id => voting_procedure
    BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, numVotes);
}

void txHashBuilder_addVote(tx_hash_builder_t *builder,
                           gov_action_id_t *govActionId,
                           voting_procedure_t *votingProcedure) {
    _TRACE("state = %d", builder->state);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_VOTING_PROCEDURES);
    ASSERT(builder->remainingVotesPerVoter > 0);
    builder->remainingVotesPerVoter--;

    // governance action id - Array(2)[Bytes[hash], Unsigned[index]]
    BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
    {
        size_t size = TX_HASH_LENGTH;
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, size);
        BUILDER_APPEND_DATA(govActionId->txHash, size);
    }
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, govActionId->govActionIndex);

    // voting procedure - Array(2)[Unsigned[vote], Null / anchor]
    BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, votingProcedure->vote);
    _appendAnchor(builder, &votingProcedure->anchor);
}

static void txHashBuilder_assertCanLeaveVotingProcedures(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);
    ASSERT(builder->remainingVoters == 0);
    ASSERT(builder->remainingVotesPerVoter == 0);
    if (builder->state != TX_HASH_BUILDER_IN_VOTING_PROCEDURES) {
        txHashBuilder_assertCanLeaveReferenceInputs(builder);
    }
}

// ============================== PROPOSAL PROCEDURES ==============================

static void _appendOptGovActionId(tx_hash_builder_t *builder,
                                  const opt_gov_action_id_t *optGovActionId) {
    if (optGovActionId->isIncluded) {
        // Array(2)[Bytes[hash], Unsigned[index]]
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
        {
            size_t size = TX_HASH_LENGTH;
            BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, size);
            BUILDER_APPEND_DATA(optGovActionId->govActionId.txHash, size);
        }
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, optGovActionId->govActionId.govActionIndex);
    } else {
        // Null
        BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
    }
}

// Null / Bytes[guardrailsScriptHash], shared by new_constitution (below) and
// treasury_withdrawals_action's finish() call: the two gov_action variants with an optional
// guardrails script hash.
static void _appendOptGuardrailsScriptHash(tx_hash_builder_t *builder,
                                           bool hasGuardrailsScriptHash,
                                           const uint8_t *guardrailsScriptHash) {
    if (hasGuardrailsScriptHash) {
        ASSERT(guardrailsScriptHash != NULL);
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, SCRIPT_HASH_LENGTH);
        BUILDER_APPEND_DATA(guardrailsScriptHash, SCRIPT_HASH_LENGTH);
    } else {
        BUILDER_APPEND_CBOR(CBOR_TYPE_NULL, 0);
    }
}

static void _appendGovAction(tx_hash_builder_t *builder, const gov_action_t *govAction) {
    switch (govAction->type) {
        case GOV_ACTION_INFO:
            // Array(1)[Unsigned[6]]
            BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 1);
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, GOV_ACTION_INFO);
            break;

        case GOV_ACTION_NO_CONFIDENCE:
            // Array(2)[Unsigned[3], Null / ...gov_action_id]
            BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, GOV_ACTION_NO_CONFIDENCE);
            _appendOptGovActionId(builder, &govAction->noConfidence);
            break;

        case GOV_ACTION_HARD_FORK_INITIATION:
            // Array(3)[
            //   Unsigned[1]
            //   Null / ...gov_action_id
            //   Array(2)[Unsigned[major], Unsigned[minor]]
            // ]
            BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, GOV_ACTION_HARD_FORK_INITIATION);
            _appendOptGovActionId(builder, &govAction->hardForkInitiation.prevActionId);
            BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED,
                                govAction->hardForkInitiation.protocolVersion.major);
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED,
                                govAction->hardForkInitiation.protocolVersion.minor);
            break;

        case GOV_ACTION_NEW_CONSTITUTION:
            // Array(3)[
            //   Unsigned[5]
            //   Null / ...gov_action_id
            //   Array(2)[...anchor, Null / Bytes[guardrails_script_hash]]
            // ]
            BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, GOV_ACTION_NEW_CONSTITUTION);
            _appendOptGovActionId(builder, &govAction->newConstitution.prevActionId);
            BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
            _appendAnchor(builder, &govAction->newConstitution.constitutionAnchor);
            _appendOptGuardrailsScriptHash(builder,
                                           govAction->newConstitution.hasGuardrailsScriptHash,
                                           govAction->newConstitution.guardrailsScriptHash);
            break;

        // LCOV_EXCL_START
        case GOV_ACTION_TREASURY_WITHDRAWALS:
        case GOV_ACTION_UPDATE_COMMITTEE:
            // Handled by their own multi-call API (txHashBuilder_treasuryWithdrawals_*,
            // txHashBuilder_updateCommittee_*) instead of this function.
            ASSERT(false);
            break;
        default:
            ASSERT(false);
            break;
            // LCOV_EXCL_STOP
    }
}

void txHashBuilder_enterProposalProcedures(tx_hash_builder_t *builder) {
    txHashBuilder_assertCanLeaveVotingProcedures(builder);
    ASSERT(builder->remainingProposalProcedures > 0);

    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_PROPOSAL_PROCEDURES);
        BUILDER_TAG_CBOR_SET();
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, builder->remainingProposalProcedures);
    }
    builder->state = TX_HASH_BUILDER_IN_PROPOSAL_PROCEDURES;
}

// Common proposal_procedure envelope prologue (validates/decrements remainingProposalProcedures,
// then opens Array(4) and emits deposit + reward account bytes), identical across all three
// ways a proposal_procedure's gov_action is emitted (simple variants, update_committee,
// treasury_withdrawals_action). Each caller appends its own gov_action array afterward.
static void _appendProposalEnvelope(tx_hash_builder_t *builder,
                                    uint64_t deposit,
                                    const uint8_t *rewardAccountBuffer,
                                    size_t rewardAccountSize) {
    _TRACE("state = %d, remainingProposalProcedures = %u",
           builder->state,
           builder->remainingProposalProcedures);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_PROPOSAL_PROCEDURES);
    ASSERT(builder->remainingProposalProcedures > 0);
    builder->remainingProposalProcedures--;

    ASSERT(rewardAccountSize == REWARD_ACCOUNT_LENGTH);

    BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 4);
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, deposit);
    }
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, rewardAccountSize);
        BUILDER_APPEND_DATA(rewardAccountBuffer, rewardAccountSize);
    }
}

void txHashBuilder_addProposalProcedure(tx_hash_builder_t *builder,
                                        uint64_t deposit,
                                        const uint8_t *rewardAccountBuffer,
                                        size_t rewardAccountSize,
                                        const gov_action_t *govAction,
                                        const anchor_t *anchor) {
    ASSERT(govAction != NULL);
    ASSERT(anchor != NULL);

    // Array(4)[
    //   Unsigned[deposit]
    //   Bytes[rewardAccount]
    //   gov_action (variant-tagged array; see _appendGovAction)
    //   Null / ...anchor
    // ]
    _appendProposalEnvelope(builder, deposit, rewardAccountBuffer, rewardAccountSize);
    {
        _appendGovAction(builder, govAction);
    }
    {
        _appendAnchor(builder, anchor);
    }
}

void txHashBuilder_updateCommittee_enter(tx_hash_builder_t *builder,
                                         uint64_t deposit,
                                         const uint8_t *rewardAccountBuffer,
                                         size_t rewardAccountSize,
                                         const opt_gov_action_id_t *prevActionId,
                                         uint16_t numRemovals) {
    ASSERT(prevActionId != NULL);

    // Array(4)[ ; proposal_procedure
    //   Unsigned[deposit]
    //   Bytes[rewardAccount]
    //   Array(5)[ ; gov_action (update_committee)
    //     Unsigned[4]
    //     Null / ...gov_action_id ; prevActionId
    //     [Tag(258)] Array(numRemovals)[...] ; removal set, streamed by addRemoval()
    //     ... ; addition map and anchor, see enterAdditions() and finish()
    //   ]
    // ]
    _appendProposalEnvelope(builder, deposit, rewardAccountBuffer, rewardAccountSize);
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 5);
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, GOV_ACTION_UPDATE_COMMITTEE);
        _appendOptGovActionId(builder, prevActionId);
        BUILDER_TAG_CBOR_SET();
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, numRemovals);
    }

    builder->committeeUpdateData.remainingCommitteeRemovals = numRemovals;
    builder->state = TX_HASH_BUILDER_IN_PROPOSAL_UPDATE_COMMITTEE_REMOVALS;
}

void txHashBuilder_updateCommittee_addRemoval(tx_hash_builder_t *builder,
                                              const credential_t *credential) {
    _TRACE("state = %d, remainingCommitteeRemovals = %u",
           builder->state,
           builder->committeeUpdateData.remainingCommitteeRemovals);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_PROPOSAL_UPDATE_COMMITTEE_REMOVALS);
    ASSERT(builder->committeeUpdateData.remainingCommitteeRemovals > 0);
    builder->committeeUpdateData.remainingCommitteeRemovals--;

    _appendCredential(builder, credential);
}

void txHashBuilder_updateCommittee_enterAdditions(tx_hash_builder_t *builder,
                                                  uint16_t numAdditions) {
    ASSERT(builder->state == TX_HASH_BUILDER_IN_PROPOSAL_UPDATE_COMMITTEE_REMOVALS);
    ASSERT(builder->committeeUpdateData.remainingCommitteeRemovals == 0);

    // Map(numAdditions)[ credential (Array(2)) => Unsigned[epoch], ... ], streamed by addAddition()
    BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, numAdditions);

    builder->committeeUpdateData.remainingCommitteeAdditions = numAdditions;
    builder->state = TX_HASH_BUILDER_IN_PROPOSAL_UPDATE_COMMITTEE_ADDITIONS;
}

void txHashBuilder_updateCommittee_addAddition(tx_hash_builder_t *builder,
                                               const credential_t *credential,
                                               uint64_t expirationEpoch) {
    _TRACE("state = %d, remainingCommitteeAdditions = %u",
           builder->state,
           builder->committeeUpdateData.remainingCommitteeAdditions);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_PROPOSAL_UPDATE_COMMITTEE_ADDITIONS);
    ASSERT(builder->committeeUpdateData.remainingCommitteeAdditions > 0);
    builder->committeeUpdateData.remainingCommitteeAdditions--;

    _appendCredential(builder, credential);
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, expirationEpoch);
}

void txHashBuilder_updateCommittee_finish(tx_hash_builder_t *builder,
                                          uint64_t thresholdNumerator,
                                          uint64_t thresholdDenominator,
                                          const anchor_t *anchor) {
    ASSERT(builder->state == TX_HASH_BUILDER_IN_PROPOSAL_UPDATE_COMMITTEE_ADDITIONS);
    ASSERT(builder->committeeUpdateData.remainingCommitteeAdditions == 0);
    ASSERT(anchor != NULL);

    // Tag(30) Array(2)[Unsigned[numerator], Unsigned[denominator]] ; unit_interval threshold,
    // closes gov_action's Array(5); anchor closes proposal_procedure's Array(4).
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_TAG, CBOR_TAG_UNIT_INTERVAL);
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, thresholdNumerator);
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, thresholdDenominator);
    }
    {
        _appendAnchor(builder, anchor);
    }

    builder->state = TX_HASH_BUILDER_IN_PROPOSAL_PROCEDURES;
}

void txHashBuilder_treasuryWithdrawals_enter(tx_hash_builder_t *builder,
                                             uint64_t deposit,
                                             const uint8_t *rewardAccountBuffer,
                                             size_t rewardAccountSize,
                                             uint16_t numWithdrawals) {
    // Array(4)[ ; proposal_procedure
    //   Unsigned[deposit]
    //   Bytes[rewardAccount]
    //   Array(3)[ ; gov_action (treasury_withdrawals_action)
    //     Unsigned[2]
    //     Map(numWithdrawals)[...] ; withdrawals map, streamed by addWithdrawal()
    //     ... ; guardrails and anchor, see finish()
    //   ]
    // ]
    _appendProposalEnvelope(builder, deposit, rewardAccountBuffer, rewardAccountSize);
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 3);
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, GOV_ACTION_TREASURY_WITHDRAWALS);
        BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, numWithdrawals);
    }

    builder->treasuryWithdrawalsData.remainingTreasuryWithdrawals = numWithdrawals;
    builder->state = TX_HASH_BUILDER_IN_PROPOSAL_TREASURY_WITHDRAWALS_ENTRIES;
}

void txHashBuilder_treasuryWithdrawals_addWithdrawal(tx_hash_builder_t *builder,
                                                     const uint8_t *withdrawalRewardAccountBuffer,
                                                     size_t withdrawalRewardAccountSize,
                                                     uint64_t coin) {
    _TRACE("state = %d, remainingTreasuryWithdrawals = %u",
           builder->state,
           builder->treasuryWithdrawalsData.remainingTreasuryWithdrawals);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_PROPOSAL_TREASURY_WITHDRAWALS_ENTRIES);
    ASSERT(builder->treasuryWithdrawalsData.remainingTreasuryWithdrawals > 0);
    builder->treasuryWithdrawalsData.remainingTreasuryWithdrawals--;

    ASSERT(withdrawalRewardAccountSize == REWARD_ACCOUNT_LENGTH);

    BUILDER_APPEND_CBOR(CBOR_TYPE_BYTES, withdrawalRewardAccountSize);
    BUILDER_APPEND_DATA(withdrawalRewardAccountBuffer, withdrawalRewardAccountSize);
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, coin);
}

// Null / Bytes[guardrailsScriptHash] closing the gov_action array, then the anchor closing
// proposal_procedure's Array(4): the identical tail of treasury_withdrawals_action and
// parameter_change_action. Each caller asserts its own state/counter invariants first.
static void _finishGuardrailsAndAnchor(tx_hash_builder_t *builder,
                                       bool hasGuardrailsScriptHash,
                                       const uint8_t *guardrailsScriptHash,
                                       const anchor_t *anchor) {
    ASSERT(anchor != NULL);

    _appendOptGuardrailsScriptHash(builder, hasGuardrailsScriptHash, guardrailsScriptHash);
    {
        _appendAnchor(builder, anchor);
    }

    builder->state = TX_HASH_BUILDER_IN_PROPOSAL_PROCEDURES;
}

void txHashBuilder_treasuryWithdrawals_finish(tx_hash_builder_t *builder,
                                              bool hasGuardrailsScriptHash,
                                              const uint8_t *guardrailsScriptHash,
                                              const anchor_t *anchor) {
    ASSERT(builder->state == TX_HASH_BUILDER_IN_PROPOSAL_TREASURY_WITHDRAWALS_ENTRIES);
    ASSERT(builder->treasuryWithdrawalsData.remainingTreasuryWithdrawals == 0);

    _finishGuardrailsAndAnchor(builder, hasGuardrailsScriptHash, guardrailsScriptHash, anchor);
}

// Tag(30) Array(2)[Unsigned[numerator], Unsigned[denominator]], the shared ratio shape for
// unit_interval / nonnegative_interval protocol_param_update values.
static void _appendParamRatio(tx_hash_builder_t *builder, const param_ratio_t *ratio) {
    BUILDER_APPEND_CBOR(CBOR_TYPE_TAG, CBOR_TAG_UNIT_INTERVAL);
    BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, ratio->numerator);
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, ratio->denominator);
}

void txHashBuilder_parameterChange_enter(tx_hash_builder_t *builder,
                                         uint64_t deposit,
                                         const uint8_t *rewardAccountBuffer,
                                         size_t rewardAccountSize,
                                         const opt_gov_action_id_t *prevActionId,
                                         uint16_t numPresentFields) {
    ASSERT(prevActionId != NULL);

    // Array(4)[ ; proposal_procedure
    //   Unsigned[deposit]
    //   Bytes[rewardAccount]
    //   Array(4)[ ; gov_action (parameter_change_action)
    //     Unsigned[0]
    //     Null / ...gov_action_id ; prevActionId
    //     Map(numPresentFields)[...] ; protocol_param_update, streamed by addField()
    //     ... ; guardrails and anchor, see finish()
    //   ]
    // ]
    _appendProposalEnvelope(builder, deposit, rewardAccountBuffer, rewardAccountSize);
    {
        BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 4);
        BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, GOV_ACTION_PARAMETER_CHANGE);
        _appendOptGovActionId(builder, prevActionId);
        BUILDER_APPEND_CBOR(CBOR_TYPE_MAP, numPresentFields);
    }

    builder->parameterChangeData.remainingParameterChangeFields = numPresentFields;
    builder->state = TX_HASH_BUILDER_IN_PROPOSAL_PARAMETER_CHANGE_FIELDS;
}

void txHashBuilder_parameterChange_addField(tx_hash_builder_t *builder,
                                            uint8_t cddlKey,
                                            const parsed_param_field_t *field) {
    _TRACE("state = %d, remainingParameterChangeFields = %u",
           builder->state,
           builder->parameterChangeData.remainingParameterChangeFields);

    ASSERT(builder->state == TX_HASH_BUILDER_IN_PROPOSAL_PARAMETER_CHANGE_FIELDS);
    ASSERT(builder->parameterChangeData.remainingParameterChangeFields > 0);
    builder->parameterChangeData.remainingParameterChangeFields--;

    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, cddlKey);
    switch (field->kind) {
        case PARAM_FIELD_COIN:
        case PARAM_FIELD_UINT:
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, field->scalar);
            break;
        case PARAM_FIELD_EX_UNITS:
            BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, 2);
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, field->exUnits.memory);
            BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, field->exUnits.steps);
            break;
        case PARAM_FIELD_RATIO:
            _appendParamRatio(builder, &field->ratio);
            break;
        // EX_UNIT_PRICES/*_VOTING_THRESHOLDS are all just Array(N)[ratio x N] (N = 2/5/10) on
        // the wire; RATIO alone has no wrapping array, so it stays separate above.
        case PARAM_FIELD_EX_UNIT_PRICES:
        case PARAM_FIELD_POOL_VOTING_THRESHOLDS:
        case PARAM_FIELD_DREP_VOTING_THRESHOLDS: {
            uint8_t count = param_field_ratio_count(field->kind);
            BUILDER_APPEND_CBOR(CBOR_TYPE_ARRAY, count);
            for (uint8_t i = 0; i < count; i++) {
                _appendParamRatio(builder, &field->ratios[i]);
            }
            break;
        }
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown param field kind");
            break;
            // LCOV_EXCL_STOP
    }
}

void txHashBuilder_parameterChange_finish(tx_hash_builder_t *builder,
                                          bool hasGuardrailsScriptHash,
                                          const uint8_t *guardrailsScriptHash,
                                          const anchor_t *anchor) {
    ASSERT(builder->state == TX_HASH_BUILDER_IN_PROPOSAL_PARAMETER_CHANGE_FIELDS);
    ASSERT(builder->parameterChangeData.remainingParameterChangeFields == 0);

    _finishGuardrailsAndAnchor(builder, hasGuardrailsScriptHash, guardrailsScriptHash, anchor);
}

static void txHashBuilder_assertCanLeaveProposalProcedures(tx_hash_builder_t *builder) {
    // No proposal procedures may remain: the same invariant whether this state was entered or
    // skipped entirely. Only walking back through the previous state is conditional.
    ASSERT(builder->remainingProposalProcedures == 0);
    if (builder->state != TX_HASH_BUILDER_IN_PROPOSAL_PROCEDURES) {
        txHashBuilder_assertCanLeaveVotingProcedures(builder);
    }
}

// ============================== TREASURY ==============================

void txHashBuilder_addTreasury(tx_hash_builder_t *builder, uint64_t treasury) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveProposalProcedures(builder);

    // add treasury item into the main tx body map
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_TREASURY);
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, treasury);

    builder->state = TX_HASH_BUILDER_IN_TREASURY;
}

static void txHashBuilder_assertCanLeaveTreasury(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    switch (builder->state) {
        case TX_HASH_BUILDER_IN_TREASURY:
            // treasury item was added, we can move on
            break;

        default:
            // make sure treasury was not expected
            ASSERT(!builder->includeTreasury);
            // assert we can leave the previous state
            txHashBuilder_assertCanLeaveProposalProcedures(builder);
            break;
    }
}

// ============================== DONATION ==============================

void txHashBuilder_addDonation(tx_hash_builder_t *builder, uint64_t donation) {
    _TRACE("state = %d", builder->state);

    txHashBuilder_assertCanLeaveTreasury(builder);

    // add donation item into the main tx body map
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, TX_BODY_KEY_DONATION);
    BUILDER_APPEND_CBOR(CBOR_TYPE_UNSIGNED, donation);

    builder->state = TX_HASH_BUILDER_IN_DONATION;
}

static void txHashBuilder_assertCanLeaveDonation(tx_hash_builder_t *builder) {
    _TRACE("state = %d", builder->state);

    switch (builder->state) {
        case TX_HASH_BUILDER_IN_DONATION:
            // donation item was added, we can move on
            break;

        default:
            // make sure donation was not expected
            ASSERT(!builder->includeDonation);
            // assert we can leave the previous state
            txHashBuilder_assertCanLeaveTreasury(builder);
            break;
    }
}

// ========================= FINALIZE ==========================

void txHashBuilder_finalize(tx_hash_builder_t *builder, uint8_t *outBuffer, size_t outSize) {
    txHashBuilder_assertCanLeaveDonation(builder);

    ASSERT(outSize == TX_HASH_LENGTH);
    {
        blake2b_256_finalize(&builder->txHash, outBuffer, outSize);
    }

    builder->state = TX_HASH_BUILDER_FINISHED;
#ifdef TRACE_TX_HASH_BUILDER
    TRACE("tx_body (%u bytes)", (unsigned int) tx_body_trace_size);
    TRACE_BUFFER(tx_body_trace_buffer, tx_body_trace_size);
#endif
}

#ifdef TRACE_TX_HASH_BUILDER
// LCOV_EXCL_START
size_t txHashBuilder_get_trace_body(uint8_t *outBuffer, size_t outMaxSize) {
    size_t copy = (tx_body_trace_size < outMaxSize) ? tx_body_trace_size : outMaxSize;
    memcpy(outBuffer, tx_body_trace_buffer, copy);
    return copy;
}
// LCOV_EXCL_STOP
#endif
