/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "cardano_buffer.h"
#include "cardano_parsers.h"
#include "keyDerivation.h"
#include "addressUtilsByron.h"
#include "addressUtilsShelley.h"
#include "bip44.h"
#include "base58.h"
#include "bech32.h"

uint8_t getAddressHeader(const uint8_t* addressBuffer, size_t addressSize) {
    ASSERT(addressSize > 0);
    ASSERT(addressSize < BUFFER_SIZE_PARANOIA);

    return addressBuffer[0];
}

address_type_t getAddressType(uint8_t addressHeader) {
    const uint8_t ADDRESS_TYPE_MASK = 0xF0;
    return (addressHeader & ADDRESS_TYPE_MASK) >> 4;
}

bool isSupportedAddressType(uint8_t addressType) {
    switch (addressType) {
        case BASE_PAYMENT_KEY_STAKE_KEY:
        case BASE_PAYMENT_SCRIPT_STAKE_KEY:
        case BASE_PAYMENT_KEY_STAKE_SCRIPT:
        case BASE_PAYMENT_SCRIPT_STAKE_SCRIPT:
        case POINTER_KEY:
        case POINTER_SCRIPT:
        case ENTERPRISE_KEY:
        case ENTERPRISE_SCRIPT:
        case BYRON:
        case REWARD_KEY:
        case REWARD_SCRIPT:
            return true;
        default:
            return false;
    }
}

bool isShelleyAddressType(uint8_t addressType) {
    switch (addressType) {
        case BASE_PAYMENT_KEY_STAKE_KEY:
        case BASE_PAYMENT_SCRIPT_STAKE_KEY:
        case BASE_PAYMENT_KEY_STAKE_SCRIPT:
        case BASE_PAYMENT_SCRIPT_STAKE_SCRIPT:
        case POINTER_KEY:
        case POINTER_SCRIPT:
        case ENTERPRISE_KEY:
        case ENTERPRISE_SCRIPT:
        case REWARD_KEY:
        case REWARD_SCRIPT:
            return true;
        default:
            return false;
    }
}

uint8_t constructShelleyAddressHeader(address_type_t type, uint8_t networkId) {
    ASSERT(isSupportedAddressType(type));
    ASSERT(isValidNetworkId(networkId));

    return (type << 4) | networkId;
}

uint8_t getNetworkId(uint8_t addressHeader) {
    const uint8_t NETWORK_ID_MASK = 0x0F;
    return addressHeader & NETWORK_ID_MASK;
}

bool isValidNetworkId(uint8_t networkId) {
    return networkId <= MAXIMUM_NETWORK_ID;
}

static bool is_valid_staking_part_type(staking_part_type_t stakingPartType) {
    switch (stakingPartType) {
        case STAKING_PART_NONE:
        case STAKING_PART_KEY_PATH:
        case STAKING_PART_KEY_HASH:
        case STAKING_PART_BLOCKCHAIN_POINTER:
        case STAKING_PART_SCRIPT_HASH:
            return true;
        default:
            return false;
    }
}

static bool is_staking_part_consistent_with_address_type(const address_params_t* address_params) {
#define CONSISTENT_WITH(STAKING_CHOICE) \
    if (address_params->stakingPartType == (STAKING_CHOICE)) return true

    switch (address_params->type) {
        case BASE_PAYMENT_KEY_STAKE_KEY:
        case BASE_PAYMENT_SCRIPT_STAKE_KEY:
        case REWARD_KEY:
            CONSISTENT_WITH(STAKING_PART_KEY_HASH);
            CONSISTENT_WITH(STAKING_PART_KEY_PATH);
            break;

        case BASE_PAYMENT_KEY_STAKE_SCRIPT:
        case BASE_PAYMENT_SCRIPT_STAKE_SCRIPT:
            CONSISTENT_WITH(STAKING_PART_SCRIPT_HASH);

            __attribute__((fallthrough));
        case POINTER_KEY:
        case POINTER_SCRIPT:
            CONSISTENT_WITH(STAKING_PART_BLOCKCHAIN_POINTER);
            break;

        case REWARD_SCRIPT:
            CONSISTENT_WITH(STAKING_PART_SCRIPT_HASH);
            break;

        case ENTERPRISE_KEY:
        case ENTERPRISE_SCRIPT:
        case BYRON:
            CONSISTENT_WITH(STAKING_PART_NONE);
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    return false;

#undef CONSISTENT_WITH
}

__noinline_due_to_stack__ static bool buffer_write_pubkey_hash(
    buffer_t* buf,
    const bip44_path_t* keyDerivationPath) {
    uint8_t hashedPubKey[ADDRESS_KEY_HASH_LENGTH] = {0};
    keyPathToKeyHash(keyDerivationPath, hashedPubKey, SIZEOF(hashedPubKey));

    return buffer_write_bytes(buf, hashedPubKey, SIZEOF(hashedPubKey));
}

// Write the payment credential (key-hash or script-hash) into buf.
static void write_payment_credential(buffer_t* buf, const address_params_t* address_params) {
    ASSERT(isValidAddressParams(address_params));
    switch (address_params->paymentPartType) {
        case PAYMENT_PART_KEY_PATH:
            ASSERT(buffer_write_pubkey_hash(buf, &address_params->paymentKeyPath));
            break;
        case PAYMENT_PART_SCRIPT_HASH:
            ASSERT(buffer_write_bytes(buf, address_params->paymentScriptHash, SCRIPT_HASH_LENGTH));
            break;
        // LCOV_EXCL_START
        case PAYMENT_PART_NONE:
            // reward addresses bypass write_payment_credential entirely via deriveAddress_reward
            break;
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }
}

// Write the staking credential (key-hash or script-hash) into buf.
// stakingPartType must be one of STAKING_PART_KEY_PATH / STAKING_PART_KEY_HASH /
// STAKING_PART_SCRIPT_HASH.
static void write_staking_credential(buffer_t* buf, const address_params_t* address_params) {
    ASSERT(isValidAddressParams(address_params));
    switch (address_params->stakingPartType) {
        case STAKING_PART_KEY_PATH:
            ASSERT(buffer_write_pubkey_hash(buf, &address_params->stakingKeyPath));
            break;
        case STAKING_PART_KEY_HASH:
            ASSERT(
                buffer_write_bytes(buf, address_params->stakingKeyHash, ADDRESS_KEY_HASH_LENGTH));
            break;
        case STAKING_PART_SCRIPT_HASH:
            ASSERT(buffer_write_bytes(buf, address_params->stakingScriptHash, SCRIPT_HASH_LENGTH));
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }
}

static bool buffer_appendVariableLengthUInt(buffer_t* buf, uint64_t value) {
    ASSERT(value < (1llu << 63));  // avoid accidental cast from negative signed value

    if (value == 0) {
        uint8_t byte = 0;
        return buffer_write_bytes(buf, &byte, 1);
    }

    ASSERT(value > 0);

    uint8_t chunks[10] = {0};  // 7-bit chunks of the input bits, at most 10 in uint64
    size_t outputSize = 0;
    {
        uint64_t bits = value;
        while (bits > 0) {
            // take next 7 bits from the right
            chunks[outputSize++] = bits & 0x7F;
            bits >>= 7;
        }
    }
    ASSERT(outputSize > 0);
    for (size_t i = outputSize - 1; i > 0; --i) {
        // highest bit set to 1 since more bytes follow
        uint8_t nextByte = chunks[i] | 0x80;
        if (!buffer_write_bytes(buf, &nextByte, 1)) {
            return false;  // LCOV_EXCL_LINE
        }
    }
    // write the remaining byte, highest bit 0
    return buffer_write_bytes(buf, &chunks[0], 1);
}

static size_t deriveAddress_reward(const address_params_t* address_params,
                                   uint8_t* outBuffer,
                                   size_t outSize) {
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);

    const uint8_t header =
        constructShelleyAddressHeader(address_params->type, address_params->networkId);

    buffer_t out = buffer_create(outBuffer, outSize);
    ASSERT(buffer_write_bytes(&out, &header, 1));
    // no payment data — reward addresses contain only the staking credential
    write_staking_credential(&out, address_params);
    return out.offset;
}

__noinline_due_to_stack__ size_t constructRewardAddressFromKeyPath(const bip44_path_t* path,
                                                                   uint8_t networkId,
                                                                   uint8_t* outBuffer,
                                                                   size_t outSize) {
    ASSERT(outSize == REWARD_ACCOUNT_LENGTH);
    ASSERT(bip44_isOrdinaryStakingKeyPath(path));

    address_params_t address_paramsStub;
    explicit_bzero(&address_paramsStub, SIZEOF(address_paramsStub));
    address_paramsStub.type = REWARD_KEY;
    address_paramsStub.networkId = networkId;
    address_paramsStub.paymentPartType = PAYMENT_PART_NONE;
    address_paramsStub.stakingPartType = STAKING_PART_KEY_PATH;
    address_paramsStub.stakingKeyPath = *path;
    return deriveAddress_reward(&address_paramsStub, outBuffer, outSize);
}

__noinline_due_to_stack__ size_t constructRewardAddressFromHash(uint8_t networkId,
                                                                reward_address_hash_source_t source,
                                                                const uint8_t* hashBuffer,
                                                                size_t hashSize,
                                                                uint8_t* outBuffer,
                                                                size_t outSize) {
    ASSERT(isValidNetworkId(networkId));
    ASSERT(hashBuffer != NULL);
    ASSERT(outBuffer != NULL);
    ASSERT(hashSize == ADDRESS_KEY_HASH_LENGTH);
    STATIC_ASSERT(ADDRESS_KEY_HASH_LENGTH == SCRIPT_HASH_LENGTH, "incompatible hash sizes");
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);

    buffer_t out = buffer_create(outBuffer, outSize);
    {
        const uint8_t addressHeader = constructShelleyAddressHeader(
            (source == REWARD_HASH_SOURCE_KEY) ? REWARD_KEY : REWARD_SCRIPT,
            networkId);
        ASSERT(buffer_write_bytes(&out, &addressHeader, 1));
        ASSERT(buffer_write_bytes(&out, hashBuffer, hashSize));
    }

    const int ADDRESS_LENGTH = REWARD_ACCOUNT_LENGTH;
    ASSERT(out.offset == ADDRESS_LENGTH);

    return out.offset;
}

__noinline_due_to_stack__ size_t deriveAddress(const address_params_t* address_params,
                                               uint8_t* outBuffer,
                                               size_t outSize) {
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);
    ASSERT(isValidAddressParams(address_params));

    // Byron is a completely different serialisation
    if (address_params->type == BYRON) {
        return deriveAddress_byron(&address_params->paymentKeyPath,
                                   address_params->protocolMagic,
                                   outBuffer,
                                   outSize);
    }

    // Reward addresses are also called from constructRewardAddressFromKeyPath
    if (address_params->type == REWARD_KEY || address_params->type == REWARD_SCRIPT) {
        return deriveAddress_reward(address_params, outBuffer, outSize);
    }

    // All remaining Shelley types: header + payment + (staking credential | blockchain pointer |
    // nothing)
    buffer_t out = buffer_create(outBuffer, outSize);
    const uint8_t header =
        constructShelleyAddressHeader(address_params->type, address_params->networkId);
    ASSERT(buffer_write_bytes(&out, &header, 1));
    write_payment_credential(&out, address_params);

    switch (address_params->stakingPartType) {
        case STAKING_PART_KEY_PATH:
        case STAKING_PART_KEY_HASH:
        case STAKING_PART_SCRIPT_HASH:
            write_staking_credential(&out, address_params);
            break;
        case STAKING_PART_BLOCKCHAIN_POINTER: {
            const blockchainPointer_t* ptr = &address_params->stakingKeyBlockchainPointer;
            ASSERT(buffer_appendVariableLengthUInt(&out, ptr->blockIndex));
            ASSERT(buffer_appendVariableLengthUInt(&out, ptr->txIndex));
            ASSERT(buffer_appendVariableLengthUInt(&out, ptr->certificateIndex));
            break;
        }
        case STAKING_PART_NONE:
            // enterprise addresses — nothing to append
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    return out.offset;
}

bool format_blockchain_pointer(blockchainPointer_t blockchainPointer, char* out, size_t outSize) {
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);

    explicit_bzero(out, outSize);

    STATIC_ASSERT(sizeof(blockchainIndex_t) <= sizeof(unsigned), "oversized type for %u");
    STATIC_ASSERT(!IS_SIGNED_TYPE(typeof(blockchainPointer.blockIndex)), "signed type for %u");
    STATIC_ASSERT(!IS_SIGNED_TYPE(typeof(blockchainPointer.txIndex)), "signed type for %u");
    STATIC_ASSERT(!IS_SIGNED_TYPE(typeof(blockchainPointer.certificateIndex)),
                  "signed type for %u");

    ASSERT(outSize > 0);
    int written = snprintf(out,
                           outSize,
                           "(%u, %u, %u)",
                           blockchainPointer.blockIndex,
                           blockchainPointer.txIndex,
                           blockchainPointer.certificateIndex);
    LEDGER_ASSERT(written > 0, "snprintf blockchain pointer formatting failed");
    LEDGER_ASSERT((size_t) written + 1 < outSize,
                  "Blockchain pointer string does not fit");  // checks for truncation
    return true;
}

bool format_address_human_readable(const uint8_t* address,
                                   size_t addressSize,
                                   char* out,
                                   size_t outSize) {
    ASSERT(addressSize > 0);
    ASSERT(addressSize < BUFFER_SIZE_PARANOIA);
    ASSERT(outSize < BUFFER_SIZE_PARANOIA);

    const uint8_t addressType = getAddressType(address[0]);
    const uint8_t networkId = getNetworkId(address[0]);

    if (addressType == BYRON) {
        if (addressSize > MAX_ENC_INPUT_SIZE) {
            return false;
        }
        int len = base58_encode(address, addressSize, out, outSize - 1);
        if (len < 0) {
            return false;
        }
        out[len] = '\0';
        ASSERT((size_t) len == strlen(out));
        ASSERT((size_t) len + 1 < outSize);  // checks for truncation
        return true;
    }

    ASSERT(isValidNetworkId(networkId));

    switch (addressType) {
        // LCOV_EXCL_START
        case BYRON:
            // BYRON is handled before reaching this switch; this case is an invariant trap
            ASSERT(false);
            __attribute__((fallthrough));
        // LCOV_EXCL_STOP
        case REWARD_KEY:
        case REWARD_SCRIPT: {
            const char* hrp = (networkId == TESTNET_NETWORK_ID)
                                  ? BECH32_PREFIX_TESTNET_STAKE_ADDRESS
                                  : BECH32_PREFIX_STAKE_ADDRESS;
            bool encoded = format_bech32(hrp, address, addressSize, out, outSize);
            if (!encoded) {
                return false;  // LCOV_EXCL_LINE
            }
            ASSERT(strlen(out) + 1 < outSize);  // checks for truncation
            return true;
        }

        default:  // all other shelley addresses
        {
            const char* hrp = (networkId == TESTNET_NETWORK_ID) ? BECH32_PREFIX_TESTNET_ADDRESS
                                                                : BECH32_PREFIX_ADDRESS;
            bool encoded = format_bech32(hrp, address, addressSize, out, outSize);
            if (!encoded) {
                return false;  // LCOV_EXCL_LINE
            }
            ASSERT(strlen(out) + 1 < outSize);  // checks for truncation
            return true;
        }
    }
}

__noinline_due_to_stack__ bool format_reward_account_from_credential(
    uint8_t networkId,
    const ext_credential_t* credential,
    char* out,
    size_t outSize) {
    ASSERT(credential != NULL);
    ASSERT(out != NULL);

    uint8_t reward_addr_bytes[REWARD_ACCOUNT_LENGTH];
    size_t reward_addr_len = 0;

    switch (credential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            reward_addr_len = constructRewardAddressFromKeyPath(&credential->keyPath,
                                                                networkId,
                                                                reward_addr_bytes,
                                                                sizeof(reward_addr_bytes));
            break;
        case EXT_CREDENTIAL_KEY_HASH:
            ASSERT(credential->keyHash != NULL);
            reward_addr_len = constructRewardAddressFromHash(networkId,
                                                             REWARD_HASH_SOURCE_KEY,
                                                             credential->keyHash,
                                                             ADDRESS_KEY_HASH_LENGTH,
                                                             reward_addr_bytes,
                                                             sizeof(reward_addr_bytes));
            break;
        case EXT_CREDENTIAL_SCRIPT_HASH:
            ASSERT(credential->scriptHash != NULL);
            reward_addr_len = constructRewardAddressFromHash(networkId,
                                                             REWARD_HASH_SOURCE_SCRIPT,
                                                             credential->scriptHash,
                                                             SCRIPT_HASH_LENGTH,
                                                             reward_addr_bytes,
                                                             sizeof(reward_addr_bytes));
            break;
        default:
            return false;
    }

    ASSERT(reward_addr_len > 0);

    return format_address_human_readable(reward_addr_bytes, reward_addr_len, out, outSize);
}

__noinline_due_to_stack__ bool format_pool_reward_account(
    uint8_t networkId,
    const pool_reward_account_t* rewardAccount,
    char* out,
    size_t outSize) {
    ASSERT(rewardAccount != NULL);
    ASSERT(out != NULL);

    uint8_t reward_account_buf[REWARD_ACCOUNT_LENGTH] = {0};
    poolRewardAccountToBuffer(rewardAccount, networkId, reward_account_buf);
    return format_address_human_readable(reward_account_buf, REWARD_ACCOUNT_LENGTH, out, outSize);
}

/*
 * Apart from parsing, we validate that the input contains nothing more than the params.
 *
 * The serialization format:
 *
 * address type 1B
 * if address type == BYRON
 *     protocol magic 4B
 * else
 *     network id 1B
 * payment part:
 *     for PAYMENT_PART_KEY_PATH:
 *         payment public key derivation path (1B for length + [0-10] x 4B)
 *     for PAYMENT_PART_SCRIPT_HASH:
 *         payment script hash 28B
 *     for PAYMENT_PART_NONE:
 *         nothing
 * staking part type 1B
 *     if STAKING_PART_NONE:
 *         nothing more
 *     if STAKING_PART_KEY_PATH:
 *         staking public key derivation path (1B for length + [0-10] x 4B)
 *     if STAKING_PART_KEY_HASH:
 *         stake key hash 28B
 *     if STAKING_PART_BLOCKCHAIN_POINTER:
 *         certificate blockchain pointer 3 x 4B
 *
 * (see also enums in addressUtilsShelley.h)
 */
bool buffer_read_address_params(buffer_t* buffer, address_params_t* params) {
    explicit_bzero(params, SIZEOF(*params));

    // address type
    uint8_t addressType = 0;
    if (!buffer_read_u8(buffer, &addressType)) {
        return false;
    }
    params->type = addressType;
    TRACE("Address type: 0x%x", params->type);
    if (!isSupportedAddressType(params->type)) {
        return false;
    }

    // protocol magic / network id
    if (params->type == BYRON) {
        uint32_t protocolMagic = 0;
        if (!buffer_read_u32(buffer, &protocolMagic, BE)) {
            return false;
        }
        params->protocolMagic = protocolMagic;
        TRACE("Protocol magic: 0x%x", params->protocolMagic);
    } else {
        uint8_t networkId = 0;
        if (!buffer_read_u8(buffer, &networkId)) {
            return false;
        }
        params->networkId = networkId;
        TRACE("Network id: 0x%x", params->networkId);
        if (!isValidNetworkId(params->networkId)) {
            return false;
        }
    }

    // payment part
    switch (params->type) {
        case BASE_PAYMENT_KEY_STAKE_KEY:
        case BASE_PAYMENT_KEY_STAKE_SCRIPT:
        case POINTER_KEY:
        case ENTERPRISE_KEY:
        case BYRON: {
            params->paymentPartType = PAYMENT_PART_KEY_PATH;
            if (!buffer_read_bip44_path(buffer, &params->paymentKeyPath)) {
                return false;
            }
            BIP44_PRINTF(&params->paymentKeyPath);
            TRACE("");
            break;
        }

        case BASE_PAYMENT_SCRIPT_STAKE_KEY:
        case BASE_PAYMENT_SCRIPT_STAKE_SCRIPT:
        case POINTER_SCRIPT:
        case ENTERPRISE_SCRIPT: {
            params->paymentPartType = PAYMENT_PART_SCRIPT_HASH;
            if (!buffer_read_bytes_ptr(buffer, &params->paymentScriptHash, SCRIPT_HASH_LENGTH)) {
                return false;
            }
            ASSERT(params->paymentScriptHash != NULL);
            TRACE("Payment script hash: ");
            TRACE_BUFFER(params->paymentScriptHash, SCRIPT_HASH_LENGTH);
            break;
        }

        case REWARD_KEY:
        case REWARD_SCRIPT:
            // no payment info for reward address types
            params->paymentPartType = PAYMENT_PART_NONE;
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            break;
            // LCOV_EXCL_STOP
    }

    // staking part type
    uint8_t stakingChoice = 0;
    if (!buffer_read_u8(buffer, &stakingChoice)) {
        return false;
    }
    params->stakingPartType = stakingChoice;
    if (!is_valid_staking_part_type(params->stakingPartType)) {
        return false;
    }

    // staking part type determines what to parse next
    switch (params->stakingPartType) {
        case STAKING_PART_NONE:
            break;

        case STAKING_PART_KEY_PATH: {
            if (!buffer_read_bip44_path(buffer, &params->stakingKeyPath)) {
                return false;
            }
            BIP44_PRINTF(&params->stakingKeyPath);
            TRACE("");
            break;
        }

        case STAKING_PART_KEY_HASH: {
            if (!buffer_read_bytes_ptr(buffer, &params->stakingKeyHash, ADDRESS_KEY_HASH_LENGTH)) {
                return false;
            }
            ASSERT(params->stakingKeyHash != NULL);
            TRACE("Stake key hash: ");
            TRACE_BUFFER(params->stakingKeyHash, ADDRESS_KEY_HASH_LENGTH);
            break;
        }

        case STAKING_PART_SCRIPT_HASH: {
            if (!buffer_read_bytes_ptr(buffer, &params->stakingScriptHash, SCRIPT_HASH_LENGTH)) {
                return false;
            }
            ASSERT(params->stakingScriptHash != NULL);
            TRACE("Stake script hash: ");
            TRACE_BUFFER(params->stakingScriptHash, SCRIPT_HASH_LENGTH);
            break;
        }

        case STAKING_PART_BLOCKCHAIN_POINTER: {
            uint32_t blockIndex = 0, txIndex = 0, certIndex = 0;
            if (!buffer_read_u32(buffer, &blockIndex, BE)) {
                return false;
            }
            if (!buffer_read_u32(buffer, &txIndex, BE)) {
                return false;
            }
            if (!buffer_read_u32(buffer, &certIndex, BE)) {
                return false;
            }
            params->stakingKeyBlockchainPointer.blockIndex = blockIndex;
            params->stakingKeyBlockchainPointer.txIndex = txIndex;
            params->stakingKeyBlockchainPointer.certificateIndex = certIndex;
            TRACE("Stake key pointer: [%u, %u, %u]", blockIndex, txIndex, certIndex);
            break;
        }

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    return true;
}

static inline bool isValidStakingInfo(const address_params_t* params) {
#define CHECK(cond) \
    if (!(cond)) return false
    CHECK(is_staking_part_consistent_with_address_type(params));
    if (params->stakingPartType == STAKING_PART_KEY_PATH) {
        CHECK(bip44_classifyPath(&params->stakingKeyPath) == PATH_ORDINARY_STAKING_KEY);
    }
    if (params->stakingPartType == STAKING_PART_KEY_HASH) {
        CHECK(params->stakingKeyHash != NULL);
    }
    if (params->stakingPartType == STAKING_PART_SCRIPT_HASH) {
        CHECK(params->stakingScriptHash != NULL);
    }
    return true;
#undef CHECK
}

static inline bool isValidPaymentInfo(const address_params_t* params) {
#define CHECK(cond) \
    if (!(cond)) return false
    switch (params->type) {
        case BYRON:
            CHECK(params->paymentPartType == PAYMENT_PART_KEY_PATH);
            CHECK(bip44_classifyPath(&params->paymentKeyPath) == PATH_ORDINARY_PAYMENT_KEY);
            CHECK(bip44_hasByronPrefix(&params->paymentKeyPath));
            break;

        case BASE_PAYMENT_KEY_STAKE_KEY:
        case BASE_PAYMENT_KEY_STAKE_SCRIPT:
        case POINTER_KEY:
        case ENTERPRISE_KEY:
            CHECK(params->paymentPartType == PAYMENT_PART_KEY_PATH);
            CHECK(bip44_classifyPath(&params->paymentKeyPath) == PATH_ORDINARY_PAYMENT_KEY);
            CHECK(bip44_hasShelleyPrefix(&params->paymentKeyPath));
            break;

        case BASE_PAYMENT_SCRIPT_STAKE_KEY:
        case BASE_PAYMENT_SCRIPT_STAKE_SCRIPT:
        case POINTER_SCRIPT:
        case ENTERPRISE_SCRIPT:
            CHECK(params->paymentPartType == PAYMENT_PART_SCRIPT_HASH);
            CHECK(params->paymentScriptHash != NULL);
            break;

        case REWARD_KEY:
        case REWARD_SCRIPT:
            // no payment credential for reward address types
            CHECK(params->paymentPartType == PAYMENT_PART_NONE);
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            break;
            // LCOV_EXCL_STOP
    }
    return true;
#undef CHECK
}

bool isValidAddressParams(const address_params_t* params) {
#define CHECK(cond) \
    if (!(cond)) return false

    if (params->type != BYRON) {
        CHECK(isValidNetworkId(params->networkId));
    }

    CHECK(isValidStakingInfo(params));
    CHECK(isValidPaymentInfo(params));

    return true;
#undef CHECK
}

void address_params_copyHashesToStorage(address_params_t* params,
                                        address_params_hashes_storage_t* storage) {
    ASSERT(params != NULL);
    ASSERT(storage != NULL);

    // Copy payment script hash if present
    if (params->paymentPartType == PAYMENT_PART_SCRIPT_HASH) {
        ASSERT(params->paymentScriptHash != NULL);
        memmove(storage->paymentHash, params->paymentScriptHash, SCRIPT_HASH_LENGTH);
        params->paymentScriptHash = storage->paymentHash;
    }

    // Copy staking key/script hash if present
    switch (params->stakingPartType) {
        case STAKING_PART_KEY_HASH:
            ASSERT(params->stakingKeyHash != NULL);
            memmove(storage->stakingHash, params->stakingKeyHash, ADDRESS_KEY_HASH_LENGTH);
            params->stakingKeyHash = storage->stakingHash;
            break;
        case STAKING_PART_SCRIPT_HASH:
            ASSERT(params->stakingScriptHash != NULL);
            memmove(storage->stakingHash, params->stakingScriptHash, SCRIPT_HASH_LENGTH);
            params->stakingScriptHash = storage->stakingHash;
            break;
        default:
            // STAKING_PART_NONE, STAKING_PART_KEY_PATH, STAKING_PART_BLOCKCHAIN_POINTER: no hash to
            // copy
            break;
    }
}

payment_choice_t determinePaymentChoice(address_type_t addressType) {
    switch (addressType) {
        case BASE_PAYMENT_KEY_STAKE_KEY:
        case BASE_PAYMENT_KEY_STAKE_SCRIPT:
        case POINTER_KEY:
        case ENTERPRISE_KEY:
        case BYRON:
            return PAYMENT_PATH;

        case BASE_PAYMENT_SCRIPT_STAKE_KEY:
        case BASE_PAYMENT_SCRIPT_STAKE_SCRIPT:
        case POINTER_SCRIPT:
        case ENTERPRISE_SCRIPT:
            return PAYMENT_SCRIPT_HASH;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            __attribute__((fallthrough));
        // LCOV_EXCL_STOP
        case REWARD_KEY:
        case REWARD_SCRIPT:
            return PAYMENT_NONE;
    }
}

payment_part_type_t addressParams_getPaymentPartType(const address_params_t* address_params) {
    ASSERT(address_params != NULL);
    return address_params->paymentPartType;
}

staking_part_type_t addressParams_getStakingPartType(const address_params_t* address_params) {
    ASSERT(address_params != NULL);
    return address_params->stakingPartType;
}

void poolRewardAccountToBuffer(const pool_reward_account_t* rewardAccount,
                               uint8_t networkId,
                               uint8_t* rewardAccountBuffer) {
    switch (rewardAccount->keyReferenceType) {
        case KEY_REFERENCE_HASH: {
            ASSERT(rewardAccount->hashBuffer != NULL);
            memmove(rewardAccountBuffer, rewardAccount->hashBuffer, REWARD_ACCOUNT_LENGTH);
            break;
        }
        case KEY_REFERENCE_PATH: {
            constructRewardAddressFromKeyPath(&rewardAccount->path,
                                              networkId,
                                              rewardAccountBuffer,
                                              REWARD_ACCOUNT_LENGTH);
            break;
        }
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }
}
