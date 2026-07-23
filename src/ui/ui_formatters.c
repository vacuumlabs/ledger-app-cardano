/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "ui_formatters.h"
#include "tx.h"
#include "utils.h"
#include "textUtils.h"
#include "ipUtils.h"
#include "format.h"
#include "cardano_tokens.h"
#include "cardano_constants.h"
#include "bech32.h"
#include "cardano_buffer.h"
#include <stdio.h>
#include <string.h>

static const char *getCertificateTypeName(certificate_type_t type) {
    switch (type) {
        case CERTIFICATE_STAKE_REGISTRATION:
            return "Stake Registration";
        case CERTIFICATE_STAKE_DEREGISTRATION:
            return "Stake Deregistration";
        case CERTIFICATE_STAKE_DELEGATION:
            return "Stake Delegation";
        case CERTIFICATE_STAKE_POOL_RETIREMENT:
            return "Pool Retirement";
        case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
            return "Stake Registration (Conway)";
        case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY:
            return "Stake Deregistration (Conway)";
        case CERTIFICATE_VOTE_DELEGATION:
            return "Vote Delegation";
        case CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION:
            return "Pool and DRep Delegation";
        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL:
            return "Account Registration + Stake Pool Delegation";
        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP:
            return "Account Registration + DRep Delegation";
        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP:
            return "Account Registration + Pool and DRep Delegation";
        case CERTIFICATE_AUTHORIZE_COMMITTEE_HOT:
            return "Committee Authorization";
        case CERTIFICATE_RESIGN_COMMITTEE_COLD:
            return "Committee Resignation";
        case CERTIFICATE_DREP_REGISTRATION:
            return "DRep Registration";
        case CERTIFICATE_DREP_DEREGISTRATION:
            return "DRep Deregistration";
        case CERTIFICATE_DREP_UPDATE:
            return "DRep Update";
        case CERTIFICATE_STAKE_POOL_REGISTRATION:
            return "Pool Registration";
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown certificate type");
            return "Unknown";
            // LCOV_EXCL_STOP
    }
}

/**
 * Format bytes to lowercase hex string (UI version with bool return)
 */
bool format_hex_bytes(const uint8_t *bytes, size_t bytes_len, char *out, size_t outSize) {
    return bytes_to_lowercase_hex(out, outSize, bytes, bytes_len) == 0;
}

/**
 * Format uint64_t value to string (UI version with correct parameter order)
 */
bool format_uint64(uint64_t value, char *out, size_t outSize) {
    return format_u64(out, outSize, value);
}

bool format_decimal_amount(uint64_t amount, size_t places, char *out, size_t outSize) {
    LEDGER_ASSERT(outSize < BUFFER_SIZE_PARANOIA, "Output buffer size exceeds paranoia limit");
    LEDGER_ASSERT(places <= UINT8_MAX, "Decimal places exceed maximum value");

    char scratchBuffer[40] = {0};
    buffer_t scratch_buf = buffer_create(scratchBuffer, SIZEOF(scratchBuffer));

    // We print in reverse
    // decimal digits
    for (size_t dec = 0; dec < places; dec++) {
        if (!buffer_write_u8(&scratch_buf, (uint8_t) ('0' + (amount % 10)))) {
            return false;  // LCOV_EXCL_LINE
        }
        amount /= 10;
    }
    if (places > 0) {
        if (!buffer_write_u8(&scratch_buf, (uint8_t) '.')) {
            return false;  // LCOV_EXCL_LINE
        }
    }
    // We want at least one iteration
    int place = 0;
    do {
        // thousands separator
        if (place && (place % 3 == 0)) {
            if (!buffer_write_u8(&scratch_buf, (uint8_t) ',')) {
                return false;  // LCOV_EXCL_LINE
            }
        }
        if (!buffer_write_u8(&scratch_buf, (uint8_t) ('0' + (amount % 10)))) {
            return false;  // LCOV_EXCL_LINE
        }
        amount /= 10;
        place++;
    } while (amount > 0);

    // Size without terminating character
    size_t rawSize = scratch_buf.offset;
    if (rawSize + 1 > outSize) {
        return false;
    }

    // Copy reversed & append terminator
    explicit_bzero(out, outSize);
    buffer_t out_buf = buffer_create(out, outSize);
    for (size_t i = 0; i < rawSize; i++) {
        if (!buffer_write_u8(&out_buf, (uint8_t) scratchBuffer[rawSize - 1 - i])) {
            return false;  // LCOV_EXCL_LINE
        }
    }
    if (!buffer_write_u8(&out_buf, 0)) {
        return false;  // LCOV_EXCL_LINE
    }

    // make sure all the information is displayed to the user
    LEDGER_ASSERT(strlen(out) == rawSize, "Formatted string length mismatch");

    return true;
}

bool format_ada_amount(uint64_t amount, char *out, size_t outSize) {
    LEDGER_ASSERT(outSize < BUFFER_SIZE_PARANOIA, "Output buffer size exceeds paranoia limit");

    explicit_bzero(out, outSize);

    bool formatted = format_decimal_amount(amount, 6, out, outSize);
    LEDGER_ASSERT(formatted, "Decimal amount formatting failed");
    const size_t rawSize = strlen(out);

    const char *suffix = " ADA";
    const size_t suffixLength = strlen(suffix);

    // make sure all the information is displayed to the user
    LEDGER_ASSERT(rawSize + suffixLength + 1 < outSize, "ADA suffix does not fit in output buffer");

    int written = snprintf(out + rawSize, outSize - rawSize, "%s", suffix);
    LEDGER_ASSERT(written > 0, "snprintf ADA suffix failed");
    LEDGER_ASSERT((size_t) written < (outSize - rawSize), "snprintf ADA suffix truncated");
    LEDGER_ASSERT((size_t) written == suffixLength, "ADA suffix length mismatch");

    return true;
}

// Note: This is valid only for mainnet
static struct {
    uint64_t startSlotNumber;
    uint64_t startEpoch;
    uint64_t slotsInEpoch;
    // Must remain sorted by descending startSlotNumber.
} EPOCH_SLOTS_CONFIG[] = {{4492800, 208, 432000}, {0, 0, 21600}};

static bool format_validity_boundary_mainnet(uint64_t slotNumber, char *out, size_t outSize) {
    LEDGER_ASSERT(outSize < BUFFER_SIZE_PARANOIA, "Output buffer size exceeds paranoia limit");

    explicit_bzero(out, outSize);

    unsigned i = 0;
    while (slotNumber < EPOCH_SLOTS_CONFIG[i].startSlotNumber) {
        i++;
        LEDGER_ASSERT(i < ARRAY_LEN(EPOCH_SLOTS_CONFIG),
                      "Slot number exceeds configured epoch boundaries");
    }

    // Intentional redundant post-condition check: keeps this invariant explicit for auditability.
    LEDGER_ASSERT(slotNumber >= EPOCH_SLOTS_CONFIG[i].startSlotNumber,
                  "Invalid slot number for epoch");

    uint64_t startSlotNumber = EPOCH_SLOTS_CONFIG[i].startSlotNumber;
    uint64_t startEpoch = EPOCH_SLOTS_CONFIG[i].startEpoch;
    uint64_t slotsInEpoch = EPOCH_SLOTS_CONFIG[i].slotsInEpoch;

    uint64_t epoch = startEpoch + (slotNumber - startSlotNumber) / slotsInEpoch;
    uint64_t slotInEpoch = (slotNumber - startSlotNumber) % slotsInEpoch;

    STATIC_ASSERT(sizeof(int) >= sizeof(uint32_t), "wrong int size");

    LEDGER_ASSERT(outSize > 0,
                  "Output buffer must not be empty");  // so we can write null terminator
    int written;
    if (epoch > 1000000) {
        // thousands of years
        written = snprintf(out, outSize, "epoch > 1000000");
    } else {
        // Safe: epoch and slotInEpoch are uint64_t but guaranteed < 1000000 by check above
        written =
            snprintf(out, outSize, "epoch %u / slot %u", (unsigned) epoch, (unsigned) slotInEpoch);
    }

    LEDGER_ASSERT(written > 0, "snprintf epoch/slot formatting failed");
    LEDGER_ASSERT((size_t) written + 1 < outSize,
                  "Epoch/slot string does not fit in output buffer");

    return true;
}

bool format_validity_boundary(uint64_t slotNumber,
                              uint8_t networkId,
                              uint32_t protocolMagic,
                              char *out,
                              size_t outSize) {
    LEDGER_ASSERT(outSize < BUFFER_SIZE_PARANOIA, "Output buffer size exceeds paranoia limit");

    explicit_bzero(out, outSize);

    // Determine if we can use the nicer mainnet formatting
    // Note: Epoch/slot calculations are valid only for mainnet,
    // as they depend on network params that could differ for testnets
    if ((networkId == MAINNET_NETWORK_ID) && (protocolMagic == MAINNET_PROTOCOL_MAGIC)) {
        // Use pretty formatting for mainnet (epoch / slot)
        return format_validity_boundary_mainnet(slotNumber, out, outSize);
    }

    // Use simple uint64 formatting for non-mainnet
    bool success = format_u64(out, outSize, slotNumber);
    LEDGER_ASSERT(success, "uint64 formatting failed");
    size_t len = strlen(out);
    LEDGER_ASSERT(len + 1 < outSize, "Formatted slot number does not fit in output buffer");
    return true;
}

/**
 * Format pool profit margin as percentage
 */
bool format_pool_margin(uint64_t numerator, uint64_t denominator, char *out, size_t outSize) {
    LEDGER_ASSERT(outSize < BUFFER_SIZE_PARANOIA, "Output buffer size exceeds paranoia limit");
    LEDGER_ASSERT(denominator > 0, "Pool margin denominator is zero");
    LEDGER_ASSERT(numerator <= UINT64_MAX / 10000, "Pool margin numerator overflow");

    // Convert to percentage (0-10000 basis points), rounded to nearest basis point.
    uint64_t margin_percentage_basis_points = (10000 * numerator + (denominator / 2)) / denominator;
    uint64_t integer_part = margin_percentage_basis_points / 100;
    uint64_t fractional_part = margin_percentage_basis_points % 100;

    STATIC_ASSERT(sizeof(unsigned long long) >= sizeof(uint64_t), "unsigned long long too small");
    int written = snprintf(out,
                           outSize,
                           "%llu.%02llu %%",
                           (unsigned long long) integer_part,
                           (unsigned long long) fractional_part);
    LEDGER_ASSERT(written > 0, "snprintf pool margin formatting failed");
    LEDGER_ASSERT((size_t) written + 1 < outSize,
                  "Pool margin string does not fit in output buffer");
    return true;
}

/**
 * Format 16-bit unsigned integer to string
 */
bool format_uint16(uint16_t value, char *out, size_t outSize) {
    STATIC_ASSERT(!IS_SIGNED_TYPE(typeof(value)), "signed type for %u");
    int written = snprintf(out, outSize, "%u", value);
    LEDGER_ASSERT(written > 0, "snprintf uint16 formatting failed");
    LEDGER_ASSERT((size_t) written + 1 < outSize, "uint16 string does not fit in output buffer");
    return true;
}

/**
 * Format unsigned integer with "#" prefix for numbered items
 */
bool format_index_with_prefix(uint32_t value, char *out, size_t outSize) {
    STATIC_ASSERT(!IS_SIGNED_TYPE(typeof(value)), "signed type for %u");
    int written = snprintf(out, outSize, "#%u", value);
    LEDGER_ASSERT(written > 0, "snprintf index prefix formatting failed");
    LEDGER_ASSERT((size_t) written + 1 < outSize,
                  "Index prefix string does not fit in output buffer");
    return true;
}

/**
 * Format IPv4 address from byte array
 */
bool format_ipv4(const ipv4_t *ipv4, char *out, size_t outSize) {
    LEDGER_ASSERT(outSize < BUFFER_SIZE_PARANOIA, "Output buffer size exceeds paranoia limit");
    ASSERT(out != NULL);
    ASSERT(ipv4 != NULL);

    explicit_bzero(out, outSize);

    if (ipv4->isNull) {
        int written = snprintf(out, outSize, "(none)");
        LEDGER_ASSERT(written > 0, "snprintf ipv4 null formatting failed");
        LEDGER_ASSERT((size_t) written + 1 < outSize,
                      "IPv4 null string does not fit in output buffer");
    } else {
        ASSERT(ipv4->ip != NULL);
        inet_ntop4(ipv4->ip, out, outSize);
    }

    // make sure all the information is displayed to the user
    LEDGER_ASSERT(strlen(out) + 1 < outSize,
                  "Formatted IPv4 address does not fit in output buffer");

    return true;
}

/**
 * Format IPv6 address from byte array
 */
bool format_ipv6(const ipv6_t *ipv6, char *out, size_t outSize) {
    LEDGER_ASSERT(outSize < BUFFER_SIZE_PARANOIA, "Output buffer size exceeds paranoia limit");
    ASSERT(out != NULL);
    ASSERT(ipv6 != NULL);

    explicit_bzero(out, outSize);

    if (ipv6->isNull) {
        int written = snprintf(out, outSize, "(none)");
        LEDGER_ASSERT(written > 0, "snprintf ipv6 null formatting failed");
        LEDGER_ASSERT((size_t) written + 1 < outSize,
                      "IPv6 null string does not fit in output buffer");
    } else {
        ASSERT(ipv6->ip != NULL);
        inet_ntop6(ipv6->ip, out, outSize);
    }

    // make sure all the information is displayed to the user
    LEDGER_ASSERT(strlen(out) + 1 < outSize,
                  "Formatted IPv6 address does not fit in output buffer");

    return true;
}

/**
 * Format vote option enum to string
 */
bool format_vote_option(vote_t voteOption, char *out, size_t outSize) {
    const char *vote_str;
    switch (voteOption) {
        case VOTE_NO:
            vote_str = "No";
            break;
        case VOTE_YES:
            vote_str = "Yes";
            break;
        case VOTE_ABSTAIN:
            vote_str = "Abstain";
            break;
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown vote option");
            return false;
            // LCOV_EXCL_STOP
    }

    int written = snprintf(out, outSize, "%s", vote_str);
    LEDGER_ASSERT(written > 0, "snprintf vote option formatting failed");
    LEDGER_ASSERT((size_t) written + 1 < outSize,
                  "Vote option string does not fit in output buffer");
    return true;
}

/**
 * Format constant DRep values (Abstain and No Confidence)
 *
 * These are special DRep types that represent predefined voting choices,
 * not derived from key paths or hashes.
 */
bool format_constant_drep(ext_drep_type_t drep_type, char *out, size_t outSize) {
    const char *drep_str;
    switch (drep_type) {
        case EXT_DREP_ABSTAIN:
            drep_str = "Abstain";
            break;
        case EXT_DREP_NO_CONFIDENCE:
            drep_str = "No Confidence";
            break;
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Only abstain and no confidence are constant DRep types");
            return false;
            // LCOV_EXCL_STOP
    }

    int written = snprintf(out, outSize, "%s", drep_str);
    LEDGER_ASSERT(written > 0, "snprintf drep formatting failed");
    LEDGER_ASSERT((size_t) written + 1 < outSize, "DRep string does not fit in output buffer");
    return true;
}

/**
 * Format certificate type enum to string
 */
bool format_certificate_type(certificate_type_t type, char *out, size_t outSize) {
    const char *cert_type_name = getCertificateTypeName(type);
    int written = snprintf(out, outSize, "%s", cert_type_name);
    LEDGER_ASSERT(written > 0, "snprintf certificate type formatting failed");
    LEDGER_ASSERT((size_t) written + 1 < outSize,
                  "Certificate type string does not fit in output buffer");
    return true;
}

/**
 * Format URL from raw buffer
 *
 * Copies URL bytes and null-terminates them.
 */
bool format_url(const uint8_t *url, size_t urlLength, char *out, size_t outSize) {
    if (urlLength + 1 >= outSize) {
        return false;
    }
    STATIC_ASSERT(MAX_ANCHOR_URL_LENGTH == MAX_POOL_METADATA_URL_LENGTH,
                  "URL length limits must match");
    LEDGER_ASSERT(urlLength <= MAX_ANCHOR_URL_LENGTH, "URL length exceeds maximum limit");
    LEDGER_ASSERT(str_isPrintableAsciiWithoutSpaces(url, urlLength),
                  "URL contains non-printable or space characters");
    memcpy(out, url, urlLength);
    out[urlLength] = '\0';
    return true;
}

bool format_dns_name(const uint8_t *dnsName, size_t dnsLength, char *out, size_t outSize) {
    if (dnsLength + 1 >= outSize) {
        return false;
    }
    LEDGER_ASSERT(dnsLength <= MAX_DNS_NAME_LENGTH, "DNS name length exceeds maximum limit");
    LEDGER_ASSERT(str_isUnambiguousAscii(dnsName, dnsLength),
                  "DNS name contains invalid ASCII characters");
    memcpy(out, dnsName, dnsLength);
    out[dnsLength] = '\0';
    return true;
}

/**
 * Format asset fingerprint in bech32 format
 */
bool format_asset_fingerprint_bech32(const uint8_t *policyId,
                                     const uint8_t *assetName,
                                     size_t assetNameLen,
                                     char *out,
                                     size_t outSize) {
    // Derive fingerprint bytes from policy ID and asset name
    uint8_t fingerprintBuffer[20];  // ASSET_FINGERPRINT_SIZE = 20
    deriveAssetFingerprintBytes(policyId,
                                MINTING_POLICY_ID_LENGTH,
                                assetName,
                                assetNameLen,
                                fingerprintBuffer,
                                sizeof(fingerprintBuffer));

    return format_bech32(BECH32_PREFIX_ASSET_FINGERPRINT,
                         fingerprintBuffer,
                         sizeof(fingerprintBuffer),
                         out,
                         outSize);
}

/**
 * Format inline datum or reference script with size and preview
 * Formats as "deadbeefaf... (XXXX bytes)" where first 6 bytes show as hex.
 */
bool format_input_with_index(const tx_input_t *input, char *out, size_t outSize) {
    ASSERT(input != NULL);
    ASSERT(out != NULL);
    int hex_status = bytes_to_lowercase_hex(out, outSize, input->txHash, TX_HASH_LENGTH);
    if (hex_status != 0) {
        return false;
    }
    size_t hash_len = strlen(out);
    if (hash_len + 1 >= outSize) {
        return false;
    }
    STATIC_ASSERT(!IS_SIGNED_TYPE(typeof(input->index)), "signed type for %u");
    int written = snprintf(out + hash_len, outSize - hash_len, " / %u", input->index);
    LEDGER_ASSERT(written > 0, "snprintf input index formatting failed");
    LEDGER_ASSERT((size_t) written + hash_len + 1 < outSize, "Input display buffer overflow");
    return true;
}

bool format_mint_summary(uint16_t num_groups, char *out, size_t outSize) {
    STATIC_ASSERT(!IS_SIGNED_TYPE(typeof(num_groups)), "signed type for %u");
    int written =
        snprintf(out, outSize, "%u asset group%s", num_groups, (num_groups == 1) ? "" : "s");
    LEDGER_ASSERT(written > 0, "snprintf mint summary formatting failed");
    LEDGER_ASSERT((size_t) written + 1 < outSize,
                  "Mint summary string does not fit in output buffer");
    return true;
}

bool format_incomplete_hex_with_length(const uint8_t *data,
                                       size_t dataLen,
                                       char *out,
                                       size_t outSize) {
    ASSERT(data != NULL);
    ASSERT(out != NULL);
    LEDGER_ASSERT(outSize > 0, "Zero output size");

    enum {
        PREVIEW_BYTES = 6,
        HEX_PREFIX_SIZE = (PREVIEW_BYTES * 2) + 1,  // 12 hex chars + null
    };
    size_t previewLen = (dataLen < PREVIEW_BYTES) ? dataLen : PREVIEW_BYTES;

    char hexPrefix[HEX_PREFIX_SIZE];
    int hexStatus = bytes_to_lowercase_hex(hexPrefix, sizeof(hexPrefix), data, previewLen);
    if (hexStatus != 0) {
        return false;  // LCOV_EXCL_LINE
    }

    STATIC_ASSERT(!IS_SIGNED_TYPE(typeof(dataLen)), "signed type for %u");
    int written = snprintf(out, outSize, "%s... (%u bytes)", hexPrefix, (unsigned int) dataLen);
    LEDGER_ASSERT(written > 0, "snprintf incomplete hex formatting failed");
    LEDGER_ASSERT((size_t) written + 1 < outSize,
                  "Incomplete hex string does not fit in output buffer");
    return true;
}

/**
 * Format a governance identifier (CIP-0129)
 *
 * Prepends the header byte (key type + credential type) to the credential hash
 * and encodes the result as bech32.
 */
bool format_governance_identifier(const char *bech32Prefix,
                                  uint8_t headerByte,
                                  const uint8_t *credentialHash,
                                  size_t credentialHashSize,
                                  char *out,
                                  size_t outSize) {
    ASSERT(bech32Prefix != NULL);
    ASSERT(credentialHash != NULL);

    uint8_t credentialType = headerByte & 0x0F;
    switch (credentialType) {
        case GOVERNANCE_ID_CREDENTIAL_KEY_HASH:
            ASSERT(credentialHashSize == ADDRESS_KEY_HASH_LENGTH);
            break;
        case GOVERNANCE_ID_CREDENTIAL_SCRIPT_HASH:
            ASSERT(credentialHashSize == SCRIPT_HASH_LENGTH);
            break;
        default:
            LEDGER_ASSERT(false, "invalid governance credential type");
    }

    uint8_t identifierBytes[GOVERNANCE_ID_LENGTH];
    identifierBytes[0] = headerByte;
    LEDGER_ASSERT(credentialHashSize + 1 <= sizeof(identifierBytes),
                  "credential hash does not fit in identifier buffer");
    memcpy(identifierBytes + 1, credentialHash, credentialHashSize);
    return format_bech32(bech32Prefix, identifierBytes, sizeof(identifierBytes), out, outSize);
}

bool format_governance_action_id(const uint8_t *txHash,
                                 uint32_t govActionIndex,
                                 char *out,
                                 size_t outSize) {
    ASSERT(txHash != NULL);
    ASSERT(govActionIndex <= UINT8_MAX);
    uint8_t idBytes[GOVERNANCE_ACTION_ID_LENGTH];
    memcpy(idBytes, txHash, TX_HASH_LENGTH);
    idBytes[TX_HASH_LENGTH] = (uint8_t) govActionIndex;
    return format_bech32(BECH32_PREFIX_GOV_ACTION,
                         idBytes,
                         GOVERNANCE_ACTION_ID_LENGTH,
                         out,
                         outSize);
}
