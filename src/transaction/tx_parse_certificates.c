/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "buffer.h"
#include "lists.h"

#include "os.h"

#include "cardano_swo.h"
#include "assert.h"
#include "utils.h"
#include "textUtils.h"
#include "ui_formatters.h"
#include "tx_parse_certificates.h"
#include "tx.h"
#include "cardano_parsers.h"

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_TX_PARSE to trace this module's parsing details.
 */
#ifdef TRACE_TX_PARSE
#define TRACE_MODULE(...) TRACE("[tx_parse_certs] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif

/// Parse CERTIFICATE_STAKE_REGISTRATION or CERTIFICATE_STAKE_DEREGISTRATION
bool parse_certificate_stake_registration_deregistration(buffer_t *buf,
                                                         certificate_type_t cert_type,
                                                         certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);
    LEDGER_ASSERT(cert_type == CERTIFICATE_STAKE_REGISTRATION ||
                      cert_type == CERTIFICATE_STAKE_DEREGISTRATION,
                  "Invalid certificate type for stake registration/deregistration");

    cert_data->type = cert_type;
    if (!buffer_read_credential(buf, &cert_data->stakeCredential)) {
        TRACE("Failed to read stake credential");
        return false;
    }
    TRACE_MODULE("stakeCredential.type=%u", cert_data->stakeCredential.type);
    return true;
}

/// Parse CERTIFICATE_STAKE_DELEGATION
bool parse_certificate_stake_delegation(buffer_t *buf, certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);
    cert_data->type = CERTIFICATE_STAKE_DELEGATION;

    if (!buffer_read_credential(buf, &cert_data->stakeCredential)) {
        TRACE("Failed to read stake credential");
        return false;
    }
    TRACE_MODULE("stakeCredential.type=%u", cert_data->stakeCredential.type);

    if (!buffer_read_bytes_ptr(buf, &cert_data->poolKeyHash, POOL_KEY_HASH_LENGTH)) {
        TRACE("Failed to read pool key hash");
        return false;
    }
    ASSERT(cert_data->poolKeyHash != NULL);
    return true;
}

/// Parse CERTIFICATE_STAKE_REGISTRATION_CONWAY or CERTIFICATE_STAKE_DEREGISTRATION_CONWAY
bool parse_certificate_stake_registration_deregistration_conway(buffer_t *buf,
                                                                certificate_type_t cert_type,
                                                                certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);
    LEDGER_ASSERT(cert_type == CERTIFICATE_STAKE_REGISTRATION_CONWAY ||
                      cert_type == CERTIFICATE_STAKE_DEREGISTRATION_CONWAY,
                  "Invalid certificate type for Conway stake registration/deregistration");

    cert_data->type = cert_type;

    if (!buffer_read_credential(buf, &cert_data->stakeCredential)) {
        TRACE("Failed to read stake credential");
        return false;
    }
    TRACE_MODULE("stakeCredential.type=%u", cert_data->stakeCredential.type);

    ASSERT_TYPE(cert_data->deposit, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->deposit, BE)) {
        TRACE("Failed to read deposit");
        return false;
    }
    if (cert_data->deposit >= LOVELACE_MAX_SUPPLY) {
        TRACE("Deposit too large: %llu", (unsigned long long) cert_data->deposit);
        return false;
    }
    TRACE_MODULE("deposit=%llu", (unsigned long long) cert_data->deposit);
    return true;
}

/// Parse CERTIFICATE_STAKE_POOL_RETIREMENT
bool parse_certificate_stake_pool_retirement(buffer_t *buf, certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);
    cert_data->type = CERTIFICATE_STAKE_POOL_RETIREMENT;

    if (!buffer_read_credential(buf, &cert_data->poolCredential)) {
        TRACE("Failed to read pool credential");
        return false;
    }
    TRACE_MODULE("poolCredential.type=%u", cert_data->poolCredential.type);

    ASSERT_TYPE(cert_data->retirementEpoch, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->retirementEpoch, BE)) {
        TRACE("Failed to read retirement epoch");
        return false;
    }
    TRACE_MODULE("retirementEpoch=%llu", (unsigned long long) cert_data->retirementEpoch);
    return true;
}

/// Parse CERTIFICATE_VOTE_DELEGATION
bool parse_certificate_vote_delegation(buffer_t *buf, certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);
    cert_data->type = CERTIFICATE_VOTE_DELEGATION;

    if (!buffer_read_credential(buf, &cert_data->stakeCredential)) {
        TRACE("Failed to read stake credential");
        return false;
    }
    TRACE_MODULE("stakeCredential.type=%u", cert_data->stakeCredential.type);

    if (!buffer_read_drep(buf, &cert_data->drep)) {
        TRACE("Failed to read drep");
        return false;
    }
    TRACE_MODULE("drep.type=%u", cert_data->drep.type);
    return true;
}

/// Parse CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION
bool parse_certificate_stake_pool_and_drep_delegation(buffer_t *buf,
                                                      certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);
    cert_data->type = CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION;

    if (!buffer_read_credential(buf, &cert_data->stakeCredential)) {
        TRACE("Failed to read stake credential");
        return false;
    }
    TRACE_MODULE("stakeCredential.type=%u", cert_data->stakeCredential.type);

    if (!buffer_read_bytes_ptr(buf, &cert_data->combinedDelegPoolKeyHash, POOL_KEY_HASH_LENGTH)) {
        TRACE("Failed to read combined pool key hash");
        return false;
    }
    ASSERT(cert_data->combinedDelegPoolKeyHash != NULL);

    if (!buffer_read_drep(buf, &cert_data->drep)) {
        TRACE("Failed to read drep");
        return false;
    }
    TRACE_MODULE("drep.type=%u", cert_data->drep.type);
    return true;
}

/// Parse CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL
bool parse_certificate_account_registration_delegation_to_stake_pool(
    buffer_t *buf,
    certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);
    cert_data->type = CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL;

    if (!buffer_read_credential(buf, &cert_data->stakeCredential)) {
        TRACE("Failed to read stake credential");
        return false;
    }
    TRACE_MODULE("stakeCredential.type=%u", cert_data->stakeCredential.type);

    if (!buffer_read_bytes_ptr(buf, &cert_data->combinedDelegPoolKeyHash, POOL_KEY_HASH_LENGTH)) {
        TRACE("Failed to read combined pool key hash");
        return false;
    }
    ASSERT(cert_data->combinedDelegPoolKeyHash != NULL);

    ASSERT_TYPE(cert_data->deposit, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->deposit, BE)) {
        TRACE("Failed to read deposit");
        return false;
    }
    if (cert_data->deposit >= LOVELACE_MAX_SUPPLY) {
        TRACE("Deposit too large: %llu", (unsigned long long) cert_data->deposit);
        return false;
    }
    TRACE_MODULE("deposit=%llu", (unsigned long long) cert_data->deposit);
    return true;
}

/// Parse CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP
bool parse_certificate_account_registration_delegation_to_drep(buffer_t *buf,
                                                               certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);
    cert_data->type = CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP;

    if (!buffer_read_credential(buf, &cert_data->stakeCredential)) {
        TRACE("Failed to read stake credential");
        return false;
    }
    TRACE_MODULE("stakeCredential.type=%u", cert_data->stakeCredential.type);

    if (!buffer_read_drep(buf, &cert_data->drep)) {
        TRACE("Failed to read drep");
        return false;
    }
    TRACE_MODULE("drep.type=%u", cert_data->drep.type);

    ASSERT_TYPE(cert_data->deposit, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->deposit, BE)) {
        TRACE("Failed to read deposit");
        return false;
    }
    if (cert_data->deposit >= LOVELACE_MAX_SUPPLY) {
        TRACE("Deposit too large: %llu", (unsigned long long) cert_data->deposit);
        return false;
    }
    TRACE_MODULE("deposit=%llu", (unsigned long long) cert_data->deposit);
    return true;
}

/// Parse CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP
bool parse_certificate_account_registration_delegation_to_stake_pool_and_drep(
    buffer_t *buf,
    certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);
    cert_data->type = CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP;

    if (!buffer_read_credential(buf, &cert_data->stakeCredential)) {
        TRACE("Failed to read stake credential");
        return false;
    }
    TRACE_MODULE("stakeCredential.type=%u", cert_data->stakeCredential.type);

    if (!buffer_read_bytes_ptr(buf, &cert_data->combinedDelegPoolKeyHash, POOL_KEY_HASH_LENGTH)) {
        TRACE("Failed to read combined pool key hash");
        return false;
    }
    ASSERT(cert_data->combinedDelegPoolKeyHash != NULL);

    if (!buffer_read_drep(buf, &cert_data->drep)) {
        TRACE("Failed to read drep");
        return false;
    }
    TRACE_MODULE("drep.type=%u", cert_data->drep.type);

    ASSERT_TYPE(cert_data->deposit, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->deposit, BE)) {
        TRACE("Failed to read deposit");
        return false;
    }
    if (cert_data->deposit >= LOVELACE_MAX_SUPPLY) {
        TRACE("Deposit too large: %llu", (unsigned long long) cert_data->deposit);
        return false;
    }
    TRACE_MODULE("deposit=%llu", (unsigned long long) cert_data->deposit);
    return true;
}

/// Parse CERTIFICATE_AUTHORIZE_COMMITTEE_HOT
bool parse_certificate_authorize_committee_hot(buffer_t *buf, certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);
    cert_data->type = CERTIFICATE_AUTHORIZE_COMMITTEE_HOT;

    if (!buffer_read_credential(buf, &cert_data->coldCredential)) {
        TRACE("Failed to read cold credential");
        return false;
    }
    TRACE_MODULE("coldCredential.type=%u", cert_data->coldCredential.type);

    if (!buffer_read_credential(buf, &cert_data->hotCredential)) {
        TRACE("Failed to read hot credential");
        return false;
    }
    TRACE_MODULE("hotCredential.type=%u", cert_data->hotCredential.type);
    return true;
}

/// Parse CERTIFICATE_RESIGN_COMMITTEE_COLD
bool parse_certificate_resign_committee_cold(buffer_t *buf, certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);
    cert_data->type = CERTIFICATE_RESIGN_COMMITTEE_COLD;

    if (!buffer_read_credential(buf, &cert_data->coldCredential)) {
        TRACE("Failed to read cold credential");
        return false;
    }
    TRACE_MODULE("coldCredential.type=%u", cert_data->coldCredential.type);

    if (!buffer_read_anchor(buf, &cert_data->anchor)) {
        TRACE("Failed to read anchor");
        return false;
    }
    TRACE_MODULE("anchor.isIncluded=%u", cert_data->anchor.isIncluded);
    return true;
}

/// Parse CERTIFICATE_DREP_REGISTRATION
bool parse_certificate_drep_registration(buffer_t *buf, certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);
    cert_data->type = CERTIFICATE_DREP_REGISTRATION;

    if (!buffer_read_credential(buf, &cert_data->dRepCredential)) {
        TRACE("Failed to read drep credential");
        return false;
    }
    TRACE_MODULE("dRepCredential.type=%u", cert_data->dRepCredential.type);

    ASSERT_TYPE(cert_data->deposit, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->deposit, BE)) {
        TRACE("Failed to read deposit");
        return false;
    }
    if (cert_data->deposit >= LOVELACE_MAX_SUPPLY) {
        TRACE("Deposit too large: %llu", (unsigned long long) cert_data->deposit);
        return false;
    }
    TRACE_MODULE("deposit=%llu", (unsigned long long) cert_data->deposit);

    if (!buffer_read_anchor(buf, &cert_data->anchor)) {
        TRACE("Failed to read anchor");
        return false;
    }
    TRACE_MODULE("anchor.isIncluded=%u", cert_data->anchor.isIncluded);
    return true;
}

/// Parse CERTIFICATE_DREP_DEREGISTRATION
bool parse_certificate_drep_deregistration(buffer_t *buf, certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);
    cert_data->type = CERTIFICATE_DREP_DEREGISTRATION;

    if (!buffer_read_credential(buf, &cert_data->dRepCredential)) {
        TRACE("Failed to read drep credential");
        return false;
    }
    TRACE_MODULE("dRepCredential.type=%u", cert_data->dRepCredential.type);

    ASSERT_TYPE(cert_data->deposit, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->deposit, BE)) {
        TRACE("Failed to read deposit");
        return false;
    }
    if (cert_data->deposit >= LOVELACE_MAX_SUPPLY) {
        TRACE("Deposit too large: %llu", (unsigned long long) cert_data->deposit);
        return false;
    }
    TRACE_MODULE("deposit=%llu", (unsigned long long) cert_data->deposit);
    return true;
}

/// Parse CERTIFICATE_DREP_UPDATE
bool parse_certificate_drep_update(buffer_t *buf, certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);
    cert_data->type = CERTIFICATE_DREP_UPDATE;

    if (!buffer_read_credential(buf, &cert_data->dRepCredential)) {
        TRACE("Failed to read drep credential");
        return false;
    }
    TRACE_MODULE("dRepCredential.type=%u", cert_data->dRepCredential.type);

    if (!buffer_read_anchor(buf, &cert_data->anchor)) {
        TRACE("Failed to read anchor");
        return false;
    }
    TRACE_MODULE("anchor.isIncluded=%u", cert_data->anchor.isIncluded);
    return true;
}

/// Helper to parse pool ID (operator key - hash or path)
static bool _parse_pool_id(buffer_t *buf, pool_id_t *pool_id) {
    ASSERT(buf != NULL);
    ASSERT(pool_id != NULL);

    uint8_t pool_id_type_wire;
    if (!buffer_read_u8(buf, &pool_id_type_wire)) {
        TRACE("Failed to read pool id type");
        return false;
    }
    TRACE_MODULE("pool_id_type_wire=0x%02x", pool_id_type_wire);

    switch (pool_id_type_wire) {
        case EXT_CREDENTIAL_KEY_HASH:
            pool_id->keyReferenceType = KEY_REFERENCE_HASH;
            if (!buffer_read_bytes_ptr(buf, &pool_id->hash, POOL_KEY_HASH_LENGTH)) {
                TRACE("Failed to read pool id hash");
                return false;
            }
            ASSERT(pool_id->hash != NULL);
            break;
        case EXT_CREDENTIAL_KEY_PATH:
            pool_id->keyReferenceType = KEY_REFERENCE_PATH;
            if (!buffer_read_bip44_path(buf, &pool_id->path)) {
                TRACE("Failed to read pool id path");
                return false;
            }
            break;
        default:
            TRACE("Unknown pool id type: 0x%02x", pool_id_type_wire);
            return false;
    }
    return true;
}

/// Parse a DNS name that is mandatory for the relay.
static bool _parse_required_relay_dns_name(buffer_t *buf,
                                           pool_relay_t *relay,
                                           const char *missing_dns_message MARK_UNUSED,
                                           const char *empty_dns_message MARK_UNUSED) {
    ASSERT(buf != NULL);
    ASSERT(relay != NULL);

    bool dns_included = false;
    if (!buffer_read_flag_included(buf, &dns_included)) {
        TRACE("Failed to read dns inclusion flag");
        return false;
    }
    if (!dns_included) {
        TRACE_MODULE("%s", missing_dns_message);
        return false;
    }

    uint8_t dns_length = 0;
    if (!buffer_read_u8(buf, &dns_length)) {
        TRACE("Failed to read dns name length");
        return false;
    }
    relay->dnsNameSize = dns_length;

    if (dns_length > MAX_DNS_NAME_LENGTH) {
        TRACE("DNS name too long: %u", (unsigned) dns_length);
        return false;
    }

    if (dns_length > 0) {
        if (!buffer_read_bytes_ptr(buf, &relay->dnsName, dns_length)) {
            TRACE("Failed to read dns name");
            return false;
        }
        ASSERT(relay->dnsName != NULL);
    } else {
        relay->dnsName = NULL;
    }

    if (relay->dnsNameSize == 0) {
        TRACE_MODULE("%s", empty_dns_message);
        return false;
    }
    if (!str_isUnambiguousAscii(relay->dnsName, relay->dnsNameSize)) {
        TRACE_MODULE("DNS name must be unambiguous ASCII");
        return false;
    }
    TRACE_MODULE("dns_len=%u", dns_length);
    return true;
}

/// Parse a single pool relay entry from the pool registration certificate.
/// The parser accepts three formats:
///   - single_host_addr (0): a port and at least one IP (IPv4 and/or IPv6)
///   - single_host_name (1): a port and a non-empty DNS name (A/AAAA host record)
///   - multi_host_name  (2): a non-empty DNS name only (SRV record); no port or IP
bool parse_pool_relay(buffer_t *buf, pool_relay_t *relay) {
    ASSERT(buf != NULL);
    ASSERT(relay != NULL);

    uint8_t relay_type;
    if (!buffer_read_u8(buf, &relay_type)) {
        TRACE("Failed to read relay type");
        return false;
    }
    TRACE_MODULE("relay_type=%u", relay_type);

    switch (relay_type) {
        case RELAY_SINGLE_HOST_IP: {
            // Address relay: optional port + optional IPv4/IPv6 on the wire. This app
            // additionally requires a port and at least one IP (enforced below).
            relay->format = RELAY_SINGLE_HOST_IP;
            relay->dnsName = NULL;
            relay->dnsNameSize = 0;

            bool port_included = false;
            if (!buffer_read_flag_included(buf, &port_included)) {
                TRACE("Failed to read port inclusion flag");
                return false;
            }
            relay->port.isNull = !port_included;
            if (port_included) {
                ASSERT_TYPE(relay->port.number, uint16_t);
                if (!buffer_read_u16(buf, &relay->port.number, BE)) {
                    TRACE("Failed to read port number");
                    return false;
                }
                TRACE_MODULE("port=%u", relay->port.number);
            }
            // A single-host-address relay is not useful without a port.
            if (relay->port.isNull) {
                TRACE_MODULE("Relay single host IP must have a port");
                return false;
            }

            bool ipv4_included = false;
            if (!buffer_read_flag_included(buf, &ipv4_included)) {
                TRACE("Failed to read ipv4 inclusion flag");
                return false;
            }
            relay->ipv4.isNull = !ipv4_included;
            if (ipv4_included) {
                if (!buffer_read_bytes_ptr(buf, &relay->ipv4.ip, IPV4_LENGTH)) {
                    TRACE("Failed to read ipv4");
                    return false;
                }
                ASSERT(relay->ipv4.ip != NULL);
                TRACE_MODULE("ipv4 present");
            }

            bool ipv6_included = false;
            if (!buffer_read_flag_included(buf, &ipv6_included)) {
                TRACE("Failed to read ipv6 inclusion flag");
                return false;
            }
            relay->ipv6.isNull = !ipv6_included;
            if (ipv6_included) {
                if (!buffer_read_bytes_ptr(buf, &relay->ipv6.ip, IPV6_LENGTH)) {
                    TRACE("Failed to read ipv6");
                    return false;
                }
                ASSERT(relay->ipv6.ip != NULL);
                TRACE_MODULE("ipv6 present");
            }
            // ...and it must carry at least one IP address (v4 and/or v6).
            if (relay->ipv4.isNull && relay->ipv6.isNull) {
                TRACE_MODULE("Relay single host IP must have at least one IP");
                return false;
            }
            break;
        }
        case RELAY_SINGLE_HOST_NAME: {
            // Named relay: optional port + a required DNS name; no IP addresses.
            relay->format = RELAY_SINGLE_HOST_NAME;
            relay->ipv4.isNull = true;
            relay->ipv4.ip = NULL;
            relay->ipv6.isNull = true;
            relay->ipv6.ip = NULL;

            bool port_included = false;
            if (!buffer_read_flag_included(buf, &port_included)) {
                TRACE("Failed to read port inclusion flag");
                return false;
            }
            relay->port.isNull = !port_included;
            if (port_included) {
                ASSERT_TYPE(relay->port.number, uint16_t);
                if (!buffer_read_u16(buf, &relay->port.number, BE)) {
                    TRACE("Failed to read port number");
                    return false;
                }
                TRACE_MODULE("port=%u", relay->port.number);
            }
            if (relay->port.isNull) {
                TRACE_MODULE("Relay single host name must have a port");
                return false;
            }

            if (!_parse_required_relay_dns_name(
                    buf,
                    relay,
                    "Relay single host name must have a DNS name",
                    "Relay single host name must have a non-empty DNS name")) {
                return false;
            }
            break;
        }
        case RELAY_MULTIPLE_HOST_NAME: {
            // SRV relay: a required DNS name only; no port or IP addresses.
            relay->format = RELAY_MULTIPLE_HOST_NAME;
            relay->port.isNull = true;
            relay->port.number = 0;
            relay->ipv4.isNull = true;
            relay->ipv4.ip = NULL;
            relay->ipv6.isNull = true;
            relay->ipv6.ip = NULL;

            if (!_parse_required_relay_dns_name(
                    buf,
                    relay,
                    "Relay multiple host name must have a DNS name",
                    "Relay multiple host name must have a non-empty DNS name")) {
                return false;
            }
            break;
        }
        default:
            TRACE("Unknown relay type: %u", (unsigned) relay_type);
            return false;
    }
    return true;
}

/// Parse pool metadata URL and hash (presence already known from pool registration header)
bool parse_pool_metadata(buffer_t *buf, pool_metadata_t *out_metadata) {
    ASSERT(buf != NULL);
    ASSERT(out_metadata != NULL);

    uint16_t url_length = 0;
    if (!buffer_read_u16(buf, &url_length, BE)) {
        TRACE("Failed to read metadata URL length");
        return false;
    }
    if (url_length > MAX_POOL_METADATA_URL_LENGTH) {
        TRACE("Invalid metadata URL length: %u", (unsigned) url_length);
        return false;
    }
    if (url_length > 0) {
        if (!buffer_read_bytes_ptr(buf, &out_metadata->url, url_length)) {
            TRACE("Failed to read metadata URL");
            return false;
        }
        ASSERT(out_metadata->url != NULL);
        if (!str_isPrintableAsciiWithoutSpaces(out_metadata->url, url_length)) {
            TRACE("Metadata URL contains non-printable or space characters");
            return false;
        }
    } else {
        out_metadata->url = NULL;
    }
    out_metadata->urlSize = url_length;

    if (!buffer_read_bytes_ptr(buf, &out_metadata->hash, POOL_METADATA_HASH_LENGTH)) {
        TRACE("Failed to read metadata hash");
        return false;
    }
    ASSERT(out_metadata->hash != NULL);
    TRACE_MODULE("metadata urlSize=%u", out_metadata->urlSize);
    return true;
}

/// Parse CERTIFICATE_STAKE_POOL_REGISTRATION
bool parse_certificate_stake_pool_registration(buffer_t *buf, certificate_data_t *cert_data) {
    ASSERT(buf != NULL);
    ASSERT(cert_data != NULL);

    cert_data->type = CERTIFICATE_STAKE_POOL_REGISTRATION;
    pool_registration_data_t *poolReg = &cert_data->poolRegistration;
    explicit_bzero(poolReg, sizeof(*poolReg));

    if (!buffer_read_u16(buf, &poolReg->payloadLength, BE) ||
        !buffer_can_read(buf, poolReg->payloadLength)) {
        TRACE("Failed to read pool registration payload length");
        return false;
    }
    TRACE_MODULE("payload_length=%u", poolReg->payloadLength);

    buffer_t pool_registration_payload_buffer = {
        .ptr = buffer_get_cur(buf),
        .size = poolReg->payloadLength,
        .offset = 0,
    };
    buffer_t *pool_reg_buf = &pool_registration_payload_buffer;

    if (!_parse_pool_id(pool_reg_buf, &cert_data->poolId)) {
        TRACE("Failed to parse pool id");
        return false;
    }
    TRACE_MODULE("poolId.keyReferenceType=%u", cert_data->poolId.keyReferenceType);

    if (!buffer_read_bytes_ptr(pool_reg_buf, &poolReg->vrfKeyHash, VRF_KEY_HASH_LENGTH)) {
        TRACE("Failed to read vrf key hash");
        return false;
    }

    ASSERT_TYPE(poolReg->pledge, uint64_t);
    if (!buffer_read_u64(pool_reg_buf, &poolReg->pledge, BE)) {
        TRACE("Failed to read pledge");
        return false;
    }
    if (poolReg->pledge >= LOVELACE_MAX_SUPPLY) {
        TRACE("Pledge too large: %llu", (unsigned long long) poolReg->pledge);
        return false;
    }
    TRACE_MODULE("pledge=%llu", (unsigned long long) poolReg->pledge);

    ASSERT_TYPE(poolReg->cost, uint64_t);
    if (!buffer_read_u64(pool_reg_buf, &poolReg->cost, BE)) {
        TRACE("Failed to read cost");
        return false;
    }
    if (poolReg->cost >= LOVELACE_MAX_SUPPLY) {
        TRACE("Cost too large: %llu", (unsigned long long) poolReg->cost);
        return false;
    }
    TRACE_MODULE("cost=%llu", (unsigned long long) poolReg->cost);

    ASSERT_TYPE(poolReg->marginNumerator, uint64_t);
    if (!buffer_read_u64(pool_reg_buf, &poolReg->marginNumerator, BE)) {
        TRACE("Failed to read margin numerator");
        return false;
    }
    TRACE_MODULE("marginNumerator=%llu", (unsigned long long) poolReg->marginNumerator);

    ASSERT_TYPE(poolReg->marginDenominator, uint64_t);
    if (!buffer_read_u64(pool_reg_buf, &poolReg->marginDenominator, BE)) {
        TRACE("Failed to read margin denominator");
        return false;
    }
    if (poolReg->marginDenominator == 0 || poolReg->marginDenominator > MARGIN_DENOMINATOR_MAX ||
        poolReg->marginNumerator > MARGIN_DENOMINATOR_MAX ||
        poolReg->marginNumerator > poolReg->marginDenominator) {
        TRACE("Invalid margin: %llu / %llu",
              (unsigned long long) poolReg->marginNumerator,
              (unsigned long long) poolReg->marginDenominator);
        return false;
    }
    TRACE_MODULE("marginDenominator=%llu", (unsigned long long) poolReg->marginDenominator);

    uint8_t reward_account_type;
    if (!buffer_read_u8(pool_reg_buf, &reward_account_type)) {
        TRACE("Failed to read reward account type");
        return false;
    }
    TRACE_MODULE("reward_account_type=0x%02x", reward_account_type);

    switch (reward_account_type) {
        case EXT_CREDENTIAL_KEY_HASH:
            poolReg->rewardAccount.keyReferenceType = KEY_REFERENCE_HASH;
            if (!buffer_read_bytes_ptr(pool_reg_buf,
                                       &poolReg->rewardAccount.hashBuffer,
                                       REWARD_ACCOUNT_LENGTH)) {
                TRACE("Failed to read reward account hash");
                return false;
            }
            ASSERT(poolReg->rewardAccount.hashBuffer != NULL);
            break;
        case EXT_CREDENTIAL_KEY_PATH:
            poolReg->rewardAccount.keyReferenceType = KEY_REFERENCE_PATH;
            if (!buffer_read_bip44_path(pool_reg_buf, &poolReg->rewardAccount.path)) {
                TRACE("Failed to read reward account path");
                return false;
            }
            break;
        default:
            TRACE("Unknown reward account type: 0x%02x", (unsigned) reward_account_type);
            return false;
    }

    if (!buffer_read_u16(pool_reg_buf, &poolReg->numPoolOwners, BE)) {
        TRACE("Failed to read number of owners");
        return false;
    }

    if (!buffer_read_u16(pool_reg_buf, &poolReg->numRelays, BE)) {
        TRACE("Failed to read number of relays");
        return false;
    }

    bool has_metadata = false;
    if (!buffer_read_flag_included(pool_reg_buf, &has_metadata)) {
        TRACE("Failed to read metadata inclusion flag");
        return false;
    }
    poolReg->hasMetadata = has_metadata;
    TRACE_MODULE("numPoolOwners=%u numRelays=%u hasMetadata=%u",
                 poolReg->numPoolOwners,
                 poolReg->numRelays,
                 has_metadata);

    // Keep outer buf at payload start. The processing stage will parse the whole
    // payload inside a bounded sub-buffer and then advance the outer cursor by
    // exactly payloadLength.
    LEDGER_ASSERT(pool_reg_buf->offset <= UINT16_MAX, "Pool registration header too long");
    poolReg->fixedHeaderLength = (uint16_t) pool_reg_buf->offset;

    return true;
}

bool parse_certificate(buffer_t *buf, certificate_data_t *out_certificate_data) {
    ASSERT(buf != NULL);
    ASSERT(out_certificate_data != NULL);

    explicit_bzero(out_certificate_data, sizeof(*out_certificate_data));

    uint8_t certificate_type_wire = 0;
    if (!buffer_read_u8(buf, &certificate_type_wire)) {
        TRACE("Failed to read certificate type");
        return false;
    }
    TRACE_MODULE("certificate_type_wire=%u", certificate_type_wire);

    certificate_type_t certificate_type = (certificate_type_t) certificate_type_wire;
    switch (certificate_type) {
        case CERTIFICATE_STAKE_REGISTRATION:
        case CERTIFICATE_STAKE_DEREGISTRATION:
            return parse_certificate_stake_registration_deregistration(buf,
                                                                       certificate_type,
                                                                       out_certificate_data);
        case CERTIFICATE_STAKE_DELEGATION:
            return parse_certificate_stake_delegation(buf, out_certificate_data);
        case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
        case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY:
            return parse_certificate_stake_registration_deregistration_conway(buf,
                                                                              certificate_type,
                                                                              out_certificate_data);
        case CERTIFICATE_STAKE_POOL_RETIREMENT:
            return parse_certificate_stake_pool_retirement(buf, out_certificate_data);
        case CERTIFICATE_STAKE_POOL_REGISTRATION:
            return parse_certificate_stake_pool_registration(buf, out_certificate_data);
        case CERTIFICATE_VOTE_DELEGATION:
            return parse_certificate_vote_delegation(buf, out_certificate_data);
        case CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION:
            return parse_certificate_stake_pool_and_drep_delegation(buf, out_certificate_data);
        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL:
            return parse_certificate_account_registration_delegation_to_stake_pool(
                buf,
                out_certificate_data);
        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP:
            return parse_certificate_account_registration_delegation_to_drep(buf,
                                                                             out_certificate_data);
        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP:
            return parse_certificate_account_registration_delegation_to_stake_pool_and_drep(
                buf,
                out_certificate_data);
        case CERTIFICATE_AUTHORIZE_COMMITTEE_HOT:
            return parse_certificate_authorize_committee_hot(buf, out_certificate_data);
        case CERTIFICATE_RESIGN_COMMITTEE_COLD:
            return parse_certificate_resign_committee_cold(buf, out_certificate_data);
        case CERTIFICATE_DREP_REGISTRATION:
            return parse_certificate_drep_registration(buf, out_certificate_data);
        case CERTIFICATE_DREP_DEREGISTRATION:
            return parse_certificate_drep_deregistration(buf, out_certificate_data);
        case CERTIFICATE_DREP_UPDATE:
            return parse_certificate_drep_update(buf, out_certificate_data);
        default:
            TRACE("Unknown certificate type: %u", (unsigned) certificate_type_wire);
            return false;
    }
}
