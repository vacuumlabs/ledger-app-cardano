/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "buffer.h"
#include "lists.h"
#include "mem.h"

#include "os.h"

#include "cardano_swo.h"
#include "app_context.h"
#include "tx_parse.h"
#include "tx_parse_certificates.h"
#include "tx.h"
#include "utils.h"
#include "assert.h"
#include "tx_constants.h"
#include "tx_output_types.h"
#include "keyDerivation.h"
#include "tx_utils.h"
#include "addressUtilsShelley.h"
#include "globals.h"
#include "securityPolicy.h"
#include "ui_utils.h"
#include "ui_warnings.h"
#include "ui_constants.h"
#include "ui_formatters.h"
#include "ui_address_fields.h"
#include "tx_ui_render_certificates.h"
#include "cardano_tokens.h"
#include "bech32.h"
#include "io.h"
#include "cardano_parsers.h"

#include <stdio.h>
#include <string.h>

credential_t credential_for_tx_hash_from_ext_credential(const ext_credential_t *credential);
drep_t drep_for_tx_hash_from_ext_drep(const ext_drep_t *ext_drep);

static void hash_certificate(tx_hash_builder_t *hash_builder,
                             const certificate_data_t *parsed_certificate_data) {
    ASSERT(hash_builder != NULL);
    ASSERT(parsed_certificate_data != NULL);

    switch (parsed_certificate_data->type) {
        case CERTIFICATE_STAKE_REGISTRATION:
        case CERTIFICATE_STAKE_DEREGISTRATION: {
            credential_t stake_credential_for_hash = credential_for_tx_hash_from_ext_credential(
                &parsed_certificate_data->stakeCredential);
            txHashBuilder_addCertificate_stakingOld(hash_builder,
                                                    parsed_certificate_data->type,
                                                    &stake_credential_for_hash);
            break;
        }
        case CERTIFICATE_STAKE_DELEGATION: {
            credential_t stake_credential_for_hash = credential_for_tx_hash_from_ext_credential(
                &parsed_certificate_data->stakeCredential);
            txHashBuilder_addCertificate_stakeDelegation(hash_builder,
                                                         &stake_credential_for_hash,
                                                         parsed_certificate_data->poolKeyHash,
                                                         POOL_KEY_HASH_LENGTH);
            break;
        }
        case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
        case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY: {
            credential_t stake_credential_for_hash = credential_for_tx_hash_from_ext_credential(
                &parsed_certificate_data->stakeCredential);
            txHashBuilder_addCertificate_staking(hash_builder,
                                                 parsed_certificate_data->type,
                                                 &stake_credential_for_hash,
                                                 parsed_certificate_data->deposit);
            break;
        }
        case CERTIFICATE_VOTE_DELEGATION: {
            credential_t stake_credential_for_hash = credential_for_tx_hash_from_ext_credential(
                &parsed_certificate_data->stakeCredential);
            drep_t drep_for_hash = drep_for_tx_hash_from_ext_drep(&parsed_certificate_data->drep);
            txHashBuilder_addCertificate_voteDelegation(hash_builder,
                                                        &stake_credential_for_hash,
                                                        &drep_for_hash);
            break;
        }
        case CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION: {
            credential_t stake_credential_for_hash = credential_for_tx_hash_from_ext_credential(
                &parsed_certificate_data->stakeCredential);
            drep_t drep_for_hash = drep_for_tx_hash_from_ext_drep(&parsed_certificate_data->drep);
            txHashBuilder_addCertificate_stakePoolAndDRepDelegation(
                hash_builder,
                &stake_credential_for_hash,
                parsed_certificate_data->combinedDelegPoolKeyHash,
                POOL_KEY_HASH_LENGTH,
                &drep_for_hash);
            break;
        }
        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL: {
            credential_t stake_credential_for_hash = credential_for_tx_hash_from_ext_credential(
                &parsed_certificate_data->stakeCredential);
            txHashBuilder_addCertificate_accountRegistrationDelegationToStakePool(
                hash_builder,
                &stake_credential_for_hash,
                parsed_certificate_data->combinedDelegPoolKeyHash,
                POOL_KEY_HASH_LENGTH,
                parsed_certificate_data->deposit);
            break;
        }
        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP: {
            credential_t stake_credential_for_hash = credential_for_tx_hash_from_ext_credential(
                &parsed_certificate_data->stakeCredential);
            drep_t drep_for_hash = drep_for_tx_hash_from_ext_drep(&parsed_certificate_data->drep);
            txHashBuilder_addCertificate_accountRegistrationDelegationToDRep(
                hash_builder,
                &stake_credential_for_hash,
                &drep_for_hash,
                parsed_certificate_data->deposit);
            break;
        }
        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP: {
            credential_t stake_credential_for_hash = credential_for_tx_hash_from_ext_credential(
                &parsed_certificate_data->stakeCredential);
            drep_t drep_for_hash = drep_for_tx_hash_from_ext_drep(&parsed_certificate_data->drep);
            txHashBuilder_addCertificate_accountRegistrationDelegationToStakePoolAndDRep(
                hash_builder,
                &stake_credential_for_hash,
                parsed_certificate_data->combinedDelegPoolKeyHash,
                POOL_KEY_HASH_LENGTH,
                &drep_for_hash,
                parsed_certificate_data->deposit);
            break;
        }
        case CERTIFICATE_AUTHORIZE_COMMITTEE_HOT: {
            credential_t cold_credential_for_hash = credential_for_tx_hash_from_ext_credential(
                &parsed_certificate_data->coldCredential);
            credential_t hot_credential_for_hash =
                credential_for_tx_hash_from_ext_credential(&parsed_certificate_data->hotCredential);
            txHashBuilder_addCertificate_committeeAuthHot(hash_builder,
                                                          &cold_credential_for_hash,
                                                          &hot_credential_for_hash);
            break;
        }
        case CERTIFICATE_RESIGN_COMMITTEE_COLD: {
            credential_t cold_credential_for_hash = credential_for_tx_hash_from_ext_credential(
                &parsed_certificate_data->coldCredential);
            txHashBuilder_addCertificate_committeeResign(hash_builder,
                                                         &cold_credential_for_hash,
                                                         &parsed_certificate_data->anchor);
            break;
        }
        case CERTIFICATE_DREP_REGISTRATION: {
            credential_t drep_credential_for_hash = credential_for_tx_hash_from_ext_credential(
                &parsed_certificate_data->dRepCredential);
            txHashBuilder_addCertificate_dRepRegistration(hash_builder,
                                                          &drep_credential_for_hash,
                                                          parsed_certificate_data->deposit,
                                                          &parsed_certificate_data->anchor);
            break;
        }
        case CERTIFICATE_DREP_DEREGISTRATION: {
            credential_t drep_credential_for_hash = credential_for_tx_hash_from_ext_credential(
                &parsed_certificate_data->dRepCredential);
            txHashBuilder_addCertificate_dRepDeregistration(hash_builder,
                                                            &drep_credential_for_hash,
                                                            parsed_certificate_data->deposit);
            break;
        }
        case CERTIFICATE_DREP_UPDATE: {
            credential_t drep_credential_for_hash = credential_for_tx_hash_from_ext_credential(
                &parsed_certificate_data->dRepCredential);
            txHashBuilder_addCertificate_dRepUpdate(hash_builder,
                                                    &drep_credential_for_hash,
                                                    &parsed_certificate_data->anchor);
            break;
        }
        case CERTIFICATE_STAKE_POOL_RETIREMENT: {
            uint8_t pool_key_hash[POOL_KEY_HASH_LENGTH] = {0};
            const ext_credential_t *pool_credential = &parsed_certificate_data->poolCredential;
            switch (pool_credential->type) {
                case EXT_CREDENTIAL_KEY_PATH:
                    keyPathToKeyHash(&pool_credential->keyPath,
                                     pool_key_hash,
                                     SIZEOF(pool_key_hash));
                    break;
                case EXT_CREDENTIAL_KEY_HASH:
                    ASSERT(pool_credential->keyHash != NULL);
                    STATIC_ASSERT(ADDRESS_KEY_HASH_LENGTH == POOL_KEY_HASH_LENGTH,
                                  "pool credential hash size mismatch");
                    memmove(pool_key_hash, pool_credential->keyHash, SIZEOF(pool_key_hash));
                    break;
                // LCOV_EXCL_START
                default:
                    LEDGER_ASSERT(false, "Unknown ext_credential_type_t for pool retirement");
                    break;
                    // LCOV_EXCL_STOP
            }
            txHashBuilder_addCertificate_poolRetirement(hash_builder,
                                                        pool_key_hash,
                                                        SIZEOF(pool_key_hash),
                                                        parsed_certificate_data->retirementEpoch);
            break;
        }
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown certificate_type_t");
            break;
            // LCOV_EXCL_STOP
    }
}

static security_policy_t determine_certificate_policy(
    certificate_type_t type,
    const certificate_data_t *parsed_certificate_data,
    const tx_params_t *tx_params,
    warning_bits_t *warning_bits) {
    switch (type) {
        case CERTIFICATE_STAKE_REGISTRATION:
        case CERTIFICATE_STAKE_DEREGISTRATION:
        case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
        case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY:
        case CERTIFICATE_STAKE_DELEGATION:
            return policyForSignTxCertificateStaking(tx_params->txSigningMode,
                                                     type,
                                                     &parsed_certificate_data->stakeCredential,
                                                     warning_bits);

        case CERTIFICATE_STAKE_POOL_RETIREMENT:
            return policyForSignTxCertificateStakePoolRetirement(
                tx_params->txSigningMode,
                &parsed_certificate_data->poolCredential,
                parsed_certificate_data->retirementEpoch,
                warning_bits);

        case CERTIFICATE_VOTE_DELEGATION:
            return policyForSignTxCertificateVoteDelegation(
                tx_params->txSigningMode,
                &parsed_certificate_data->stakeCredential,
                &parsed_certificate_data->drep,
                warning_bits);

        case CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION:
            return policyForSignTxCertificateStakePoolAndDRepDelegation(
                tx_params->txSigningMode,
                &parsed_certificate_data->stakeCredential,
                &parsed_certificate_data->drep,
                warning_bits);

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL:
            return policyForSignTxCertificateAccountRegistrationDelegationToStakePool(
                tx_params->txSigningMode,
                &parsed_certificate_data->stakeCredential,
                warning_bits);

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP:
            return policyForSignTxCertificateAccountRegistrationDelegationToDRep(
                tx_params->txSigningMode,
                &parsed_certificate_data->stakeCredential,
                &parsed_certificate_data->drep,
                warning_bits);

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP:
            return policyForSignTxCertificateAccountRegistrationDelegationToStakePoolAndDRep(
                tx_params->txSigningMode,
                &parsed_certificate_data->stakeCredential,
                &parsed_certificate_data->drep,
                warning_bits);

        case CERTIFICATE_DREP_REGISTRATION:
        case CERTIFICATE_DREP_DEREGISTRATION:
        case CERTIFICATE_DREP_UPDATE:
            return policyForSignTxCertificateDRep(tx_params->txSigningMode,
                                                  &parsed_certificate_data->dRepCredential,
                                                  warning_bits);

        case CERTIFICATE_AUTHORIZE_COMMITTEE_HOT:
            return policyForSignTxCertificateCommitteeAuth(tx_params->txSigningMode,
                                                           &parsed_certificate_data->coldCredential,
                                                           &parsed_certificate_data->hotCredential,
                                                           warning_bits);

        case CERTIFICATE_RESIGN_COMMITTEE_COLD:
            return policyForSignTxCertificateCommitteeResign(
                tx_params->txSigningMode,
                &parsed_certificate_data->coldCredential,
                warning_bits);

        // LCOV_EXCL_START
        case CERTIFICATE_STAKE_POOL_REGISTRATION:
            LEDGER_ASSERT(false, "CERTIFICATE_STAKE_POOL_REGISTRATION handled separately");
            return POLICY_DENY;

        default:
            LEDGER_ASSERT(false, "Unknown certificate_type_t");
            return POLICY_DENY;
            // LCOV_EXCL_STOP
    }
}

/**
 * Scan the owner list (without consuming buf) to count path-type owners and
 * record the first one found.
 *
 * Pool registration in OWNER signing mode requires exactly one path owner,
 * whose key path becomes the witness. We need this count before calling
 * policyForSignTxStakePoolRegistrationInit, hence the pre-scan.
 *
 * @param[in]  owners_buf          Buffer snapshot positioned at the start of owner data
 * @param[in]  num_owners          Number of owners to scan
 * @param[out] out_path_owner_count   Number of path-type owners found
 * @param[out] out_first_path_owner   First path owner found (valid iff out_path_owner_count >= 1)
 * @return true on success, false if owner data could not be parsed
 */
static bool scan_pool_owners_for_path_witnesses(buffer_t owners_buf,
                                                uint16_t num_owners,
                                                uint32_t *out_path_owner_count,
                                                ext_credential_t *out_first_path_owner) {
    ASSERT(out_path_owner_count != NULL);
    ASSERT(out_first_path_owner != NULL);

    *out_path_owner_count = 0;
    explicit_bzero(out_first_path_owner, sizeof(*out_first_path_owner));

    for (uint16_t i = 0; i < num_owners; i++) {
        ext_credential_t owner_credential = {0};
        if (!buffer_read_credential(&owners_buf, &owner_credential)) {
            return false;
        }
        if (owner_credential.type == EXT_CREDENTIAL_KEY_PATH) {
            (*out_path_owner_count)++;
            if (*out_path_owner_count == 1) {
                *out_first_path_owner = owner_credential;
            }
        }
    }
    return true;
}

bool process_pool_registration_certificate(buffer_t *buf,
                                           tx_processing_state_t *state,
                                           const certificate_data_t *parsed_cert) {
    ASSERT(buf != NULL);
    ASSERT(state != NULL && state->tx_params != NULL && state->warning_bits != NULL);
    ASSERT(parsed_cert != NULL && parsed_cert->type == CERTIFICATE_STAKE_POOL_REGISTRATION);

    // buf is positioned at the start of the pool registration payload.

    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;
    tx_hash_builder_t *hash_builder = &state->hash_builder;

    const pool_registration_data_t *pool_registration = &parsed_cert->poolRegistration;
    if (pool_registration->payloadLength < pool_registration->fixedHeaderLength) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_CERTIFICATES);
        return false;
    }
    buffer_t pool_payload_buf = {
        .ptr = buffer_get_cur(buf),
        .size = pool_registration->payloadLength,
        .offset = 0,
    };
    if (!buffer_seek_cur(&pool_payload_buf, pool_registration->fixedHeaderLength)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_CERTIFICATES);
        return false;
    }

    TRACE("Pool registration: owners=%u relays=%u",
          (unsigned) pool_registration->numPoolOwners,
          (unsigned) pool_registration->numRelays);

    // Scan owner list (without consuming buf) to count path owners and find the first one.
    // We need path_owner_count before calling policyForSignTxStakePoolRegistrationInit,
    // and the first path owner to extract the witness key in OWNER signing mode.
    uint32_t path_owner_count = 0;
    ext_credential_t first_path_owner = {0};
    if (!scan_pool_owners_for_path_witnesses(pool_payload_buf,
                                             pool_registration->numPoolOwners,
                                             &path_owner_count,
                                             &first_path_owner)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_CERTIFICATES);
        return false;
    }

    if (mode->run_validation) {
        security_policy_t certificate_policy =
            policyForSignTxStakePoolRegistrationInit(tx_params->txSigningMode,
                                                     pool_registration->numPoolOwners,
                                                     pool_registration->numRelays,
                                                     path_owner_count,
                                                     state->warning_bits);
        APPLY_POLICY(certificate_policy,
                     plan_or_render_pool_registration_header,
                     mode,
                     parsed_cert->type);

        security_policy_t pool_id_policy =
            policyForSignTxStakePoolRegistrationPoolId(tx_params->txSigningMode,
                                                       &parsed_cert->poolId,
                                                       state->warning_bits);
        APPLY_POLICY(pool_id_policy, plan_or_render_pool_id, mode, &parsed_cert->poolId);

        security_policy_t vrf_policy =
            policyForSignTxStakePoolRegistrationVrfKey(tx_params->txSigningMode,
                                                       state->warning_bits);
        APPLY_POLICY(vrf_policy,
                     plan_or_render_pool_vrf_key_hash,
                     mode,
                     pool_registration->vrfKeyHash);

        plan_or_render_pool_financials(mode, pool_registration);

        security_policy_t reward_policy =
            policyForSignTxStakePoolRegistrationRewardAccount(tx_params->txSigningMode,
                                                              tx_params->networkId,
                                                              &pool_registration->rewardAccount,
                                                              state->warning_bits);
        APPLY_POLICY(reward_policy,
                     plan_or_render_pool_reward_account,
                     mode,
                     tx_params->networkId,
                     &pool_registration->rewardAccount);
    }

    // In OWNER signing mode, record the unique path owner as the witness key.
    // policyForSignTxStakePoolRegistrationInit already enforced path_owner_count == 1
    // for OWNER mode, so the assert below is a guaranteed invariant, not a condition.
    // Done on the hash-builder pass (pass 1) only — not repeated on the UI render pass.
    if (mode->run_hash_builder &&
        tx_params->txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER) {
        LEDGER_ASSERT(!G_context.tx_info.pool_owner_path_present,
                      "Multiple pool registrations in owner mode");
        LEDGER_ASSERT(path_owner_count == 1, "Expected exactly one path owner in owner mode");
        G_context.tx_info.pool_owner_path = first_path_owner.keyPath;
        G_context.tx_info.pool_owner_path_present = true;
    }

    if (mode->run_hash_builder) {
        txHashBuilder_poolRegistrationCertificate_enter(hash_builder,
                                                        pool_registration->numPoolOwners,
                                                        pool_registration->numRelays);
        uint8_t pool_key_hash[POOL_KEY_HASH_LENGTH] = {0};
        switch (parsed_cert->poolId.keyReferenceType) {
            case KEY_REFERENCE_PATH:
                keyPathToKeyHash(&parsed_cert->poolId.path, pool_key_hash, SIZEOF(pool_key_hash));
                break;
            case KEY_REFERENCE_HASH:
                ASSERT(parsed_cert->poolId.hash != NULL);
                memmove(pool_key_hash, parsed_cert->poolId.hash, SIZEOF(pool_key_hash));
                break;
            // LCOV_EXCL_START
            default:
                LEDGER_ASSERT(false, "Unknown pool ID key reference type");
                // LCOV_EXCL_STOP
        }
        txHashBuilder_poolRegistrationCertificate_poolKeyHash(hash_builder,
                                                              pool_key_hash,
                                                              SIZEOF(pool_key_hash));
        txHashBuilder_poolRegistrationCertificate_vrfKeyHash(hash_builder,
                                                             pool_registration->vrfKeyHash,
                                                             VRF_KEY_HASH_LENGTH);
        txHashBuilder_poolRegistrationCertificate_financials(hash_builder,
                                                             pool_registration->pledge,
                                                             pool_registration->cost,
                                                             pool_registration->marginNumerator,
                                                             pool_registration->marginDenominator);
        uint8_t *reward_account_buffer = tx_alloc_temp_buffer_or_fail(REWARD_ACCOUNT_LENGTH);
        poolRewardAccountToBuffer(&pool_registration->rewardAccount,
                                  tx_params->networkId,
                                  reward_account_buffer);
        txHashBuilder_poolRegistrationCertificate_rewardAccount(hash_builder,
                                                                reward_account_buffer,
                                                                REWARD_ACCOUNT_LENGTH);
        APP_MEM_FREE_AND_NULL((void **) &reward_account_buffer);
        txHashBuilder_addPoolRegistrationCertificate_enterOwners(hash_builder);
    }

    // Owners
    TRACE("Processing %u owners", (unsigned) pool_registration->numPoolOwners);
    if (pool_registration->numPoolOwners > 0) {
        for (uint16_t owner_index = 0; owner_index < pool_registration->numPoolOwners;
             owner_index++) {
            ext_credential_t owner_credential = {0};
            if (!buffer_read_credential(&pool_payload_buf, &owner_credential)) {
                tx_handle_parse_error(SWO_TX_PARSING_FAIL_CERTIFICATES);
                return false;
            }

            if (mode->run_validation) {
                security_policy_t owner_policy =
                    policyForSignTxStakePoolRegistrationOwner(tx_params->txSigningMode,
                                                              &owner_credential,
                                                              state->warning_bits);
                APPLY_POLICY(owner_policy,
                             plan_or_render_pool_owner,
                             mode,
                             tx_params->networkId,
                             &owner_credential);
            }

            if (mode->run_hash_builder) {
                credential_t owner_credential_for_hash =
                    credential_for_tx_hash_from_ext_credential(&owner_credential);
                txHashBuilder_addPoolRegistrationCertificate_addOwner(
                    hash_builder,
                    owner_credential_for_hash.keyHash,
                    SIZEOF(owner_credential_for_hash.keyHash));
            }
        }
    } else {
        // numOwners == 0: warning already set by policyForSignTxStakePoolRegistrationInit.
        plan_or_render_pool_no_owners(mode);
    }

    // Relays
    if (mode->run_hash_builder) {
        txHashBuilder_addPoolRegistrationCertificate_enterRelays(hash_builder);
    }
    TRACE("Processing %u relays", (unsigned) pool_registration->numRelays);
    if (pool_registration->numRelays > 0) {
        for (uint16_t relay_index = 0; relay_index < pool_registration->numRelays; relay_index++) {
            pool_relay_t relay = {0};
            if (!parse_pool_relay(&pool_payload_buf, &relay)) {
                tx_handle_parse_error(SWO_TX_PARSING_FAIL_CERTIFICATES);
                return false;
            }

            if (mode->run_validation) {
                security_policy_t relay_policy =
                    policyForSignTxStakePoolRegistrationRelay(tx_params->txSigningMode,
                                                              &relay,
                                                              state->warning_bits);
                APPLY_POLICY(relay_policy, plan_or_render_pool_relay, mode, relay_index, &relay);
            }

            if (mode->run_hash_builder) {
                txHashBuilder_addPoolRegistrationCertificate_addRelay(hash_builder, &relay);
            }
        }
    } else {
        // numRelays == 0: warning already set by policyForSignTxStakePoolRegistrationInit.
        plan_or_render_pool_no_relays(mode);
    }

    // Metadata (presence known from header)
    if (!pool_registration->hasMetadata) {
        if (mode->run_validation) {
            security_policy_t no_metadata_policy =
                policyForSignTxStakePoolRegistrationNoMetadata(state->warning_bits);
            APPLY_POLICY(no_metadata_policy, plan_or_render_pool_no_metadata, mode);
        }

        if (mode->run_hash_builder) {
            txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata_null(hash_builder);
        }
    } else {
        pool_metadata_t pool_metadata = {0};
        if (!parse_pool_metadata(&pool_payload_buf, &pool_metadata)) {
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_CERTIFICATES);
            return false;
        }

        if (mode->run_validation) {
            security_policy_t metadata_policy =
                policyForSignTxStakePoolRegistrationMetadata(&pool_metadata, state->warning_bits);
            APPLY_POLICY(metadata_policy, plan_or_render_pool_metadata, mode, &pool_metadata);
        }

        if (mode->run_hash_builder) {
            txHashBuilder_addPoolRegistrationCertificate_addPoolMetadata(hash_builder,
                                                                         pool_metadata.url,
                                                                         pool_metadata.urlSize,
                                                                         pool_metadata.hash,
                                                                         POOL_METADATA_HASH_LENGTH);
        }
    }

    // The payload sub-buffer must be consumed exactly.
    if (buffer_can_read(&pool_payload_buf, 1)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_CERTIFICATES);
        return false;
    }
    // Advance outer transaction buffer by the exact payload length.
    if (!buffer_seek_cur(buf, pool_registration->payloadLength)) {
        tx_handle_parse_error(SWO_TX_PARSING_FAIL_CERTIFICATES);
        return false;
    }

    return true;
}

bool tx_process_certificates(buffer_t *buf, tx_processing_state_t *state) {
    ASSERT(buf != NULL);
    ASSERT(state != NULL && state->tx_params != NULL && state->warning_bits != NULL);
    const tx_params_t *tx_params = state->tx_params;
    const tx_processing_mode_t *mode = &state->mode;

    if (tx_params->num_certificates == 0) {
        return true;
    }

    certificate_data_t *parsed_certificate_data =
        (certificate_data_t *) tx_alloc_temp_buffer_or_fail(sizeof(certificate_data_t));

    if (mode->run_hash_builder) {
        G_context.tx_info.pool_owner_path_present = false;
        txHashBuilder_enterCertificates(&state->hash_builder);
    }

    for (uint16_t certificate_index = 0; certificate_index < tx_params->num_certificates;
         certificate_index++) {
        explicit_bzero(parsed_certificate_data, sizeof(certificate_data_t));

        if (!parse_certificate(buf, parsed_certificate_data)) {
            APP_MEM_FREE_AND_NULL((void **) &parsed_certificate_data);
            tx_handle_parse_error(SWO_TX_PARSING_FAIL_CERTIFICATES);
            return false;
        }

        if (parsed_certificate_data->type == CERTIFICATE_STAKE_POOL_REGISTRATION) {
            if (!process_pool_registration_certificate(buf, state, parsed_certificate_data)) {
                return false;
            }
            continue;
        }

        if (mode->run_validation) {
            security_policy_t certificate_policy =
                determine_certificate_policy(parsed_certificate_data->type,
                                             parsed_certificate_data,
                                             tx_params,
                                             state->warning_bits);

            APPLY_POLICY(certificate_policy,
                         tx_ui_plan_or_render_certificate,
                         mode,
                         parsed_certificate_data);

            if (parsed_certificate_data->anchor.isIncluded) {
                // Called for side-effect: sets WARNING_BIT_EMPTY_ANCHOR_URL if anchor URL is empty.
                // The warning bit must be set during Pass 1 (planning) so that the render pass
                // assertion in plan_or_render_anchor does not fire.
                security_policy_t anchor_policy =
                    policyForSignTxAnchor(&parsed_certificate_data->anchor, state->warning_bits);
                LEDGER_ASSERT(anchor_policy == POLICY_SHOW, "Unexpected anchor policy");
            }
        }

        if (mode->run_hash_builder) {
            hash_certificate(&state->hash_builder, parsed_certificate_data);
        }
    }

    APP_MEM_FREE_AND_NULL((void **) &parsed_certificate_data);
    return true;
}
