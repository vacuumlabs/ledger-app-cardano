/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "addressUtilsShelley.h"
#include "bip44.h"
#include "aux_data_hash_builder.h"
#include "messageSigning.h"
#include "cvote_types.h"
#include "securityPolicyType.h"
#include "tx_hash_builder.h"
#include "tx.h"

#include "securityWarnings.h"

static inline security_policy_t combine_security_policies(security_policy_t a,
                                                          security_policy_t b) {
    if (a == POLICY_DENY || b == POLICY_DENY) {
        return POLICY_DENY;
    }

    if (a == POLICY_SHOW || b == POLICY_SHOW) {
        return POLICY_SHOW;
    }

    LEDGER_ASSERT(a == POLICY_HIDE && b == POLICY_HIDE, "Unexpected policy combination");
    return POLICY_HIDE;
}

typedef struct {
    warning_bit_e bit;
    const char* title;
    const char* description;
} warning_definition_t;

static inline warning_bits_t warning_bits_mask_for(warning_bit_e bit) {
    return ((warning_bits_t) 1) << bit;
}

static inline warning_bits_t warning_bits_except_mask(warning_bits_t warnings,
                                                      warning_bits_t excluded_mask) {
    return warnings & ~excluded_mask;
}

bool shouldShowNetworkDetails(const tx_params_t* txParams);

security_policy_t policyForDerivePrivateKey(const bip44_path_t* path);

security_policy_t policyForGetExtendedPublicKey(const bip44_path_t* path, warning_bits_t* w);

security_policy_t policyForReturnDeriveAddress(const address_params_t* address_params,
                                               warning_bits_t* w);
security_policy_t policyForDeriveNativeScriptHashDevicePubkey(const bip44_path_t* path,
                                                              warning_bits_t* w);
security_policy_t policyForShowDeriveAddress(const address_params_t* address_params,
                                             warning_bits_t* w);

security_policy_t policyForSignTxInit(const tx_params_t* txParams, warning_bits_t* w);

security_policy_t policyForSignTxInput(sign_tx_signingmode_t txSigningMode,
                                       const tx_input_t* input MARK_UNUSED,
                                       warning_bits_t* w);

security_policy_t policyForSignTxOutput(const tx_output_description_t* output,
                                        sign_tx_signingmode_t txSigningMode,
                                        const uint8_t networkId,
                                        const uint32_t protocolMagic,
                                        warning_bits_t* w);
security_policy_t policyForSignTxOutputDatumHash(security_policy_t outputPolicy, warning_bits_t* w);

security_policy_t policyForSignTxOutputRefScript(security_policy_t outputPolicy, warning_bits_t* w);
security_policy_t policyForSignTxCollateralOutputAddress(const tx_output_description_t* output,
                                                         sign_tx_signingmode_t txSigningMode,
                                                         const uint8_t networkId,
                                                         const uint32_t protocolMagic,
                                                         bool isTotalCollateralIncluded,
                                                         warning_bits_t* w);
security_policy_t policyForSignTxCollateralOutputAdaAmount(security_policy_t outputPolicy,
                                                           bool isTotalCollateralPresent,
                                                           warning_bits_t* w);
security_policy_t policyForSignTxCollateralOutputTokens(security_policy_t outputPolicy,
                                                        const tx_output_description_t* output,
                                                        warning_bits_t* w);

security_policy_t policyForSignTxFee(sign_tx_signingmode_t txSigningMode,
                                     uint64_t fee,
                                     warning_bits_t* w);
security_policy_t policyForSignTxTtl(uint64_t ttl, warning_bits_t* w);
security_policy_t policyForSignTxCertificateStaking(sign_tx_signingmode_t txSigningMode,
                                                    const certificate_type_t certificateType,
                                                    const ext_credential_t* stakeCredential,
                                                    warning_bits_t* w);
security_policy_t policyForSignTxCertificateVoteDelegation(sign_tx_signingmode_t txSigningMode,
                                                           const ext_credential_t* stakeCredential,
                                                           const ext_drep_t* drep,
                                                           warning_bits_t* w);
security_policy_t policyForSignTxCertificateStakePoolAndDRepDelegation(
    sign_tx_signingmode_t txSigningMode,
    const ext_credential_t* stakeCredential,
    const ext_drep_t* drep,
    warning_bits_t* w);
security_policy_t policyForSignTxCertificateAccountRegistrationDelegationToStakePool(
    sign_tx_signingmode_t txSigningMode,
    const ext_credential_t* stakeCredential,
    warning_bits_t* w);
security_policy_t policyForSignTxCertificateAccountRegistrationDelegationToDRep(
    sign_tx_signingmode_t txSigningMode,
    const ext_credential_t* stakeCredential,
    const ext_drep_t* drep,
    warning_bits_t* w);
security_policy_t policyForSignTxCertificateAccountRegistrationDelegationToStakePoolAndDRep(
    sign_tx_signingmode_t txSigningMode,
    const ext_credential_t* stakeCredential,
    const ext_drep_t* drep,
    warning_bits_t* w);
security_policy_t policyForSignTxCertificateCommitteeAuth(sign_tx_signingmode_t txSigningMode,
                                                          const ext_credential_t* coldCredential,
                                                          const ext_credential_t* hotCredential,
                                                          warning_bits_t* w);
security_policy_t policyForSignTxCertificateCommitteeResign(sign_tx_signingmode_t txSigningMode,
                                                            const ext_credential_t* coldCredential,
                                                            warning_bits_t* w);
security_policy_t policyForSignTxCertificateDRep(sign_tx_signingmode_t txSigningMode,
                                                 const ext_credential_t* dRepCredential,
                                                 warning_bits_t* w);
security_policy_t policyForSignTxCertificateStakePoolRetirement(
    sign_tx_signingmode_t txSigningMode,
    const ext_credential_t* poolCredential,
    uint64_t epoch,
    warning_bits_t* w);
security_policy_t policyForSignTxStakePoolRegistrationInit(sign_tx_signingmode_t txSigningMode,
                                                           uint32_t numOwners,
                                                           uint32_t numRelays,
                                                           uint32_t numPathOwners,
                                                           warning_bits_t* w);
security_policy_t policyForSignTxStakePoolRegistrationPoolId(sign_tx_signingmode_t txSigningMode,
                                                             const pool_id_t* poolId,
                                                             warning_bits_t* w);
security_policy_t policyForSignTxStakePoolRegistrationVrfKey(sign_tx_signingmode_t txSigningMode,
                                                             warning_bits_t* w);
security_policy_t policyForSignTxStakePoolRegistrationRewardAccount(
    sign_tx_signingmode_t txSigningMode,
    uint8_t networkId,
    const pool_reward_account_t* poolRewardAccount,
    warning_bits_t* w);
security_policy_t policyForSignTxStakePoolRegistrationOwner(
    const sign_tx_signingmode_t txSigningMode,
    const ext_credential_t* ownerCredential,
    warning_bits_t* w);
security_policy_t policyForSignTxStakePoolRegistrationRelay(
    const sign_tx_signingmode_t txSigningMode,
    const pool_relay_t* relay,
    warning_bits_t* w);
security_policy_t policyForSignTxStakePoolRegistrationMetadata(const pool_metadata_t* metadata,
                                                               warning_bits_t* w);
security_policy_t policyForSignTxStakePoolRegistrationNoMetadata(warning_bits_t* w);
security_policy_t policyForSignTxAnchor(const anchor_t* anchor, warning_bits_t* w);
security_policy_t policyForSignTxWithdrawal(sign_tx_signingmode_t txSigningMode,
                                            const ext_credential_t* stakeCredential,
                                            warning_bits_t* w);
security_policy_t policyForSignTxAuxData(aux_data_type_t auxDataType, warning_bits_t* w);

security_policy_t policyForSignTxValidityIntervalStart(warning_bits_t* w);
security_policy_t policyForSignTxMintInit(const sign_tx_signingmode_t txSigningMode,
                                          warning_bits_t* w);

security_policy_t policyForSignTxScriptDataHash(const sign_tx_signingmode_t txSigningMode,
                                                warning_bits_t* w);

security_policy_t policyForSignTxCollateralInput(const sign_tx_signingmode_t txSigningMode,
                                                 bool isTotalCollateralIncluded,
                                                 const tx_input_t* collateralInput,
                                                 warning_bits_t* w);

security_policy_t policyForSignTxRequiredSigner(const sign_tx_signingmode_t txSigningMode,
                                                required_signer_t* requiredSigner,
                                                warning_bits_t* w);

security_policy_t policyForSignTxTotalCollateral(warning_bits_t* w);

security_policy_t policyForSignTxReferenceInput(const sign_tx_signingmode_t txSigningMode,
                                                const tx_input_t* referenceInput,
                                                warning_bits_t* w);

security_policy_t policyForSignTxVotingProcedure(sign_tx_signingmode_t txSigningMode,
                                                 ext_voter_t* voter,
                                                 warning_bits_t* w);

security_policy_t policyForSignTxTreasury(sign_tx_signingmode_t txSigningMode,
                                          uint64_t treasury,
                                          warning_bits_t* w);

security_policy_t policyForSignTxDonation(sign_tx_signingmode_t txSigningMode,
                                          uint64_t donation,
                                          warning_bits_t* w);
security_policy_t policyForSignTxDisplayTxHash(sign_tx_signingmode_t txSigningMode,
                                               warning_bits_t* w);

security_policy_t policyForSignTxWitness(sign_tx_signingmode_t txSigningMode,
                                         bool isSwap,
                                         const bip44_path_t* witnessPath,
                                         bool mintPresent,
                                         const bip44_path_t* poolOwnerPath,
                                         warning_bits_t* w);

security_policy_t policyForCVoteRegistrationVoteKey(const cvote_credential_t* credential,
                                                    cvote_registration_format_t format,
                                                    warning_bits_t* w);
security_policy_t policyForCVoteRegistrationStakingKey(const bip44_path_t* stakingKeyPath,
                                                       warning_bits_t* w);
security_policy_t policyForCVoteRegistrationPaymentDestination(
    const tx_output_destination_t* destination,
    const uint8_t networkId,
    warning_bits_t* w);
security_policy_t policyForCVoteRegistrationNonce(warning_bits_t* w);
security_policy_t policyForCVoteRegistrationVotingPurpose(uint64_t votingPurpose,
                                                          warning_bits_t* w);

security_policy_t policyForSignOpCert(const bip44_path_t* poolColdKeyPathSpec, warning_bits_t* w);

size_t warning_bits_to_definitions(warning_bits_t warnings,
                                   const warning_definition_t** definitions,
                                   size_t max_definitions);

security_policy_t policyForSignCVoteWitness(const bip44_path_t* path, warning_bits_t* w);

security_policy_t policyForSignMsg(const bip44_path_t* witnessPath,
                                   cip8_address_field_type_t addressFieldType,
                                   const address_params_t* address_params,
                                   warning_bits_t* w);
