/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>

#include "os.h"
#include "addressUtilsShelley.h"
#include "addressUtilsByron.h"
#include "cardano_settings.h"
#include "bip44.h"
#include "tx_hash_builder.h"
#include "tx_utils.h"

#define HIGH_FEE_WARNING_THRESHOLD 5000000

#include "securityPolicy.h"

static bool is_staking_credential_key_path_allowed(sign_tx_signingmode_t txSigningMode,
                                                   const bip44_path_t *path) {
    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_ORDINARY:
        case SIGN_TX_SIGNINGMODE_PLUTUS:
            return bip44_isOrdinaryStakingKeyPath(path);

        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            return bip44_isOrdinaryStakingKeyPath(path) || bip44_isMultisigStakingKeyPath(path);

        case SIGN_TX_SIGNINGMODE_MULTISIG:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            return false;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            return false;
            // LCOV_EXCL_STOP
    }
}

// stake key path has the same account as the payment key path
static inline bool is_standard_base_address(const address_params_t *address_params) {
    ASSERT(isValidAddressParams(address_params));

#define CHECK(cond) \
    if (!(cond)) return false
    CHECK(address_params->type == BASE_PAYMENT_KEY_STAKE_KEY);
    CHECK(addressParams_getStakingPartType(address_params) == STAKING_PART_KEY_PATH);

    CHECK(addressParams_getPaymentPartType(address_params) == PAYMENT_PART_KEY_PATH);
    CHECK(bip44_classifyPath(&address_params->paymentKeyPath) == PATH_ORDINARY_PAYMENT_KEY);
    CHECK(bip44_isPathReasonable(&address_params->paymentKeyPath));

    CHECK(bip44_classifyPath(&address_params->stakingKeyPath) == PATH_ORDINARY_STAKING_KEY);
    CHECK(bip44_isPathReasonable(&address_params->stakingKeyPath));
    // most SW wallets do not use multidelegation,
    // so outputs sending funds to such addresses should not be hidden
    CHECK(!bip44_isMultidelegationStakingKeyPath(&address_params->stakingKeyPath));

    CHECK(bip44_getAccount(&address_params->stakingKeyPath) ==
          bip44_getAccount(&address_params->paymentKeyPath));

    return true;
#undef CHECK
}

static address_type_t getDestinationAddressType(const tx_output_destination_t *destination) {
    ASSERT(destination != NULL);

    switch (destination->type) {
        case DESTINATION_DEVICE_OWNED:
            return destination->params.type;
        case DESTINATION_THIRD_PARTY:
            ASSERT(destination->address.buffer != NULL);
            LEDGER_ASSERT(destination->address.length > 0, "Zero destination address length");
            return getAddressType(destination->address.buffer[0]);
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }
}

/*
 * SECURITY POLICY MACROS: CONTROL-FLOW + WARNING CONTRACT
 *
 * Conventions:
 * - Every policy function accepts `warning_bits_t *w`.
 * - `w` is the canonical name and must be used consistently.
 * - Policy functions must not return policies directly.
 *   Always return through SHOW()/HIDE()/DENY() (or conditional variants).
 *
 * Control flow:
 * - SHOW(), HIDE(), DENY() are terminal actions.
 * - They expand to checked returns from the current policy function.
 * - Conditional forms (SHOW_IF, HIDE_IF, DENY_IF, DENY_UNLESS, etc.)
 *   are also terminal when triggered.
 *
 * Warning invariant:
 * - Warnings are allowed only with POLICY_SHOW or POLICY_DENY.
 * - POLICY_HIDE with newly added w is forbidden and must assert.
 * - Therefore, all returns must go through policy macros that enforce this.
 *
 * Style rules:
 * - In switch branches, keep explicit `break` for readability,
 *   even though macro-return paths are terminal.
 * - Order checks as DENY > SHOW > HIDE unless an exceptional case is documented.
 *
 * Unusual path warning rule:
 * - WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH must be set only via
 *   mark_unusual_key_derivation(w, ...), never directly.
 */
static warning_bits_t policy_warnings_snapshot(const warning_bits_t *w) {
    ASSERT(w != NULL);
    return *w;
}

static security_policy_t policy_checked_return(const warning_bits_t *w,
                                               warning_bits_t w_start,
                                               security_policy_t policy) {
    ASSERT(w != NULL);
    ASSERT(policy != POLICY_HIDE || warning_bits_except_mask(*w, w_start) == 0);
    return policy;
}

#define POLICY_INIT() const warning_bits_t w_start = policy_warnings_snapshot(w);

#define RETURN(policy) return policy_checked_return(w, w_start, (policy));

#define DENY() RETURN(POLICY_DENY)
#define DENY_IF(expr) \
    if (expr) RETURN(POLICY_DENY)
#define DENY_UNLESS(expr) \
    if (!(expr)) RETURN(POLICY_DENY)

#define SHOW() RETURN(POLICY_SHOW)
#define SHOW_IF(expr) \
    if (expr) RETURN(POLICY_SHOW)
#define SHOW_UNLESS(expr) \
    if (!(expr)) RETURN(POLICY_SHOW)

#define HIDE() RETURN(POLICY_HIDE)
#define HIDE_IF(expr) \
    if (expr) RETURN(POLICY_HIDE)
#define HIDE_UNLESS(expr) \
    if (!(expr)) RETURN(POLICY_HIDE)

static inline bool mark_unusual_key_derivation(warning_bits_t *w, const bip44_path_t *path) {
    ASSERT(w != NULL);
    ASSERT(path != NULL);

    const bool is_unusual = !bip44_isPathReasonable(path);
    if (is_unusual) {
        warning_bits_set(w, WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH);
    }
    return is_unusual;
}

static security_policy_t _policyForGetExtendedPublicKey_silent(const bip44_path_t *path,
                                                               warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(path != NULL);
    switch (bip44_classifyPath(path)) {
        case PATH_ORDINARY_ACCOUNT:
        case PATH_ORDINARY_PAYMENT_KEY:
        case PATH_ORDINARY_STAKING_KEY:
        case PATH_MULTISIG_ACCOUNT:
        case PATH_MULTISIG_PAYMENT_KEY:
        case PATH_MULTISIG_STAKING_KEY:
        case PATH_CVOTE_ACCOUNT:
        case PATH_CVOTE_KEY:
            SHOW_IF(mark_unusual_key_derivation(w, path));
            // we do not show these if user turned on silent key export
            HIDE();
            break;

        case PATH_DREP_KEY:
        case PATH_COMMITTEE_COLD_KEY:
        case PATH_COMMITTEE_HOT_KEY:
        case PATH_MINT_KEY:
        case PATH_POOL_COLD_KEY:
            // these paths are rare and might give significant power
            // so we rather show them every time to alert the user
            // about his SW wallet asking about these keys
            SHOW_IF(mark_unusual_key_derivation(w, path));
            SHOW();
            break;

        case PATH_INVALID:
            DENY();
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            break;
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// Get extended public key and return it to the host
security_policy_t policyForGetExtendedPublicKey(const bip44_path_t *path, warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(path != NULL);

    if (is_silent_pubkey_export_allowed()) {
        RETURN(_policyForGetExtendedPublicKey_silent(path, w));
    }

    // user turned off silent public key export
    switch (bip44_classifyPath(path)) {
        case PATH_ORDINARY_ACCOUNT:
        case PATH_MULTISIG_ACCOUNT:
        case PATH_ORDINARY_PAYMENT_KEY:
        case PATH_ORDINARY_STAKING_KEY:
        case PATH_MULTISIG_PAYMENT_KEY:
        case PATH_MULTISIG_STAKING_KEY:
        case PATH_DREP_KEY:
        case PATH_COMMITTEE_COLD_KEY:
        case PATH_COMMITTEE_HOT_KEY:
        case PATH_MINT_KEY:
        case PATH_POOL_COLD_KEY:
        case PATH_CVOTE_ACCOUNT:
        case PATH_CVOTE_KEY:
            SHOW_IF(mark_unusual_key_derivation(w, path));
            SHOW();
            break;

        case PATH_INVALID:
            DENY();
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            break;
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// Common policy for returnDeriveAddress and showDeriveAddress:
// enforce DENY rules and unusual-path escalation to SHOW.
// successPolicy is returned if no DENY and no forced SHOW apply.
static security_policy_t _policyForDeriveAddress(const address_params_t *address_params,
                                                 security_policy_t successPolicy,
                                                 warning_bits_t *w) {
    POLICY_INIT();
    DENY_UNLESS(isValidAddressParams(address_params));

    switch (address_params->type) {
        case BASE_PAYMENT_KEY_STAKE_KEY:
            SHOW_IF(mark_unusual_key_derivation(w, &address_params->paymentKeyPath));

            if (addressParams_getStakingPartType(address_params) == STAKING_PART_KEY_PATH) {
                SHOW_IF(mark_unusual_key_derivation(w, &address_params->stakingKeyPath));
            }
            break;

        case BASE_PAYMENT_KEY_STAKE_SCRIPT:
        case POINTER_KEY:
        case ENTERPRISE_KEY:
        case BYRON:
            SHOW_IF(mark_unusual_key_derivation(w, &address_params->paymentKeyPath));
            break;

        case BASE_PAYMENT_SCRIPT_STAKE_KEY:
        case REWARD_KEY:
            DENY_IF(addressParams_getStakingPartType(address_params) != STAKING_PART_KEY_PATH);
            SHOW_IF(mark_unusual_key_derivation(w, &address_params->stakingKeyPath));
            break;

        case BASE_PAYMENT_SCRIPT_STAKE_SCRIPT:
        case POINTER_SCRIPT:
        case ENTERPRISE_SCRIPT:
        case REWARD_SCRIPT:
            // no paths in the address
            break;

        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unexpected address type in derive-address policy");
            break;
            // LCOV_EXCL_STOP
    }

    RETURN(successPolicy);
}

// Derive address and return it to the host
security_policy_t policyForReturnDeriveAddress(const address_params_t *address_params,
                                               warning_bits_t *w) {
    POLICY_INIT();
    // in expert mode, do not export addresses without permission
    security_policy_t policy = is_expert_mode() ? POLICY_SHOW : POLICY_HIDE;

    RETURN(_policyForDeriveAddress(address_params, policy, w));
}

security_policy_t policyForDeriveNativeScriptHashDevicePubkey(const bip44_path_t *path,
                                                              warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(path != NULL);

    // Keep permissive behavior for all recognized Cardano path classes.
    // Reject only malformed/unrecognized (PATH_INVALID) paths.
    switch (bip44_classifyPath(path)) {
        case PATH_INVALID:
            DENY();
            break;
        default:
            SHOW();
            break;
    }

    DENY();  // should not be reached
}

// Derive address and show it to the user
security_policy_t policyForShowDeriveAddress(const address_params_t *address_params,
                                             warning_bits_t *w) {
    POLICY_INIT();
    RETURN(_policyForDeriveAddress(address_params, POLICY_SHOW, w));
}

// true iff network is the standard mainnet or testnet
static bool isNetworkUsual(uint32_t networkId, uint32_t protocolMagic) {
    if (networkId == MAINNET_NETWORK_ID && protocolMagic == MAINNET_PROTOCOL_MAGIC) {
        return true;
    }

    const bool knownTestnetProtocolMagic = protocolMagic == TESTNET_PROTOCOL_MAGIC_LEGACY ||
                                           protocolMagic == TESTNET_PROTOCOL_MAGIC_PREPROD ||
                                           protocolMagic == TESTNET_PROTOCOL_MAGIC_PREVIEW;

    if (networkId == TESTNET_NETWORK_ID && knownTestnetProtocolMagic) {
        return true;
    }

    return false;
}

// true iff tx contains an element with network id
static bool isTxNetworkIdVerifiable(bool includeNetworkId,
                                    uint32_t numOutputs,
                                    bool includeCollateralOutput,
                                    uint32_t numWithdrawals,
                                    sign_tx_signingmode_t txSigningMode) {
    if (includeNetworkId) return true;

    if (numOutputs > 0) return true;
    if (includeCollateralOutput) return true;
    if (numWithdrawals > 0) return true;

    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
            // pool registration certificate contains pool reward account
            return true;

        default:
            return false;
    }
}

bool shouldShowNetworkDetails(const tx_params_t *txParams) {
    ASSERT(txParams != NULL);

    const bool is_network_id_verifiable = isTxNetworkIdVerifiable(txParams->includeNetworkId,
                                                                  txParams->num_outputs,
                                                                  txParams->includeCollateralOutput,
                                                                  txParams->num_withdrawals,
                                                                  txParams->txSigningMode);
    if (!is_network_id_verifiable) {
        // no point in showing the given network id because tx body
        // does not have any elements containing it
        return false;
    }

    // we hide usual network details to avoid bothering users
    return !isNetworkUsual(txParams->networkId, txParams->protocolMagic);
}

static inline void set_missing_collateral_warning(warning_bits_t *w,
                                                  sign_tx_signingmode_t signingMode,
                                                  uint32_t numCollateralInputs,
                                                  bool includesScriptDataHash) {
    const bool collateralExpected =
        (signingMode == SIGN_TX_SIGNINGMODE_PLUTUS) ||
        (signingMode == SIGN_TX_SIGNINGMODE_UNRESTRICTED && includesScriptDataHash);
    if (collateralExpected && (numCollateralInputs == 0)) {
        warning_bits_set(w, WARNING_BIT_PLUTUS_MISSING_COLLATERAL);
    }
}

static inline void set_unknown_collateral_warning(warning_bits_t *w,
                                                  sign_tx_signingmode_t signingMode,
                                                  uint32_t numCollateralInputs,
                                                  bool includesTotalCollateral) {
    const bool collateralExpected =
        (signingMode == SIGN_TX_SIGNINGMODE_PLUTUS) ||
        (signingMode == SIGN_TX_SIGNINGMODE_UNRESTRICTED && numCollateralInputs > 0);
    if (collateralExpected && (!includesTotalCollateral)) {
        warning_bits_set(w, WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL);
    }
}

static inline void set_missing_script_data_hash_warning(warning_bits_t *w,
                                                        sign_tx_signingmode_t signingMode,
                                                        bool includesScriptDataHash) {
    const bool scriptDataHashExpected = (signingMode == SIGN_TX_SIGNINGMODE_PLUTUS);
    if (scriptDataHashExpected && !includesScriptDataHash) {
        warning_bits_set(w, WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH);
    }
}

static inline void set_network_not_verifiable_warning(warning_bits_t *w,
                                                      bool includeNetworkId,
                                                      uint32_t numOutputs,
                                                      bool includeCollateralOutput,
                                                      uint32_t numWithdrawals,
                                                      sign_tx_signingmode_t txSigningMode) {
    if (!isTxNetworkIdVerifiable(includeNetworkId,
                                 numOutputs,
                                 includeCollateralOutput,
                                 numWithdrawals,
                                 txSigningMode)) {
        warning_bits_set(w, WARNING_BIT_NETWORK_NOT_VERIFIABLE);
    }
}

static inline void set_network_unusual_warning(warning_bits_t *w,
                                               uint32_t networkId,
                                               uint32_t protocolMagic) {
    if (!isNetworkUsual(networkId, protocolMagic)) {
        warning_bits_set(w, WARNING_BIT_NETWORK_UNUSUAL);
    }
}

// Initiate transaction signing
security_policy_t policyForSignTxInit(const tx_params_t *txParams, warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(txParams != NULL);
    DENY_UNLESS(isValidNetworkId(txParams->networkId));
    // Deny shelley mainnet with weird byron protocol magic
    DENY_IF(txParams->networkId == MAINNET_NETWORK_ID &&
            txParams->protocolMagic != MAINNET_PROTOCOL_MAGIC);
    // Note: testnets can still use byron mainnet protocol magic so we can't deny the opposite
    // direction

    // At least one input is required for certificate replay protection:
    // the input uniquely identifies the transaction by consuming a UTxO.
    DENY_IF(txParams->num_inputs == 0);

    // certain combinations of tx body elements are forbidden
    // mostly because of potential cross-witnessing
    switch (txParams->txSigningMode) {
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
            // necessary to avoid intermingling witnesses from several certs
            DENY_UNLESS(txParams->num_certificates == 1);

            // witnesses for owners and withdrawals are the same
            // we forbid withdrawals so that users cannot be tricked into witnessing
            // something unintentionally (e.g. an owner given by the stake key hash)
            DENY_UNLESS(txParams->num_withdrawals == 0);

            // mint must not be combined with pool registration certificates
            DENY_IF(txParams->num_mint_asset_groups > 0);

            // no Plutus elements for pool registrations
            DENY_IF(txParams->includeScriptDataHash);
            DENY_IF(txParams->num_collateral_inputs > 0);
            DENY_IF(txParams->num_required_signers > 0);
            DENY_IF(txParams->includeCollateralOutput);
            DENY_IF(txParams->includeTotalCollateral);
            DENY_IF(txParams->num_reference_inputs > 0);

            // no voting, treasuries, donations for pool registrations
            // we don't need them and we want to avoid overlap in witnesses
            DENY_IF(txParams->num_voters > 0);
            DENY_IF(txParams->includeTreasury);
            DENY_IF(txParams->includeDonation);
            break;

        case SIGN_TX_SIGNINGMODE_ORDINARY:
        case SIGN_TX_SIGNINGMODE_MULTISIG:
            // collateral inputs are allowed only in PLUTUS_TX
            DENY_IF(txParams->num_collateral_inputs > 0);
            DENY_IF(txParams->includeCollateralOutput);
            DENY_IF(txParams->includeTotalCollateral);
            DENY_IF(txParams->num_reference_inputs > 0);
            break;

        case SIGN_TX_SIGNINGMODE_PLUTUS:
            break;

        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            DENY_UNLESS(is_expert_mode());
            warning_bits_set(w, WARNING_BIT_UNRESTRICTED_SIGNING);
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    // w are collected here; UI machine decides which screens to show
    set_network_not_verifiable_warning(w,
                                       txParams->includeNetworkId,
                                       txParams->num_outputs,
                                       txParams->includeCollateralOutput,
                                       txParams->num_withdrawals,
                                       txParams->txSigningMode);
    set_network_unusual_warning(w, txParams->networkId, txParams->protocolMagic);
    set_missing_collateral_warning(w,
                                   txParams->txSigningMode,
                                   txParams->num_collateral_inputs,
                                   txParams->includeScriptDataHash);
    set_unknown_collateral_warning(w,
                                   txParams->txSigningMode,
                                   txParams->num_collateral_inputs,
                                   txParams->includeTotalCollateral);
    set_missing_script_data_hash_warning(w,
                                         txParams->txSigningMode,
                                         txParams->includeScriptDataHash);

    SHOW();
}

security_policy_t policyForSignTxSwapInit(const tx_params_t *txParams, warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(txParams != NULL);

    warning_bits_t normal_policy_warnings = 0;
    DENY_IF(policyForSignTxInit(txParams, &normal_policy_warnings) == POLICY_DENY);

    DENY_UNLESS(txParams->txSigningMode == SIGN_TX_SIGNINGMODE_ORDINARY);
    DENY_UNLESS(txParams->networkId == MAINNET_NETWORK_ID);
    DENY_UNLESS(txParams->protocolMagic == MAINNET_PROTOCOL_MAGIC);
    DENY_IF(txParams->num_inputs == 0);
    DENY_IF(txParams->num_outputs == 0);

    DENY_IF(txParams->num_certificates != 0);
    DENY_IF(txParams->num_withdrawals != 0);
    DENY_IF(txParams->includeAuxDataHash);
    DENY_IF(txParams->num_mint_asset_groups != 0);
    DENY_IF(txParams->includeScriptDataHash);
    DENY_IF(txParams->num_collateral_inputs != 0);
    DENY_IF(txParams->num_required_signers != 0);
    DENY_IF(txParams->includeCollateralOutput);
    DENY_IF(txParams->includeTotalCollateral);
    DENY_IF(txParams->num_reference_inputs != 0);
    DENY_IF(txParams->num_voters != 0);
    DENY_IF(txParams->includeTreasury);
    DENY_IF(txParams->includeDonation);

    HIDE();
}

// ======================================= Inputs =======================================

security_policy_t policyForSignTxInput(sign_tx_signingmode_t txSigningMode,
                                       const tx_input_t *input MARK_UNUSED,
                                       warning_bits_t *w) {
    POLICY_INIT();
    // Input contents are intentionally ignored by policy; only signing mode affects visibility.
    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_PLUTUS:
            // user should check inputs because they are not interchangeable for Plutus scripts
            SHOW_IF(is_expert_mode());
            HIDE();
            break;

        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            SHOW();
            break;

        case SIGN_TX_SIGNINGMODE_ORDINARY:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
        case SIGN_TX_SIGNINGMODE_MULTISIG:
            // inputs are not interesting for the user (transferred funds are shown in the outputs)
            HIDE();
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// ======================================= Outputs =======================================

static bool is_addressBytes_suitable_for_tx_output(const uint8_t *addressBuffer,
                                                   size_t addressSize,
                                                   const uint8_t networkId,
                                                   const uint32_t protocolMagic
                                                   __attribute__((unused))) {
    ASSERT(addressSize < BUFFER_SIZE_PARANOIA);
    ASSERT(addressSize >= 1);

#define CHECK(cond) \
    if (!(cond)) return false

    const address_type_t addressType = getAddressType(addressBuffer[0]);
    {
        // check address type and network identification
        switch (addressType) {
            case REWARD_KEY:
            case REWARD_SCRIPT:
                // outputs may not contain reward addresses
                return false;

            case BYRON: {
                uint32_t extractedMagic;
                CHECK(extractProtocolMagic(addressBuffer, addressSize, &extractedMagic));
                CHECK(extractedMagic == protocolMagic);
                break;
            }

            default: {
                // unsupported address types are rejected
                CHECK(isSupportedAddressType(addressType));
                // shelley types allowed in output
                const uint8_t addressNetworkId = getNetworkId(addressBuffer[0]);
                CHECK(addressNetworkId == networkId);
                break;
            }
        }
    }
    {
        // check address length
        switch (addressType) {
            case BASE_PAYMENT_KEY_STAKE_KEY:
                CHECK(addressSize == 1 + ADDRESS_KEY_HASH_LENGTH + ADDRESS_KEY_HASH_LENGTH);
                break;
            case BASE_PAYMENT_KEY_STAKE_SCRIPT:
                CHECK(addressSize == 1 + ADDRESS_KEY_HASH_LENGTH + SCRIPT_HASH_LENGTH);
                break;
            case BASE_PAYMENT_SCRIPT_STAKE_KEY:
                CHECK(addressSize == 1 + SCRIPT_HASH_LENGTH + ADDRESS_KEY_HASH_LENGTH);
                break;
            case BASE_PAYMENT_SCRIPT_STAKE_SCRIPT:
                CHECK(addressSize == 1 + SCRIPT_HASH_LENGTH + SCRIPT_HASH_LENGTH);
                break;

            case ENTERPRISE_KEY:
                CHECK(addressSize == 1 + ADDRESS_KEY_HASH_LENGTH);
                break;
            case ENTERPRISE_SCRIPT:
                CHECK(addressSize == 1 + SCRIPT_HASH_LENGTH);
                break;

            default:  // not meaningful or complicated to verify address length in the other cases
                break;
        }
    }
    return true;
#undef CHECK
}

static bool contains_forbidden_plutus_elements(const tx_output_description_t *output,
                                               sign_tx_signingmode_t txSigningMode) {
    if (output->includeDatum || output->includeRefScript) {
        // no Plutus elements for pool registration, only allow in other modes
        switch (txSigningMode) {
            case SIGN_TX_SIGNINGMODE_ORDINARY:
            case SIGN_TX_SIGNINGMODE_MULTISIG:
            case SIGN_TX_SIGNINGMODE_PLUTUS:
            case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
                break;

            case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
            case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
                return true;

            // LCOV_EXCL_START
            default:
                ASSERT(false);
                return true;
                // LCOV_EXCL_STOP
        }
    }

    return false;
}

static bool needsMissingDatumWarning(const tx_output_destination_t *destination,
                                     bool includeDatum) {
    const bool mightRequireDatum =
        determinePaymentChoice(getDestinationAddressType(destination)) == PAYMENT_SCRIPT_HASH;
    return mightRequireDatum && !includeDatum;
}

// For each transaction output with third-party address
static security_policy_t policyForSignTxOutputAddressBytes(const tx_output_description_t *output,
                                                           sign_tx_signingmode_t txSigningMode,
                                                           const uint8_t networkId,
                                                           const uint32_t protocolMagic,
                                                           warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(output != NULL);
    ASSERT(output->destination.type == DESTINATION_THIRD_PARTY);
    const uint8_t *addressBuffer = output->destination.address.buffer;
    const size_t addressSize = output->destination.address.length;

    DENY_UNLESS(is_addressBytes_suitable_for_tx_output(addressBuffer,
                                                       addressSize,
                                                       networkId,
                                                       protocolMagic));

    DENY_IF(contains_forbidden_plutus_elements(output, txSigningMode));

    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
            // all the funds are provided by the operator
            // and thus outputs are irrelevant to the owner (even those having tokens or datum hash)
            HIDE();
            break;

        case SIGN_TX_SIGNINGMODE_ORDINARY:
        case SIGN_TX_SIGNINGMODE_MULTISIG:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
        case SIGN_TX_SIGNINGMODE_PLUTUS:
        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            // utxo on a Plutus script address without datum hash is unspendable
            // but we can't DENY because it is valid for native scripts
            if (needsMissingDatumWarning(&output->destination, output->includeDatum)) {
                warning_bits_set(w, WARNING_BIT_OUTPUT_MISSING_DATUM);
            }
            // we always show third-party output addresses
            SHOW();
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

static bool is_address_params_suitable_for_tx_output(const address_params_t *params,
                                                     const uint8_t networkId,
                                                     const uint32_t protocolMagic,
                                                     bool enforceSingleAccount) {
#define CHECK(cond) \
    if (!(cond)) return false
    CHECK(isValidAddressParams(params));

    // only allow valid address types
    // and check network identification as appropriate
    switch (params->type) {
        case REWARD_KEY:
        case REWARD_SCRIPT:
            // outputs must not contain reward addresses (true not only for HW wallets)
            return false;

        case BYRON:
            CHECK(params->protocolMagic == protocolMagic);
            break;

        default:  // all Shelley types allowed in output
            CHECK(params->networkId == networkId);
            break;
    }

    {
        // outputs to a different account within this HW wallet,
        // or to a different wallet, should be given as raw address bytes
        // this captures the essence of a change output: money stays
        // on an address where payment is fully controlled by this device
        // Note: if we allowed script hash in payment part, we must add a warning
        // for missing datum (see policyForSignTxOutputAddressBytes)
        CHECK(determinePaymentChoice(params->type) == PAYMENT_PATH);
        ASSERT(addressParams_getPaymentPartType(params) == PAYMENT_PART_KEY_PATH);
        if (enforceSingleAccount) {
            CHECK(!violatesSingleAccountOrStoreIt(&params->paymentKeyPath));
        }
    }

    return true;
#undef CHECK
}

// For each output given by payment derivation path
static security_policy_t policyForSignTxOutputAddressParams(const tx_output_description_t *output,
                                                            sign_tx_signingmode_t txSigningMode,
                                                            const uint8_t networkId,
                                                            const uint32_t protocolMagic,
                                                            warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(output != NULL);
    ASSERT(output->destination.type == DESTINATION_DEVICE_OWNED);
    const address_params_t *params = &output->destination.params;

    const bool enforceSingleAccount = (txSigningMode != SIGN_TX_SIGNINGMODE_UNRESTRICTED);
    DENY_UNLESS(is_address_params_suitable_for_tx_output(params,
                                                         networkId,
                                                         protocolMagic,
                                                         enforceSingleAccount));

    DENY_IF(contains_forbidden_plutus_elements(output, txSigningMode));

    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
        case SIGN_TX_SIGNINGMODE_ORDINARY: {
            if (!is_standard_base_address(params)) {
                SHOW_IF(mark_unusual_key_derivation(w, &params->paymentKeyPath));
                if (addressParams_getStakingPartType(params) == STAKING_PART_KEY_PATH) {
                    SHOW_IF(mark_unusual_key_derivation(w, &params->stakingKeyPath));
                }
                SHOW();
            }

            // outputs (eUTXOs) with datum or ref script are not interchangeable
            if (output->includeDatum || output->includeRefScript) {
                // can't happen for SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR
                SHOW_IF(is_expert_mode());
            }

            // it is safe to hide the remaining change outputs
            HIDE();
            break;
        }

        case SIGN_TX_SIGNINGMODE_MULTISIG: {
            // for simplicity, all outputs should be given as external addresses;
            // generally, more than one party is needed to sign
            // payment from a multisig address, so we do not expect
            // there will be 1852 outputs (that would be considered change)
            DENY();
            break;
        }

        case SIGN_TX_SIGNINGMODE_PLUTUS: {
            // the output could affect script validation so it must not be entirely hidden
            // Note: if we relax this, some of the above restrictions may apply
            SHOW_IF(is_expert_mode());
            HIDE();
            break;
        }

        case SIGN_TX_SIGNINGMODE_UNRESTRICTED: {
            // Keep warning-triggered display explicit even though unrestricted currently shows.
            SHOW_IF(mark_unusual_key_derivation(w, &params->paymentKeyPath));
            if (addressParams_getStakingPartType(params) == STAKING_PART_KEY_PATH) {
                SHOW_IF(mark_unusual_key_derivation(w, &params->stakingKeyPath));
            }
            SHOW();
            break;
        }

        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER: {
            // we forbid these to avoid leaking information
            // (since the outputs are not shown, the user is unaware of what addresses are being
            // derived) it also makes the tx signing faster if all outputs are given as addresses
            DENY();
            break;
        }

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForSignTxOutput(const tx_output_description_t *output,
                                        sign_tx_signingmode_t txSigningMode,
                                        const uint8_t networkId,
                                        const uint32_t protocolMagic,
                                        warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(output != NULL);

    switch (output->destination.type) {
        case DESTINATION_THIRD_PARTY:
            RETURN(policyForSignTxOutputAddressBytes(output,
                                                     txSigningMode,
                                                     networkId,
                                                     protocolMagic,
                                                     w));
        case DESTINATION_DEVICE_OWNED:
            RETURN(policyForSignTxOutputAddressParams(output,
                                                      txSigningMode,
                                                      networkId,
                                                      protocolMagic,
                                                      w));
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            break;
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForSignTxSwapOutput(const tx_output_description_t *output,
                                            sign_tx_signingmode_t txSigningMode,
                                            const uint8_t networkId,
                                            const uint32_t protocolMagic,
                                            warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(output != NULL);

    DENY_UNLESS(txSigningMode == SIGN_TX_SIGNINGMODE_ORDINARY);
    DENY_UNLESS(networkId == MAINNET_NETWORK_ID);
    DENY_UNLESS(protocolMagic == MAINNET_PROTOCOL_MAGIC);

    warning_bits_t normal_policy_warnings = 0;
    security_policy_t normal_output_policy = policyForSignTxOutput(output,
                                                                   txSigningMode,
                                                                   networkId,
                                                                   protocolMagic,
                                                                   &normal_policy_warnings);
    DENY_IF(normal_output_policy == POLICY_DENY);
    DENY_IF(normal_policy_warnings != 0);

    DENY_IF(output->numAssetGroups != 0);
    DENY_IF(output->includeDatum);
    DENY_IF(output->includeRefScript);

    switch (output->destination.type) {
        case DESTINATION_THIRD_PARTY:
            HIDE();
            break;

        case DESTINATION_DEVICE_OWNED:
            // In swap mode there is no Cardano-app UI, so change outputs must be
            // boring enough for the normal policy to hide.
            DENY_UNLESS(normal_output_policy == POLICY_HIDE);
            HIDE();
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            break;
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForSignTxOutputDatumHash(security_policy_t outputPolicy,
                                                 warning_bits_t *w) {
    POLICY_INIT();
    switch (outputPolicy) {
        // LCOV_EXCL_START
        case POLICY_DENY:
            LEDGER_ASSERT(false, "Output policy DENY should not reach datum policy");
            break;
        // LCOV_EXCL_STOP
        case POLICY_SHOW:
            SHOW();
            break;
        case POLICY_HIDE:
            HIDE();
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            DENY();
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForSignTxOutputRefScript(security_policy_t outputPolicy,
                                                 warning_bits_t *w) {
    POLICY_INIT();
    switch (outputPolicy) {
        // LCOV_EXCL_START
        case POLICY_DENY:
            LEDGER_ASSERT(false, "Output policy DENY should not reach ref script policy");
            break;
        // LCOV_EXCL_STOP
        case POLICY_SHOW:
            SHOW_IF(is_expert_mode());
            HIDE();
            break;
        case POLICY_HIDE:
            HIDE();
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            DENY();
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// ======================================= Collateral Output =======================================

static bool is_address_suitable_for_collateral_output(const tx_output_description_t *output) {
    switch (getDestinationAddressType(&output->destination)) {
        case BASE_PAYMENT_KEY_STAKE_KEY:
        case BASE_PAYMENT_KEY_STAKE_SCRIPT:
        case POINTER_KEY:
        case ENTERPRISE_KEY:
            // we only allow addresses with payment controlled by key
            return true;

        default:
            return false;
    }
}

static security_policy_t policyForSignTxCollateralOutputAddressBytes(
    const tx_output_description_t *output,
    sign_tx_signingmode_t txSigningMode,
    const uint8_t networkId,
    const uint32_t protocolMagic,
    warning_bits_t *w) {
    POLICY_INIT();
    // WARNING: policies for collateral inputs, collateral return output and total collateral are
    // interdependent

    ASSERT(output->destination.type == DESTINATION_THIRD_PARTY);
    const uint8_t *addressBuffer = output->destination.address.buffer;
    const size_t addressSize = output->destination.address.length;

    DENY_UNLESS(is_addressBytes_suitable_for_tx_output(addressBuffer,
                                                       addressSize,
                                                       networkId,
                                                       protocolMagic));
    DENY_UNLESS(is_address_suitable_for_collateral_output(output));

    DENY_IF(output->includeDatum);
    DENY_IF(output->includeRefScript);

    DENY_UNLESS(txSigningMode == SIGN_TX_SIGNINGMODE_PLUTUS ||
                txSigningMode == SIGN_TX_SIGNINGMODE_UNRESTRICTED);

    SHOW();
}

static security_policy_t policyForSignTxCollateralOutputAddressParams(
    const tx_output_description_t *output,
    sign_tx_signingmode_t txSigningMode,
    const uint8_t networkId,
    const uint32_t protocolMagic,
    bool isTotalCollateralIncluded,
    warning_bits_t *w) {
    POLICY_INIT();
    // WARNING: policies for collateral inputs, collateral return output and total collateral are
    // interdependent

    ASSERT(output->destination.type == DESTINATION_DEVICE_OWNED);
    const address_params_t *params = &output->destination.params;

    const bool enforceSingleAccount = (txSigningMode != SIGN_TX_SIGNINGMODE_UNRESTRICTED);
    DENY_UNLESS(is_address_params_suitable_for_tx_output(params,
                                                         networkId,
                                                         protocolMagic,
                                                         enforceSingleAccount));

    DENY_UNLESS(is_address_suitable_for_collateral_output(output));

    DENY_IF(output->includeDatum);
    DENY_IF(output->includeRefScript);

    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_PLUTUS:
            if (isTotalCollateralIncluded) {
                // change outputs can be hidden; show when paths look unusual
                if (!is_standard_base_address(params)) {
                    SHOW_IF(mark_unusual_key_derivation(w, &params->paymentKeyPath));
                    if (addressParams_getStakingPartType(params) == STAKING_PART_KEY_PATH) {
                        SHOW_IF(mark_unusual_key_derivation(w, &params->stakingKeyPath));
                    }
                    SHOW();
                } else {
                    HIDE();
                }
            } else {
                // collateral output ADA must be shown, so the whole output must be shown
                SHOW();
            }
            break;

        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            // Keep warning-triggered display explicit even though unrestricted currently shows.
            SHOW_IF(mark_unusual_key_derivation(w, &params->paymentKeyPath));
            if (addressParams_getStakingPartType(params) == STAKING_PART_KEY_PATH) {
                SHOW_IF(mark_unusual_key_derivation(w, &params->stakingKeyPath));
            }
            SHOW();
            break;

        // LCOV_EXCL_START
        default:
            // should be used only in Plutus transactions
            ASSERT(false);
            break;
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForSignTxCollateralOutputAddress(const tx_output_description_t *output,
                                                         sign_tx_signingmode_t txSigningMode,
                                                         const uint8_t networkId,
                                                         const uint32_t protocolMagic,
                                                         bool isTotalCollateralIncluded,
                                                         warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(output != NULL);

    switch (output->destination.type) {
        case DESTINATION_THIRD_PARTY:
            RETURN(policyForSignTxCollateralOutputAddressBytes(output,
                                                               txSigningMode,
                                                               networkId,
                                                               protocolMagic,
                                                               w));
        case DESTINATION_DEVICE_OWNED:
            RETURN(policyForSignTxCollateralOutputAddressParams(output,
                                                                txSigningMode,
                                                                networkId,
                                                                protocolMagic,
                                                                isTotalCollateralIncluded,
                                                                w));
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            break;
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForSignTxCollateralOutputAdaAmount(security_policy_t outputPolicy,
                                                           sign_tx_signingmode_t txSigningMode,
                                                           bool isTotalCollateralPresent,
                                                           warning_bits_t *w) {
    POLICY_INIT();
    // WARNING: policies for collateral inputs, collateral return output and total collateral are
    // interdependent
    LEDGER_ASSERT(outputPolicy != POLICY_DENY,
                  "Collateral ADA sub-policy called with DENY output policy");

    if (outputPolicy == POLICY_HIDE) {
        // output not shown, so none of its elements should be shown
        HIDE();
    }

    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_PLUTUS:
        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            // ADA amount is calculable from total collateral
            // but only expert users are to be bothered by a possible collateral loss
            SHOW_IF(!isTotalCollateralPresent && is_expert_mode());
            HIDE();
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForSignTxCollateralOutputTokens(security_policy_t outputPolicy,
                                                        sign_tx_signingmode_t txSigningMode,
                                                        const tx_output_description_t *output,
                                                        warning_bits_t *w) {
    POLICY_INIT();
    // WARNING: policies for collateral inputs, collateral return output and total collateral are
    // interdependent
    ASSERT(output != NULL);
    LEDGER_ASSERT(outputPolicy != POLICY_DENY,
                  "Collateral token sub-policy called with DENY output policy");

    if (outputPolicy == POLICY_HIDE) {
        // output not shown, so none of its elements should be shown
        HIDE();
    }

    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_PLUTUS:
        case SIGN_TX_SIGNINGMODE_UNRESTRICTED: {
            // for non-change outputs, control over the collateral tokens is potentially transferred
            // to another party, so we should show them in the expert mode (non-expert users are
            // supposed to not be interested in any collateral loss)
            const bool lossOfControl = (output->destination.type != DESTINATION_DEVICE_OWNED);
            SHOW_IF(lossOfControl && is_expert_mode());
            HIDE();
            break;
        }

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// ======================================= Fee =======================================

security_policy_t policyForSignTxFee(sign_tx_signingmode_t txSigningMode,
                                     uint64_t fee,
                                     warning_bits_t *w) {
    POLICY_INIT();

    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
        case SIGN_TX_SIGNINGMODE_ORDINARY:
        case SIGN_TX_SIGNINGMODE_MULTISIG:
        case SIGN_TX_SIGNINGMODE_PLUTUS:
        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            // always show the fee if it is paid by the signer
            if (fee > HIGH_FEE_WARNING_THRESHOLD) {
                warning_bits_set(w, WARNING_BIT_HIGH_FEE);
            }
            SHOW();
            break;

        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
            // fees are paid by the operator and are thus irrelevant for owners
            HIDE();
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// ======================================= TTL =======================================

security_policy_t policyForSignTxTtl(uint64_t ttl MARK_UNUSED, warning_bits_t *w) {
    POLICY_INIT();
    // TTL value is intentionally ignored; only expert mode controls whether TTL is shown.
    SHOW_IF(is_expert_mode());
    HIDE();
}

// ======================================= Certificates =======================================

// applicable to credentials that are witnessed in this tx
static bool _forbiddenCredential(sign_tx_signingmode_t txSigningMode,
                                 const ext_credential_t *credential) {
    // certain combinations of tx signing mode and credential type are not allowed
    // either because they don't make sense or are dangerous
    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_MULTISIG:
            switch (credential->type) {
                case EXT_CREDENTIAL_KEY_PATH:
                case EXT_CREDENTIAL_KEY_HASH:
                    // everything is expected to be governed by native scripts
                    return true;
                case EXT_CREDENTIAL_SCRIPT_HASH:
                    break;
                // LCOV_EXCL_START
                default:
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;

        case SIGN_TX_SIGNINGMODE_PLUTUS:
        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            // everything allowed, txs are too complex for a HW wallet to understand
            // and there might be third-party key hashes in the tx
            break;

        case SIGN_TX_SIGNINGMODE_ORDINARY:
            switch (credential->type) {
                case EXT_CREDENTIAL_KEY_HASH:
                case EXT_CREDENTIAL_SCRIPT_HASH:
                    // keys must be given by path, otherwise the user does not know
                    // if the hash corresponds to some of his keys,
                    // and might inadvertently sign several certificates with a single witness
                    return true;
                case EXT_CREDENTIAL_KEY_PATH:
                    break;
                // LCOV_EXCL_START
                default:
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;

        // LCOV_EXCL_START
        default:
            // this should not be called in POOL_REGISTRATION signing modes
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    return false;
}

static security_policy_t _policyForSignTxCertificateStakeCredential(
    sign_tx_signingmode_t txSigningMode,
    const ext_credential_t *stakeCredential,
    warning_bits_t *w) {
    POLICY_INIT();
    DENY_IF(txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER ||
            txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR);
    DENY_IF(_forbiddenCredential(txSigningMode, stakeCredential));

    switch (stakeCredential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            switch (txSigningMode) {
                case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
                    DENY_UNLESS(is_staking_credential_key_path_allowed(txSigningMode,
                                                                       &stakeCredential->keyPath));
                    break;

                case SIGN_TX_SIGNINGMODE_ORDINARY:
                case SIGN_TX_SIGNINGMODE_MULTISIG:
                case SIGN_TX_SIGNINGMODE_PLUTUS:
                    DENY_UNLESS(is_staking_credential_key_path_allowed(txSigningMode,
                                                                       &stakeCredential->keyPath));
                    DENY_IF(violatesSingleAccountOrStoreIt(&stakeCredential->keyPath));
                    break;

                // LCOV_EXCL_START
                default:
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;
        case EXT_CREDENTIAL_KEY_HASH:
        case EXT_CREDENTIAL_SCRIPT_HASH:
            // the rest is OK, forbidden credentials have been dealt with above
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    SHOW();
}

static inline security_policy_t _policyForSignTxCertificateDRep(sign_tx_signingmode_t txSigningMode,
                                                                const ext_drep_t *drep,
                                                                warning_bits_t *w) {
    POLICY_INIT();
    DENY_IF(txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER ||
            txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR);
    switch (drep->type) {
        case EXT_DREP_KEY_PATH:
            DENY_UNLESS(bip44_isDRepKeyPath(&drep->keyPath));
            switch (txSigningMode) {
                case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
                    break;

                case SIGN_TX_SIGNINGMODE_ORDINARY:
                case SIGN_TX_SIGNINGMODE_MULTISIG:
                case SIGN_TX_SIGNINGMODE_PLUTUS:
                    DENY_IF(violatesSingleAccountOrStoreIt(&drep->keyPath));
                    break;

                // LCOV_EXCL_START
                default:
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;

        case EXT_DREP_KEY_HASH:
        case EXT_DREP_SCRIPT_HASH:
        case EXT_DREP_ABSTAIN:
        case EXT_DREP_NO_CONFIDENCE:
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    SHOW();
}

security_policy_t policyForSignTxCertificateStaking(sign_tx_signingmode_t txSigningMode,
                                                    const certificate_type_t certificateType,
                                                    const ext_credential_t *stakeCredential,
                                                    warning_bits_t *w) {
    POLICY_INIT();
    DENY_IF(txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER ||
            txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR);
    switch (certificateType) {
        case CERTIFICATE_STAKE_REGISTRATION:
        case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
        case CERTIFICATE_STAKE_DEREGISTRATION:
        case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY:
        case CERTIFICATE_STAKE_DELEGATION:
            // this policy only applies to these types
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    RETURN(_policyForSignTxCertificateStakeCredential(txSigningMode, stakeCredential, w));
}

security_policy_t policyForSignTxCertificateVoteDelegation(sign_tx_signingmode_t txSigningMode,
                                                           const ext_credential_t *stakeCredential,
                                                           const ext_drep_t *drep,
                                                           warning_bits_t *w) {
    POLICY_INIT();
    RETURN(combine_security_policies(
        _policyForSignTxCertificateDRep(txSigningMode, drep, w),
        _policyForSignTxCertificateStakeCredential(txSigningMode, stakeCredential, w)));
}

security_policy_t policyForSignTxCertificateStakePoolAndDRepDelegation(
    sign_tx_signingmode_t txSigningMode,
    const ext_credential_t *stakeCredential,
    const ext_drep_t *drep,
    warning_bits_t *w) {
    POLICY_INIT();
    RETURN(combine_security_policies(
        _policyForSignTxCertificateDRep(txSigningMode, drep, w),
        _policyForSignTxCertificateStakeCredential(txSigningMode, stakeCredential, w)));
}

security_policy_t policyForSignTxCertificateAccountRegistrationDelegationToStakePool(
    sign_tx_signingmode_t txSigningMode,
    const ext_credential_t *stakeCredential,
    warning_bits_t *w) {
    POLICY_INIT();
    DENY_IF(txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER ||
            txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR);
    RETURN(_policyForSignTxCertificateStakeCredential(txSigningMode, stakeCredential, w));
}

security_policy_t policyForSignTxCertificateAccountRegistrationDelegationToDRep(
    sign_tx_signingmode_t txSigningMode,
    const ext_credential_t *stakeCredential,
    const ext_drep_t *drep,
    warning_bits_t *w) {
    POLICY_INIT();
    RETURN(combine_security_policies(
        _policyForSignTxCertificateDRep(txSigningMode, drep, w),
        _policyForSignTxCertificateStakeCredential(txSigningMode, stakeCredential, w)));
}

security_policy_t policyForSignTxCertificateAccountRegistrationDelegationToStakePoolAndDRep(
    sign_tx_signingmode_t txSigningMode,
    const ext_credential_t *stakeCredential,
    const ext_drep_t *drep,
    warning_bits_t *w) {
    POLICY_INIT();
    RETURN(combine_security_policies(
        _policyForSignTxCertificateDRep(txSigningMode, drep, w),
        _policyForSignTxCertificateStakeCredential(txSigningMode, stakeCredential, w)));
}

security_policy_t policyForSignTxCertificateCommitteeAuth(sign_tx_signingmode_t txSigningMode,
                                                          const ext_credential_t *coldCredential,
                                                          const ext_credential_t *hotCredential,
                                                          warning_bits_t *w) {
    POLICY_INIT();
    DENY_IF(txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER ||
            txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR);
    DENY_IF(_forbiddenCredential(txSigningMode, coldCredential));

    switch (coldCredential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            DENY_UNLESS(bip44_isCommitteeColdKeyPath(&coldCredential->keyPath));
            switch (txSigningMode) {
                case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
                    break;

                case SIGN_TX_SIGNINGMODE_ORDINARY:
                case SIGN_TX_SIGNINGMODE_MULTISIG:
                case SIGN_TX_SIGNINGMODE_PLUTUS:
                    DENY_IF(violatesSingleAccountOrStoreIt(&coldCredential->keyPath));
                    break;

                // LCOV_EXCL_START
                default:
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;

        case EXT_CREDENTIAL_KEY_HASH:
        case EXT_CREDENTIAL_SCRIPT_HASH:
            // the rest is OK, forbidden credentials have been dealt with above
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    switch (hotCredential->type) {
        case EXT_CREDENTIAL_SCRIPT_HASH:
        case EXT_CREDENTIAL_KEY_HASH:
            // keys might be governed outside of this device
            break;

        case EXT_CREDENTIAL_KEY_PATH:
            DENY_UNLESS(bip44_isCommitteeHotKeyPath(&hotCredential->keyPath));
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    SHOW();
}

security_policy_t policyForSignTxCertificateCommitteeResign(sign_tx_signingmode_t txSigningMode,
                                                            const ext_credential_t *coldCredential,
                                                            warning_bits_t *w) {
    POLICY_INIT();
    DENY_IF(txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER ||
            txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR);
    DENY_IF(_forbiddenCredential(txSigningMode, coldCredential));

    switch (coldCredential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            DENY_UNLESS(bip44_isCommitteeColdKeyPath(&coldCredential->keyPath));
            switch (txSigningMode) {
                case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
                    break;

                case SIGN_TX_SIGNINGMODE_ORDINARY:
                case SIGN_TX_SIGNINGMODE_MULTISIG:
                case SIGN_TX_SIGNINGMODE_PLUTUS:
                    DENY_IF(violatesSingleAccountOrStoreIt(&coldCredential->keyPath));
                    break;

                // LCOV_EXCL_START
                default:
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;

        case EXT_CREDENTIAL_KEY_HASH:
        case EXT_CREDENTIAL_SCRIPT_HASH:
            // the rest is OK, forbidden credentials have been dealt with above
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    SHOW();
}

security_policy_t policyForSignTxCertificateDRep(sign_tx_signingmode_t txSigningMode,
                                                 const ext_credential_t *dRepCredential,
                                                 warning_bits_t *w) {
    POLICY_INIT();
    DENY_IF(txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER ||
            txSigningMode == SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR);
    DENY_IF(_forbiddenCredential(txSigningMode, dRepCredential));

    switch (dRepCredential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            DENY_UNLESS(bip44_isDRepKeyPath(&dRepCredential->keyPath));
            switch (txSigningMode) {
                case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
                    break;

                case SIGN_TX_SIGNINGMODE_ORDINARY:
                case SIGN_TX_SIGNINGMODE_MULTISIG:
                case SIGN_TX_SIGNINGMODE_PLUTUS:
                    DENY_IF(violatesSingleAccountOrStoreIt(&dRepCredential->keyPath));
                    break;

                // LCOV_EXCL_START
                default:
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;

        case EXT_CREDENTIAL_KEY_HASH:
        case EXT_CREDENTIAL_SCRIPT_HASH:
            // the rest is OK, forbidden credentials have been dealt with above
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    SHOW();
}

security_policy_t policyForSignTxCertificateStakePoolRetirement(
    sign_tx_signingmode_t txSigningMode,
    const ext_credential_t *poolCredential,
    uint64_t epoch MARK_UNUSED,
    warning_bits_t *w) {
    POLICY_INIT();
    // Retirement epoch is intentionally not constrained by policy; witness authority is checked.
    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_ORDINARY:
        case SIGN_TX_SIGNINGMODE_PLUTUS:
        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            DENY_UNLESS(poolCredential->type == EXT_CREDENTIAL_KEY_PATH);
            DENY_UNLESS(bip44_isPoolColdKeyPath(&poolCredential->keyPath));
            SHOW();
            break;

        case SIGN_TX_SIGNINGMODE_MULTISIG:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            DENY();
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationInit(sign_tx_signingmode_t txSigningMode,
                                                           uint32_t numOwners,
                                                           uint32_t numRelays,
                                                           uint32_t numPathOwners,
                                                           warning_bits_t *w) {
    POLICY_INIT();
    if (numOwners == 0) {
        warning_bits_set(w, WARNING_BIT_POOL_REGISTRATION_NO_OWNERS);
    }
    if (numRelays == 0) {
        warning_bits_set(w, WARNING_BIT_POOL_REGISTRATION_NO_RELAYS);
    }
    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
            // Tightened vs legacy app-cardano repository (old Shelley app):
            // old flow accepted owner-mode certs with 0 path owners and only blocked witness later.
            // In the unified parser we already know owner cardinality at cert-init time, so we
            // enforce the intended invariant early: exactly one owner path for owner mode.
            DENY_IF(numOwners == 0);
            DENY_UNLESS(numPathOwners == 1);
            // In unified review, pool registration must always be visible.
            SHOW();
            break;

        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            // Operator mode never witnesses pool owners; all owners must be hashes.
            DENY_UNLESS(numPathOwners == 0);
            // In unified review, pool registration must always be visible.
            SHOW();
            break;

        case SIGN_TX_SIGNINGMODE_ORDINARY:
        case SIGN_TX_SIGNINGMODE_MULTISIG:
        case SIGN_TX_SIGNINGMODE_PLUTUS:
        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            DENY();
            break;

        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unexpected signing mode");
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationPoolId(sign_tx_signingmode_t txSigningMode,
                                                             const pool_id_t *poolId,
                                                             warning_bits_t *w) {
    POLICY_INIT();
    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
            // owner should see a hash
            DENY_UNLESS(poolId->keyReferenceType == KEY_REFERENCE_HASH);
            SHOW();
            break;

        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            // operator should see a path
            DENY_UNLESS(poolId->keyReferenceType == KEY_REFERENCE_PATH);
            SHOW();
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationVrfKey(sign_tx_signingmode_t txSigningMode,
                                                             warning_bits_t *w) {
    POLICY_INIT();
    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
            // not interesting for an owner, show only in expert mode
            SHOW_IF(is_expert_mode());
            HIDE();
            break;

        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            SHOW();
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationRewardAccount(
    sign_tx_signingmode_t txSigningMode,
    uint8_t networkId,
    const pool_reward_account_t *poolRewardAccount,
    warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(poolRewardAccount != NULL);
    switch (poolRewardAccount->keyReferenceType) {
        case KEY_REFERENCE_HASH: {
            ASSERT(poolRewardAccount->hashBuffer != NULL);
            const uint8_t header =
                getAddressHeader(poolRewardAccount->hashBuffer, REWARD_ACCOUNT_LENGTH);
            const address_type_t address_type = getAddressType(header);
            DENY_UNLESS(address_type == REWARD_KEY || address_type == REWARD_SCRIPT);
            DENY_UNLESS(getNetworkId(header) == networkId);
            break;
        }
        case KEY_REFERENCE_PATH:
            DENY_UNLESS(bip44_isOrdinaryStakingKeyPath(&poolRewardAccount->path));
            // we do not enforce single account, no benefit for pool registrations
            // and it is compatible with previous app versions
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            SHOW();
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationOwner(
    const sign_tx_signingmode_t txSigningMode,
    const ext_credential_t *ownerCredential,
    warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(ownerCredential != NULL);
    switch (ownerCredential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            // when path is present, it should be a valid staking path
            DENY_UNLESS(bip44_isOrdinaryStakingKeyPath(&ownerCredential->keyPath));
            DENY_IF(violatesSingleAccountOrStoreIt(&ownerCredential->keyPath));
            break;
        case EXT_CREDENTIAL_KEY_HASH:
            break;
        case EXT_CREDENTIAL_SCRIPT_HASH:
            DENY();
            break;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
            SHOW();
            break;

        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            // operator should receive owners given by hash
            DENY_UNLESS(ownerCredential->type == EXT_CREDENTIAL_KEY_HASH);
            SHOW();
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }
    DENY();  // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationRelay(
    const sign_tx_signingmode_t txSigningMode,
    const pool_relay_t *relay MARK_UNUSED,
    warning_bits_t *w) {
    POLICY_INIT();
    // Relay details are intentionally ignored; visibility depends only on signer role/mode.
    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
            // not interesting for an owner, show only in expert mode
            SHOW_IF(is_expert_mode());
            HIDE();
            break;

        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            SHOW();
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForSignTxStakePoolRegistrationMetadata(const pool_metadata_t *metadata,
                                                               warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(metadata != NULL);
    if (metadata->urlSize == 0) {
        warning_bits_set(w, WARNING_BIT_POOL_REGISTRATION_EMPTY_METADATA_URL);
    }
    // Metadata presence is material for pool registration and must be visible.
    SHOW();
}

security_policy_t policyForSignTxStakePoolRegistrationNoMetadata(warning_bits_t *w) {
    POLICY_INIT();
    // Explicitly show absence of metadata so owners/operators can verify this case.
    SHOW();
}

security_policy_t policyForSignTxAnchor(const anchor_t *anchor, warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(anchor != NULL && anchor->isIncluded);

    if (anchor->urlLength == 0) {
        warning_bits_set(w, WARNING_BIT_EMPTY_ANCHOR_URL);
    }

    SHOW();
}

// ======================================= Withdrawals =======================================

security_policy_t policyForSignTxWithdrawal(sign_tx_signingmode_t txSigningMode,
                                            const ext_credential_t *stakeCredential,
                                            warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(stakeCredential != NULL);
    // Withdrawals can be signed by staking keys used to sign pool registration certificates,
    // so we do not allow them.
    LEDGER_ASSERT(txSigningMode != SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER &&
                      txSigningMode != SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR,
                  "Withdrawal in pool registration mode");
    switch (stakeCredential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            switch (txSigningMode) {
                case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
                    DENY_UNLESS(is_staking_credential_key_path_allowed(txSigningMode,
                                                                       &stakeCredential->keyPath));
                    SHOW_IF(mark_unusual_key_derivation(w, &stakeCredential->keyPath));
                    SHOW();
                    break;

                case SIGN_TX_SIGNINGMODE_ORDINARY:
                case SIGN_TX_SIGNINGMODE_PLUTUS:
                    DENY_UNLESS(is_staking_credential_key_path_allowed(txSigningMode,
                                                                       &stakeCredential->keyPath));
                    DENY_IF(violatesSingleAccountOrStoreIt(&stakeCredential->keyPath));
                    SHOW_IF(mark_unusual_key_derivation(w, &stakeCredential->keyPath));
                    SHOW_IF(is_expert_mode());
                    HIDE();
                    break;

                case SIGN_TX_SIGNINGMODE_MULTISIG:
                    // script hash is expected for multisig txs
                    DENY();
                    break;

                // LCOV_EXCL_START
                default:
                    // in POOL_REGISTRATION signing modes, this certificate should have already been
                    // reported as invalid (only pool registration certificate is allowed)
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;

        case EXT_CREDENTIAL_KEY_HASH:
            switch (txSigningMode) {
                case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
                    SHOW();
                    break;

                case SIGN_TX_SIGNINGMODE_PLUTUS:
                    SHOW_IF(is_expert_mode());
                    HIDE();
                    break;

                case SIGN_TX_SIGNINGMODE_ORDINARY:
                    // key path is expected for ordinary txs
                    // no known usecase for using 3rd party withdrawals in an ordinary tx
                    // the hash might come from a key used in a witness
                    // we are protecting users from accidentally signing such withdrawals
                    DENY();
                    break;

                case SIGN_TX_SIGNINGMODE_MULTISIG:
                    // script hash is expected for multisig txs
                    DENY();
                    break;

                // LCOV_EXCL_START
                default:
                    // in POOL_REGISTRATION signing modes, this certificate should have already been
                    // reported as invalid (only pool registration certificate is allowed)
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;

        case EXT_CREDENTIAL_SCRIPT_HASH:
            switch (txSigningMode) {
                case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
                    SHOW();
                    break;

                case SIGN_TX_SIGNINGMODE_MULTISIG:
                case SIGN_TX_SIGNINGMODE_PLUTUS:
                    SHOW_IF(is_expert_mode());
                    HIDE();
                    break;

                case SIGN_TX_SIGNINGMODE_ORDINARY:
                    // key path is expected for ordinary txs
                    DENY();
                    break;

                // LCOV_EXCL_START
                default:
                    // in POOL_REGISTRATION signing modes, this certificate should have already been
                    // reported as invalid (only pool registration certificate is allowed)
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;

        // LCOV_EXCL_START
        default:
            // in POOL_REGISTRATION signing modes, non-zero number of withdrawals
            // should have already been reported as invalid
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// ======================================= Tx auxiliary data) ====================================

security_policy_t policyForSignTxAuxData(aux_data_type_t auxDataType, warning_bits_t *w) {
    POLICY_INIT();
    switch (auxDataType) {
        case AUX_DATA_TYPE_ARBITRARY_HASH:
            SHOW_IF(is_expert_mode());
            HIDE();

            break;
        case AUX_DATA_TYPE_CVOTE_REGISTRATION:
            // this is the policy for the initial prompt
            // details of the registration are governed by separate policies
            // (see policyForCVoteRegistration...)
            SHOW();
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// ================================== Validity Interval Start ==================================

security_policy_t policyForSignTxValidityIntervalStart(warning_bits_t *w) {
    POLICY_INIT();
    SHOW_IF(is_expert_mode());
    HIDE();
}

// ======================================= Mint =======================================

security_policy_t policyForSignTxMintInit(const sign_tx_signingmode_t txSigningMode,
                                          warning_bits_t *w) {
    POLICY_INIT();
    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_ORDINARY:
        case SIGN_TX_SIGNINGMODE_MULTISIG:
        case SIGN_TX_SIGNINGMODE_PLUTUS:
        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            SHOW();
            break;

        // LCOV_EXCL_START
        default:
            // in POOL_REGISTRATION signing modes, non-empty mint field
            // should have already been reported as invalid
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// ======================================= Script Data Hash ======================================
security_policy_t policyForSignTxScriptDataHash(const sign_tx_signingmode_t txSigningMode,
                                                warning_bits_t *w) {
    POLICY_INIT();
    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_ORDINARY:
        case SIGN_TX_SIGNINGMODE_MULTISIG:
        case SIGN_TX_SIGNINGMODE_PLUTUS:
            SHOW_IF(is_expert_mode());
            HIDE();
            break;

        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            SHOW();
            break;

        // LCOV_EXCL_START
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            // unreachable: pool registration modes are rejected at tx init before script data hash
            // processing
            DENY();
            break;
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// ======================================= Collateral Inputs =======================================

security_policy_t policyForSignTxCollateralInput(const sign_tx_signingmode_t txSigningMode,
                                                 bool isTotalCollateralPresent,
                                                 const tx_input_t *collateralInput MARK_UNUSED,
                                                 warning_bits_t *w) {
    POLICY_INIT();
    // Individual collateral input data is intentionally ignored; only aggregate collateral safety
    // is enforced. WARNING: policies for collateral inputs, collateral return output and total
    // collateral are interdependent

    // we do not impose restrictions on individual collateral inputs
    // because a HW wallet cannot verify anything about the input

    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_PLUTUS:
            // safe to hide if total collateral is given
            // (if tokens are present, they go to collateral output, and collateral ADA is
            // shown explicitly, so we don't need to see individual collateral inputs)
            SHOW_IF(!isTotalCollateralPresent && is_expert_mode());
            HIDE();
            break;

        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            SHOW();
            break;

        // LCOV_EXCL_START
        case SIGN_TX_SIGNINGMODE_ORDINARY:
        case SIGN_TX_SIGNINGMODE_MULTISIG:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            // unreachable: these modes are rejected at tx init before collateral input processing
            DENY();
            break;
        // LCOV_EXCL_STOP

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// ======================================= Required Signers =======================================

static bool is_required_signer_allowed(bip44_path_t *path, bool allowPoolColdKey) {
    switch (bip44_classifyPath(path)) {
        case PATH_ORDINARY_ACCOUNT:
        case PATH_ORDINARY_PAYMENT_KEY:
        case PATH_ORDINARY_STAKING_KEY:
            return bip44_hasShelleyPrefix(path);

        case PATH_MULTISIG_ACCOUNT:
        case PATH_MULTISIG_PAYMENT_KEY:
        case PATH_MULTISIG_STAKING_KEY:
            return true;

        case PATH_DREP_KEY:
        case PATH_COMMITTEE_COLD_KEY:
        case PATH_COMMITTEE_HOT_KEY:
            // no known use case, but also no reason to deny
            return true;

        case PATH_MINT_KEY:
            return true;

        case PATH_POOL_COLD_KEY:
            return allowPoolColdKey;

        case PATH_CVOTE_ACCOUNT:
        case PATH_CVOTE_KEY:
        case PATH_INVALID:
            return false;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            return false;
            // LCOV_EXCL_STOP
    }
}

security_policy_t policyForSignTxRequiredSigner(const sign_tx_signingmode_t txSigningMode,
                                                required_signer_t *requiredSigner,
                                                warning_bits_t *w) {
    POLICY_INIT();
    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_ORDINARY:
        case SIGN_TX_SIGNINGMODE_MULTISIG:
        case SIGN_TX_SIGNINGMODE_PLUTUS:
        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            // OK
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            break;
            // LCOV_EXCL_STOP
    }

    switch (requiredSigner->type) {
        case REQUIRED_SIGNER_WITH_HASH:
            switch (txSigningMode) {
                case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
                    SHOW();
                    break;

                case SIGN_TX_SIGNINGMODE_PLUTUS:
                case SIGN_TX_SIGNINGMODE_ORDINARY:
                case SIGN_TX_SIGNINGMODE_MULTISIG:
                    SHOW_IF(is_expert_mode());
                    HIDE();
                    break;

                // LCOV_EXCL_START
                default:
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;

        case REQUIRED_SIGNER_WITH_PATH:
            switch (txSigningMode) {
                case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
                    DENY_UNLESS(is_required_signer_allowed(&requiredSigner->keyPath, true));
                    SHOW_IF(mark_unusual_key_derivation(w, &requiredSigner->keyPath));
                    SHOW();
                    break;

                case SIGN_TX_SIGNINGMODE_PLUTUS:
                case SIGN_TX_SIGNINGMODE_ORDINARY:
                case SIGN_TX_SIGNINGMODE_MULTISIG:
                    DENY_UNLESS(is_required_signer_allowed(&requiredSigner->keyPath, false));
                    SHOW_IF(is_expert_mode());
                    HIDE();
                    break;

                // LCOV_EXCL_START
                default:
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// ======================================= Total Collateral =======================================

security_policy_t policyForSignTxTotalCollateral(warning_bits_t *w) {
    POLICY_INIT();
    // WARNING: policies for collateral inputs, collateral return output and total collateral are
    // interdependent

    // showing protects against unlimited collateral loss
    // if not present, we display a warning about unknown collateral
    SHOW();
}

// ======================================= Reference Inputs =======================================

security_policy_t policyForSignTxReferenceInput(const sign_tx_signingmode_t txSigningMode,
                                                const tx_input_t *referenceInput MARK_UNUSED,
                                                warning_bits_t *w) {
    POLICY_INIT();
    // Reference input contents are intentionally ignored; policy only gates by signing mode.
    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_PLUTUS:
            // should be shown because the user loses all collateral if Plutus execution fails
            SHOW_IF(is_expert_mode());
            HIDE();
            break;

        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            SHOW();
            break;

        case SIGN_TX_SIGNINGMODE_ORDINARY:
        case SIGN_TX_SIGNINGMODE_MULTISIG:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            DENY();
            break;

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }
    DENY();  // should not be reached
}

// ======================================= Voting Procedures =======================================

security_policy_t policyForSignTxVotingProcedure(sign_tx_signingmode_t txSigningMode,
                                                 ext_voter_t *voter,
                                                 warning_bits_t *w) {
    POLICY_INIT();
    // Gov action id and vote can be arbitrary.
    // We only restrict voter because that determines witnesses.
    // Certain combinations of tx signing mode and credential type are not allowed
    // either because they don't make sense or are dangerous.
    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_ORDINARY:
            switch (voter->type) {
                case EXT_VOTER_COMMITTEE_HOT_KEY_HASH:
                case EXT_VOTER_COMMITTEE_HOT_SCRIPT_HASH:
                case EXT_VOTER_DREP_KEY_HASH:
                case EXT_VOTER_DREP_SCRIPT_HASH:
                case EXT_VOTER_STAKE_POOL_KEY_HASH:
                    // keys must be given by path, otherwise the user does not know
                    // if the hash corresponds to one of his keys
                    DENY();
                    break;

                case EXT_VOTER_COMMITTEE_HOT_KEY_PATH:
                    DENY_UNLESS(bip44_isCommitteeHotKeyPath(&voter->keyPath));
                    DENY_IF(violatesSingleAccountOrStoreIt(&voter->keyPath));
                    SHOW_IF(mark_unusual_key_derivation(w, &voter->keyPath));
                    SHOW();
                    break;

                case EXT_VOTER_DREP_KEY_PATH:
                    DENY_UNLESS(bip44_isDRepKeyPath(&voter->keyPath));
                    DENY_IF(violatesSingleAccountOrStoreIt(&voter->keyPath));
                    SHOW_IF(mark_unusual_key_derivation(w, &voter->keyPath));
                    SHOW();
                    break;

                case EXT_VOTER_STAKE_POOL_KEY_PATH:
                    // Pool cold keys are exempt from single-account constraint.
                    DENY_UNLESS(bip44_isPoolColdKeyPath(&voter->keyPath));
                    SHOW_IF(mark_unusual_key_derivation(w, &voter->keyPath));
                    SHOW();
                    break;

                // LCOV_EXCL_START
                default:
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;

        case SIGN_TX_SIGNINGMODE_MULTISIG:
            switch (voter->type) {
                case EXT_VOTER_COMMITTEE_HOT_KEY_PATH:
                case EXT_VOTER_COMMITTEE_HOT_KEY_HASH:
                case EXT_VOTER_DREP_KEY_PATH:
                case EXT_VOTER_DREP_KEY_HASH:
                case EXT_VOTER_STAKE_POOL_KEY_PATH:
                case EXT_VOTER_STAKE_POOL_KEY_HASH:
                    // everything is expected to be governed by native scripts
                    DENY();
                    break;

                case EXT_VOTER_COMMITTEE_HOT_SCRIPT_HASH:
                case EXT_VOTER_DREP_SCRIPT_HASH:
                    // scripts are OK
                    SHOW();
                    break;

                // LCOV_EXCL_START
                default:
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;

        case SIGN_TX_SIGNINGMODE_PLUTUS:
        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            switch (voter->type) {
                case EXT_VOTER_COMMITTEE_HOT_KEY_PATH:
                    DENY_UNLESS(bip44_isCommitteeHotKeyPath(&voter->keyPath));
                    SHOW_IF(mark_unusual_key_derivation(w, &voter->keyPath));
                    SHOW();
                    break;

                case EXT_VOTER_DREP_KEY_PATH:
                    DENY_UNLESS(bip44_isDRepKeyPath(&voter->keyPath));
                    SHOW_IF(mark_unusual_key_derivation(w, &voter->keyPath));
                    SHOW();
                    break;

                case EXT_VOTER_STAKE_POOL_KEY_PATH:
                    DENY_UNLESS(bip44_isPoolColdKeyPath(&voter->keyPath));
                    SHOW_IF(mark_unusual_key_derivation(w, &voter->keyPath));
                    SHOW();
                    break;

                case EXT_VOTER_COMMITTEE_HOT_KEY_HASH:
                case EXT_VOTER_COMMITTEE_HOT_SCRIPT_HASH:
                case EXT_VOTER_DREP_KEY_HASH:
                case EXT_VOTER_DREP_SCRIPT_HASH:
                case EXT_VOTER_STAKE_POOL_KEY_HASH:
                    SHOW();
                    break;

                // LCOV_EXCL_START
                default:
                    ASSERT(false);
                    // LCOV_EXCL_STOP
            }
            break;

        // LCOV_EXCL_START
        default:
            // this should not be called in POOL_REGISTRATION signing modes
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// ======================================= Treasury =======================================

security_policy_t policyForSignTxTreasury(sign_tx_signingmode_t txSigningMode MARK_UNUSED,
                                          uint64_t treasury MARK_UNUSED,
                                          warning_bits_t *w) {
    POLICY_INIT();
    // Treasury amount/mode are intentionally not validated here; field presence is always
    // user-visible.
    SHOW();
}

// ======================================= Donation =======================================

security_policy_t policyForSignTxDonation(sign_tx_signingmode_t txSigningMode MARK_UNUSED,
                                          uint64_t donation MARK_UNUSED,
                                          warning_bits_t *w) {
    POLICY_INIT();
    // Donation amount/mode are intentionally not validated here; field presence is always
    // user-visible.
    SHOW();
}

// ======================================= Tx hash =======================================

security_policy_t policyForSignTxDisplayTxHash(sign_tx_signingmode_t signingMode,
                                               warning_bits_t *w) {
    POLICY_INIT();
    switch (signingMode) {
        case SIGN_TX_SIGNINGMODE_ORDINARY:
        case SIGN_TX_SIGNINGMODE_MULTISIG:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            SHOW_IF(is_expert_mode());
            HIDE();
            break;

        case SIGN_TX_SIGNINGMODE_PLUTUS:
        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            SHOW();
            break;

        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown tx signing mode for tx hash display policy");
            DENY();
            break;
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// ======================================= Tx witnesses =======================================

static inline security_policy_t _ordinaryWitnessPolicy(const bip44_path_t *path,
                                                       bool mintPresent,
                                                       warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(path != NULL);
    switch (bip44_classifyPath(path)) {
        case PATH_ORDINARY_PAYMENT_KEY:
        case PATH_ORDINARY_STAKING_KEY:
            // ordinary key paths can be hidden if they are not unusual
            // (the user saw all outputs not belonging to him, withdrawals and certificates,
            // those belong to him in an ORDINARY txs thanks to
            // keys being displayed by paths instead of hashes)
            DENY_IF(violatesSingleAccountOrStoreIt(path));
            SHOW_IF(mark_unusual_key_derivation(w, path));
            SHOW_IF(is_expert_mode());
            HIDE();
            break;

        case PATH_DREP_KEY:
        case PATH_COMMITTEE_COLD_KEY:
        case PATH_COMMITTEE_HOT_KEY:
            // used to sign certificates and voting procedures
            // these won't occur often, so little benefit from hiding them
            // better to show them at least while they are new
            // in the future, we might want to hide some of them in non-expert mode
            DENY_IF(violatesSingleAccountOrStoreIt(path));
            SHOW_IF(mark_unusual_key_derivation(w, path));
            SHOW();
            break;

        case PATH_POOL_COLD_KEY:
            // could be hidden perhaps, but it's safer to let the user to know
            // the SW wallet wants to sign with the stake pool key
            SHOW_IF(mark_unusual_key_derivation(w, path));
            SHOW();
            break;

        case PATH_MINT_KEY:
            DENY_UNLESS(mintPresent);
            // maybe not necessary, but let the user know which mint key is he using (eg. in case
            // the minting policy contains multiple of his keys but with different rules)
            SHOW();
            break;

        default:
            // multisig keys forbidden
            DENY();
            break;
    }
}

static inline security_policy_t _multisigWitnessPolicy(const bip44_path_t *path,
                                                       bool mintPresent,
                                                       warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(path != NULL);

    switch (bip44_classifyPath(path)) {
        case PATH_MULTISIG_PAYMENT_KEY:
        case PATH_MULTISIG_STAKING_KEY:
            // multisig key paths are allowed, but hiding them would make impossible for the user to
            // distinguish what funds are being spent (multisig UTXOs sharing a signer are not
            // necessarily interchangeable, because they may be governed by a different script)
            SHOW_IF(mark_unusual_key_derivation(w, path));
            SHOW();
            break;

        case PATH_MINT_KEY:
            DENY_UNLESS(mintPresent);
            // maybe not necessary, but let the user know which mint key is he using (eg. in case
            // the minting policy contains multiple of his keys but with different rules)
            SHOW();
            break;

        default:
            // ordinary and pool cold keys forbidden
            // DRep and committee keys forbidden
            DENY();
            break;
    }
}

static inline security_policy_t _plutusWitnessPolicy(const bip44_path_t *path,
                                                     bool mintPresent,
                                                     warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(path != NULL);
    switch (bip44_classifyPath(path)) {
        // in PLUTUS_TX, we allow signing with any path, but it must be shown
        case PATH_ORDINARY_PAYMENT_KEY:
        case PATH_ORDINARY_STAKING_KEY:
        case PATH_MULTISIG_PAYMENT_KEY:
        case PATH_MULTISIG_STAKING_KEY:
        case PATH_DREP_KEY:
        case PATH_COMMITTEE_COLD_KEY:
        case PATH_COMMITTEE_HOT_KEY:
            SHOW_IF(mark_unusual_key_derivation(w, path));
            SHOW();
            break;

        case PATH_MINT_KEY:
            // mint witness without mint in the tx: somewhat suspicious,
            // no known usecase, but a mint path could be e.g. in required signers
            SHOW_UNLESS(mintPresent);
            // maybe not necessary, but let the user know which mint key is he using (e.g. in case
            // the minting policy contains multiple of his keys but with different rules)
            SHOW();
            break;

        case PATH_POOL_COLD_KEY:
        default:
            DENY();
            break;
    }
}

static inline security_policy_t _unrestrictedWitnessPolicy(const bip44_path_t *path,
                                                           bool mintPresent MARK_UNUSED,
                                                           warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(path != NULL);
    switch (bip44_classifyPath(path)) {
        case PATH_ORDINARY_PAYMENT_KEY:
        case PATH_ORDINARY_STAKING_KEY:
        case PATH_MULTISIG_PAYMENT_KEY:
        case PATH_MULTISIG_STAKING_KEY:
        case PATH_DREP_KEY:
        case PATH_COMMITTEE_COLD_KEY:
        case PATH_COMMITTEE_HOT_KEY:
        case PATH_POOL_COLD_KEY:
            SHOW_IF(mark_unusual_key_derivation(w, path));
            SHOW();
            break;

        case PATH_MINT_KEY:
            SHOW();
            break;

        default:
            DENY();
            break;
    }
}

static inline security_policy_t _poolRegistrationOwnerWitnessPolicy(
    const bip44_path_t *witnessPath,
    const bip44_path_t *poolOwnerPath,
    warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(witnessPath != NULL);
    switch (bip44_classifyPath(witnessPath)) {
        case PATH_ORDINARY_STAKING_KEY:
            ASSERT(poolOwnerPath != NULL);
            // an owner was given by path
            // the witness path must be identical
            DENY_UNLESS(bip44_pathsEqual(witnessPath, poolOwnerPath));

            SHOW_IF(mark_unusual_key_derivation(w, witnessPath));
            SHOW();
            break;

        default:
            DENY();
            break;
    }
}

static inline security_policy_t _poolRegistrationOperatorWitnessPolicy(const bip44_path_t *path,
                                                                       warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(path != NULL);
    switch (bip44_classifyPath(path)) {
        case PATH_ORDINARY_PAYMENT_KEY:
        case PATH_POOL_COLD_KEY:
            // only ordinary payment key paths (because of inputs) and pool cold key path are
            // allowed
            SHOW_IF(mark_unusual_key_derivation(w, path));
            // it might be safe to hide the witnesses, but txs related to stake pools
            // are rare, so it would not help much and might introduce some unknown risk
            SHOW();
            break;

        default:
            DENY();
            break;
    }
}

static inline security_policy_t _swapWitnessPolicy(const sign_tx_signingmode_t txSigningMode,
                                                   const bip44_path_t *path,
                                                   warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(path != NULL);

    // Swap flow must sign ordinary transactions only.
    DENY_UNLESS(txSigningMode == SIGN_TX_SIGNINGMODE_ORDINARY);

    switch (bip44_classifyPath(path)) {
        case PATH_ORDINARY_PAYMENT_KEY:
            // Keep single-account invariant in swap mode as well.
            DENY_IF(violatesSingleAccountOrStoreIt(path));
            // Swap does not show witness UI, so unusual derivations must be denied.
            DENY_UNLESS(bip44_isPathReasonable(path));
            HIDE();
            break;

        default:
            // In swap mode we only accept ordinary payment key witnesses.
            // This rejects pool cold, staking, multisig, mint and governance paths.
            DENY();
            break;
    }
    DENY();  // should not be reached
}

// For each transaction witness
// Note: witnesses reveal public key of an address and Ledger *does not* check
// whether they correspond to previously declared inputs and certificates
security_policy_t policyForSignTxWitness(sign_tx_signingmode_t txSigningMode,
                                         bool isSwap,
                                         const bip44_path_t *witnessPath,
                                         bool mintPresent,
                                         const bip44_path_t *poolOwnerPath,
                                         warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(witnessPath != NULL);

    if (isSwap) {
        RETURN(_swapWitnessPolicy(txSigningMode, witnessPath, w));
    }

    switch (txSigningMode) {
        case SIGN_TX_SIGNINGMODE_ORDINARY:
            RETURN(_ordinaryWitnessPolicy(witnessPath, mintPresent, w));

        case SIGN_TX_SIGNINGMODE_MULTISIG:
            RETURN(_multisigWitnessPolicy(witnessPath, mintPresent, w));

        case SIGN_TX_SIGNINGMODE_PLUTUS:
            RETURN(_plutusWitnessPolicy(witnessPath, mintPresent, w));

        case SIGN_TX_SIGNINGMODE_UNRESTRICTED:
            RETURN(_unrestrictedWitnessPolicy(witnessPath, mintPresent, w));

        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER:
            RETURN(_poolRegistrationOwnerWitnessPolicy(witnessPath, poolOwnerPath, w));

        case SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR:
            RETURN(_poolRegistrationOperatorWitnessPolicy(witnessPath, w));

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

// ======================================= CVote aux data =======================================

security_policy_t policyForCVoteRegistrationVoteKey(const cvote_credential_t *credential,
                                                    cvote_registration_format_t format,
                                                    warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(credential != NULL);

    switch (credential->type) {
        case CVOTE_CREDENTIAL_KEY: {
            SHOW();
            break;
        }
        case CVOTE_CREDENTIAL_KEY_PATH: {
            DENY_UNLESS(format == CIP36);

            DENY_UNLESS(bip44_classifyPath(&credential->keyPath) == PATH_CVOTE_KEY);

            SHOW_IF(mark_unusual_key_derivation(w, &credential->keyPath));
            SHOW();
            break;
        }
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            DENY();
            break;
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForCVoteRegistrationStakingKey(const bip44_path_t *stakingKeyPath,
                                                       warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(stakingKeyPath != NULL);

    DENY_UNLESS(bip44_isOrdinaryStakingKeyPath(stakingKeyPath));

    SHOW_IF(mark_unusual_key_derivation(w, stakingKeyPath));

    SHOW();
}

// based on https://input-output-rnd.slack.com/archives/C036XSMFXE3/p1668185230182239
security_policy_t policyForCVoteRegistrationPaymentDestination(
    const tx_output_destination_t *destination,
    const uint8_t networkId,
    warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(destination != NULL);

    switch (destination->type) {
        case DESTINATION_DEVICE_OWNED: {
            DENY_UNLESS(isValidAddressParams(&destination->params));
            DENY_UNLESS(isShelleyAddressType(destination->params.type));
            DENY_IF(destination->params.networkId != networkId);

            // in a typical case, the rewards go to an address controlled by this device
            // and the address is sent in a way allowing a verification of that fact
            if (!is_standard_base_address(&destination->params)) {
                warning_bits_set(w, WARNING_BIT_CVOTE_PAYMENT_NONSTANDARD_OWNED);
            }
            SHOW_UNLESS(is_standard_base_address(&destination->params));

            // we are sure the address belongs to the device
            SHOW();
            break;
        }

        case DESTINATION_THIRD_PARTY: {
            const uint8_t header =
                getAddressHeader(destination->address.buffer, destination->address.length);
            DENY_UNLESS(isShelleyAddressType(getAddressType(header)));
            DENY_IF(getNetworkId(header) != networkId);

            // we don't know who owns the address
            // to possibly avoid this warning, send the address as parameters (see above)
            warning_bits_set(w, WARNING_BIT_CVOTE_PAYMENT_THIRD_PARTY);
            SHOW();
            break;
        }

        // LCOV_EXCL_START
        default:
            ASSERT(false);
            // LCOV_EXCL_STOP
    }

    DENY();  // should not be reached
}

security_policy_t policyForCVoteRegistrationNonce(warning_bits_t *w) {
    POLICY_INIT();
    SHOW();
}

security_policy_t policyForCVoteRegistrationVotingPurpose(uint64_t votingPurpose,
                                                          warning_bits_t *w) {
    POLICY_INIT();
    // Non-default voting purpose is security-relevant: always show it so the
    // user can see an attacker-controlled governance domain before signing.
    SHOW_IF(votingPurpose != 0);
    SHOW_IF(is_expert_mode());
    HIDE();
}

// ======================================= Operational certificate
// =======================================

security_policy_t policyForSignOpCert(const bip44_path_t *poolColdKeyPath, warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(poolColdKeyPath != NULL);
    switch (bip44_classifyPath(poolColdKeyPath)) {
        case PATH_POOL_COLD_KEY:
            SHOW_IF(mark_unusual_key_derivation(w, poolColdKeyPath));
            SHOW();
            break;

        default:
            DENY();
            break;
    }

    DENY();  // should not be reached
}

// ======================================= Warnings =======================================

static const warning_definition_t WARNING_DEFINITIONS[WARNING_BIT_COUNT] = {
    [WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH] =
        {
            .bit = WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH,
            .title = "Unusual derivation path",
            .description = "Key path outside of standard range",
        },
    [WARNING_BIT_NETWORK_UNUSUAL] =
        {
            .bit = WARNING_BIT_NETWORK_UNUSUAL,
            .title = "Unusual network",
            .description = "Network id or protocol magic is unexpected",
        },
    [WARNING_BIT_NETWORK_NOT_VERIFIABLE] =
        {
            .bit = WARNING_BIT_NETWORK_NOT_VERIFIABLE,
            .title = "Network not verifiable",
            .description = "Transaction body lacks data to verify destination network",
        },
    [WARNING_BIT_PLUTUS_MISSING_COLLATERAL] =
        {
            .bit = WARNING_BIT_PLUTUS_MISSING_COLLATERAL,
#ifdef SCREEN_SIZE_WALLET
            .title = "Missing collateral inputs",
#else
            .title = "Collateral inputs",
#endif
            .description = "Plutus transaction without collateral inputs",
        },
    [WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL] =
        {
            .bit = WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL,
#ifdef SCREEN_SIZE_WALLET
            .title = "Collateral not specified",
#else
            .title = "Total collateral",
#endif
            .description = "Plutus transaction without total collateral",
        },
    [WARNING_BIT_COLLATERAL_OUTPUT_WARNING] =
        {
            .bit = WARNING_BIT_COLLATERAL_OUTPUT_WARNING,
#ifdef SCREEN_SIZE_WALLET
            .title = "Tokens in third-party collateral output",
            .description = "Collateral return output to third-party address includes tokens",
#else
            .title = "Collateral output",
            .description = "Collateral return output includes tokens",
#endif
        },
    [WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH] =
        {
            .bit = WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH,
            .title = "Missing script data hash",
            .description = "Plutus transaction lacks script data hash",
        },
    [WARNING_BIT_OUTPUT_MISSING_DATUM] =
        {
            .bit = WARNING_BIT_OUTPUT_MISSING_DATUM,
            .title = "Datum missing",
            .description = "Script output lacks datum; funds might be unspendable",
        },
    [WARNING_BIT_CVOTE_PAYMENT_THIRD_PARTY] =
        {
            .bit = WARNING_BIT_CVOTE_PAYMENT_THIRD_PARTY,
            .title = "Voting rewards to third party",
            .description = "Catalyst voting rewards go to an external address",
        },
    [WARNING_BIT_CVOTE_PAYMENT_NONSTANDARD_OWNED] =
        {
            .bit = WARNING_BIT_CVOTE_PAYMENT_NONSTANDARD_OWNED,
            .title = "Non-standard voting reward address",
            .description = "Device-owned voting reward address uses an unusual derivation",
        },
    [WARNING_BIT_CVOTE_WITNESS_NOT_FULLY_VERIFIABLE] =
        {
            .bit = WARNING_BIT_CVOTE_WITNESS_NOT_FULLY_VERIFIABLE,
            .title = "Limited vote verification",
            .description =
                "Device cannot analyze vote consequences and does not display all details",
        },
    [WARNING_BIT_POOL_REGISTRATION_NO_OWNERS] =
        {
            .bit = WARNING_BIT_POOL_REGISTRATION_NO_OWNERS,
            .title = "No pool owners",
            .description = "Stake pool registration does not specify any pool owners",
        },
    [WARNING_BIT_POOL_REGISTRATION_NO_RELAYS] =
        {
            .bit = WARNING_BIT_POOL_REGISTRATION_NO_RELAYS,
            .title = "No pool relays",
            .description = "Stake pool registration does not specify any pool relays",
        },
    [WARNING_BIT_POOL_REGISTRATION_EMPTY_METADATA_URL] =
        {
            .bit = WARNING_BIT_POOL_REGISTRATION_EMPTY_METADATA_URL,
            .title = "Empty metadata URL",
            .description = "Stake pool registration metadata URL is empty",
        },
    [WARNING_BIT_EMPTY_ANCHOR_URL] =
        {
            .bit = WARNING_BIT_EMPTY_ANCHOR_URL,
            .title = "Empty anchor URL",
            .description = "Anchor URL is empty",
        },
    [WARNING_BIT_HIGH_FEE] =
        {
            .bit = WARNING_BIT_HIGH_FEE,
            .title = "High fee",
            .description = "Transaction fee exceeds typical threshold",
        },
    [WARNING_BIT_UNRESTRICTED_SIGNING] =
        {
            .bit = WARNING_BIT_UNRESTRICTED_SIGNING,
            .title = "Unrestricted signing",
            .description = "Unusual elements! Witness might sign many opaque script hashes.",
        },
};

size_t warning_bits_to_definitions(warning_bits_t w,
                                   const warning_definition_t **definitions,
                                   size_t max_definitions) {
    size_t count = 0;
    for (warning_bit_e bit = 0; bit < WARNING_BIT_COUNT && count < max_definitions; ++bit) {
        if (!warning_bits_has(w, bit)) continue;
        const warning_definition_t *def =
            (const warning_definition_t *) PIC(&WARNING_DEFINITIONS[bit]);
        const char *title = (const char *) PIC(def->title);
        const char *description = (const char *) PIC(def->description);
        if (title == NULL || description == NULL || description[0] == '\0') {
            // LCOV_EXCL_START
            TRACE("Missing warning definition for bit %d", bit);
            LEDGER_ASSERT(false, "Missing warning definition");
            return count;
            // LCOV_EXCL_STOP
        }
        definitions[count++] = def;
    }
    return count;
}

// ======================================= CVote witness (votecast)
// =======================================

security_policy_t policyForSignCVoteWitness(const bip44_path_t *path, warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(path != NULL);
    warning_bits_set(w, WARNING_BIT_CVOTE_WITNESS_NOT_FULLY_VERIFIABLE);

    switch (bip44_classifyPath(path)) {
        case PATH_CVOTE_KEY:
            SHOW_IF(mark_unusual_key_derivation(w, path));
            SHOW();
            break;

        default:
            DENY();
            break;
    }

    DENY();  // should not be reached
}

// ======================================= Sign msg =======================================

security_policy_t policyForSignMsg(const bip44_path_t *witnessPath,
                                   cip8_address_field_type_t addressFieldType,
                                   const address_params_t *address_params,
                                   warning_bits_t *w) {
    POLICY_INIT();
    ASSERT(witnessPath != NULL);

    switch (bip44_classifyPath(witnessPath)) {
        case PATH_ORDINARY_PAYMENT_KEY:
        case PATH_ORDINARY_STAKING_KEY:
        case PATH_MULTISIG_PAYMENT_KEY:
        case PATH_MULTISIG_STAKING_KEY:
        case PATH_MINT_KEY:
        case PATH_DREP_KEY:
        case PATH_COMMITTEE_COLD_KEY:
        case PATH_COMMITTEE_HOT_KEY:
        case PATH_POOL_COLD_KEY:
            // OK - path classification is valid
            break;
        default:
            DENY();
            break;
    }

    if (addressFieldType == CIP8_ADDRESS_FIELD_ADDRESS) {
        DENY_UNLESS(isValidAddressParams(address_params));

        switch (address_params->type) {
            case BASE_PAYMENT_KEY_STAKE_KEY:
            case BASE_PAYMENT_KEY_STAKE_SCRIPT:
            case REWARD_KEY:
            case ENTERPRISE_KEY:
                // OK
                break;

            default:
                DENY();
                break;
        }
    }

    SHOW_IF(mark_unusual_key_derivation(w, witnessPath));
    SHOW();
}
