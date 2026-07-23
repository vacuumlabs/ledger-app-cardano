/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>
#include <string.h>

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_UI_DISPLAY to trace certificate UI rendering.
 */
#ifdef TRACE_UI_DISPLAY
#define TRACE_MODULE(...) TRACE("[tx_ui_render_certificates] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif

#include "assert.h"
#include "addressUtilsShelley.h"
#include "bech32.h"
#include "cardano_constants.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "keyDerivation.h"
#include "mem.h"
#include "tx_certificate_types.h"
#include "tx_credential_types.h"
#include "tx_ui_governance_id.h"
#include "tx_ui_pair_counts.h"
#include "tx_ui_render_certificates.h"
#include "ui_constants.h"
#include "ui_formatters.h"
#include "ui_utils.h"

// ---------------------------------------------------------------------------
// Credential render helpers (pure renderers, no policy awareness)
// ---------------------------------------------------------------------------

static void render_credential(const ext_credential_t *credential,
                              const char *key_path_label,
                              const char *key_hash_label,
                              const char *key_hash_prefix,
                              const char *script_hash_label,
                              const char *script_hash_prefix) {
    ASSERT(credential != NULL);

    switch (credential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            UI_ADD_FORMAT1(key_path_label,
                           MAX_BIP44_PATH_STRING_LENGTH,
                           format_bip44_path,
                           &credential->keyPath);
            break;
        case EXT_CREDENTIAL_KEY_HASH:
            ASSERT(credential->keyHash != NULL);
            UI_ADD_FORMAT3(key_hash_label,
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           key_hash_prefix,
                           credential->keyHash,
                           ADDRESS_KEY_HASH_LENGTH);
            break;
        case EXT_CREDENTIAL_SCRIPT_HASH:
            ASSERT(credential->scriptHash != NULL);
            UI_ADD_FORMAT3(script_hash_label,
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           script_hash_prefix,
                           credential->scriptHash,
                           SCRIPT_HASH_LENGTH);
            break;
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown credential type");
            // LCOV_EXCL_STOP
    }
}

// Governance credentials are shown as CIP-0129 identifiers: bech32 over a 1-byte
// header (key type + credential type) followed by the credential hash.
static void render_governance_credential(const ext_credential_t *credential,
                                         const char *key_path_label,
                                         const char *key_hash_label,
                                         const char *script_hash_label,
                                         const char *bech32_prefix,
                                         uint8_t key_type) {
    ASSERT(credential != NULL);

    switch (credential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            UI_ADD_FORMAT1(key_path_label,
                           MAX_BIP44_PATH_STRING_LENGTH,
                           format_bip44_path,
                           &credential->keyPath);
            break;
        case EXT_CREDENTIAL_KEY_HASH:
            ASSERT(credential->keyHash != NULL);
            UI_ADD_FORMAT4(key_hash_label,
                           MAX_BECH32_STRING_LENGTH,
                           format_governance_identifier,
                           bech32_prefix,
                           governance_id_header(key_type, GOVERNANCE_ID_CREDENTIAL_KEY_HASH),
                           credential->keyHash,
                           ADDRESS_KEY_HASH_LENGTH);
            break;
        case EXT_CREDENTIAL_SCRIPT_HASH:
            ASSERT(credential->scriptHash != NULL);
            UI_ADD_FORMAT4(script_hash_label,
                           MAX_BECH32_STRING_LENGTH,
                           format_governance_identifier,
                           bech32_prefix,
                           governance_id_header(key_type, GOVERNANCE_ID_CREDENTIAL_SCRIPT_HASH),
                           credential->scriptHash,
                           SCRIPT_HASH_LENGTH);
            break;
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown credential type");
            // LCOV_EXCL_STOP
    }
}

static void render_stake_credential(const ext_credential_t *credential) {
    render_credential(credential,
                      UI_STATIC_LABEL("Stake key"),
                      UI_STATIC_LABEL("Stake key hash"),
                      BECH32_PREFIX_STAKE_KEY_HASH,
                      UI_LABEL_BY_SCREEN("Stake script hash", "Stake script"),
                      BECH32_PREFIX_SCRIPT_HASH);
}

static void render_voter_credential(const ext_credential_t *credential) {
    render_credential(credential,
                      UI_STATIC_LABEL("Voter"),
                      UI_STATIC_LABEL("Voter hash"),
                      BECH32_PREFIX_STAKE_KEY_HASH,
                      UI_LABEL_BY_SCREEN("Voter script hash", "Voter script"),
                      BECH32_PREFIX_SCRIPT_HASH);
}

static void render_drep_credential(const ext_credential_t *credential) {
    render_governance_credential(credential,
                                 UI_STATIC_LABEL("DRep key"),
                                 UI_STATIC_LABEL("DRep key hash"),
                                 UI_LABEL_BY_SCREEN("DRep script hash", "DRep script"),
                                 BECH32_PREFIX_DREP,
                                 GOVERNANCE_ID_KEY_TYPE_DREP);
}

static void render_committee_cold_credential(const ext_credential_t *credential) {
    render_governance_credential(credential,
                                 UI_LABEL_BY_SCREEN("Committee cold key", "Cmte c key"),
                                 UI_LABEL_BY_SCREEN("Committee cold key hash", "Cmte c key"),
                                 UI_LABEL_BY_SCREEN("Committee cold script hash", "Cmte c scr"),
                                 BECH32_PREFIX_COMMITTEE_COLD,
                                 GOVERNANCE_ID_KEY_TYPE_COMMITTEE_COLD);
}

static void render_committee_hot_credential(const ext_credential_t *credential) {
    render_governance_credential(credential,
                                 UI_LABEL_BY_SCREEN("Committee hot key", "Cmte hot key"),
                                 UI_LABEL_BY_SCREEN("Committee hot key hash", "Cmte hot key"),
                                 UI_LABEL_BY_SCREEN("Committee hot script hash", "Cmte hot scr"),
                                 BECH32_PREFIX_COMMITTEE_HOT,
                                 GOVERNANCE_ID_KEY_TYPE_COMMITTEE_HOT);
}

static void render_drep(const ext_drep_t *drep, const char *label) {
    ASSERT(drep != NULL);
    ASSERT(label != NULL);

    switch (drep->type) {
        case EXT_DREP_KEY_PATH:
            UI_ADD_FORMAT1(label, MAX_BIP44_PATH_STRING_LENGTH, format_bip44_path, &drep->keyPath);
            break;
        case EXT_DREP_KEY_HASH:
            ASSERT(drep->keyHash != NULL);
            UI_ADD_FORMAT4(label,
                           MAX_BECH32_STRING_LENGTH,
                           format_governance_identifier,
                           BECH32_PREFIX_DREP,
                           governance_id_header(GOVERNANCE_ID_KEY_TYPE_DREP,
                                                GOVERNANCE_ID_CREDENTIAL_KEY_HASH),
                           drep->keyHash,
                           ADDRESS_KEY_HASH_LENGTH);
            break;
        case EXT_DREP_SCRIPT_HASH:
            ASSERT(drep->scriptHash != NULL);
            UI_ADD_FORMAT4(label,
                           MAX_BECH32_STRING_LENGTH,
                           format_governance_identifier,
                           BECH32_PREFIX_DREP,
                           governance_id_header(GOVERNANCE_ID_KEY_TYPE_DREP,
                                                GOVERNANCE_ID_CREDENTIAL_SCRIPT_HASH),
                           drep->scriptHash,
                           SCRIPT_HASH_LENGTH);
            break;
        case EXT_DREP_ABSTAIN:
        case EXT_DREP_NO_CONFIDENCE:
            UI_ADD_FORMAT1(label, MAX_DREP_OPTION_LENGTH, format_constant_drep, drep->type);
            break;
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown DRep type");
            break;
            // LCOV_EXCL_STOP
    }
}

// ---------------------------------------------------------------------------
// Anchor planning/rendering helper (pure, no policy evaluation)
// ---------------------------------------------------------------------------

static void plan_or_render_anchor(const tx_processing_mode_t *mode, const anchor_t *anchor) {
    ASSERT(mode != NULL);
    ASSERT(anchor != NULL && anchor->isIncluded);

    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_ANCHOR;
    } else if (mode->ui_render) {
        START_COUNT();
        if (anchor->urlLength == 0) {
            LEDGER_ASSERT(
                warning_bits_has(tx_body_ctx()->warning_bits, WARNING_BIT_EMPTY_ANCHOR_URL),
                "Empty anchor URL warning missing");
            UI_ADD_STATIC(UI_STATIC_LABEL("Anchor URL"), UI_STATIC_LABEL("(empty)"));
        } else {
            UI_ADD_FORMAT2(UI_STATIC_LABEL("Anchor URL"),
                           MAX_ANCHOR_URL_LENGTH,
                           format_url,
                           anchor->url,
                           anchor->urlLength);
        }
        UI_ADD_FORMAT2(UI_STATIC_LABEL("Anchor hash"),
                       MAX_ANCHOR_HASH_STRING_LENGTH,
                       format_hex_bytes,
                       anchor->hash,
                       ANCHOR_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_ANCHOR);
    }
}

// ---------------------------------------------------------------------------
// Certificate type render helpers
// ---------------------------------------------------------------------------

static void render_deposit(uint64_t deposit) {
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Deposit"),
                   MAX_ADA_AMOUNT_STRING_LENGTH,
                   format_ada_amount,
                   deposit);
}

static void render_certificate_header(certificate_type_t type) {
    if (G_context.tx_info.tx_params.num_certificates >= CERTIFICATE_NEW_PAGE_COUNT_TRESHOLD) {
        ui_pairs_force_new_page();
    }
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Certificate"),
                   MAX_CERTIFICATE_TYPE_LENGTH,
                   format_certificate_type,
                   type);
}

static void plan_or_render_certificate_stake_registration(
    const tx_processing_mode_t *mode,
    const certificate_data_t *certificate_data) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_CERTIFICATE_STAKE_REGISTRATION;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_REGISTRATION);
    }
}

static void plan_or_render_certificate_stake_deregistration(
    const tx_processing_mode_t *mode,
    const certificate_data_t *certificate_data) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_CERTIFICATE_STAKE_DEREGISTRATION;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_DEREGISTRATION);
    }
}

static void plan_or_render_certificate_stake_registration_conway(
    const tx_processing_mode_t *mode,
    const certificate_data_t *certificate_data) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_CERTIFICATE_STAKE_REGISTRATION_CONWAY;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        render_deposit(certificate_data->deposit);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_REGISTRATION_CONWAY);
    }
}

static void plan_or_render_certificate_stake_deregistration_conway(
    const tx_processing_mode_t *mode,
    const certificate_data_t *certificate_data) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_CERTIFICATE_STAKE_DEREGISTRATION_CONWAY;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        render_deposit(certificate_data->deposit);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_DEREGISTRATION_CONWAY);
    }
}

static void plan_or_render_certificate_stake_delegation(
    const tx_processing_mode_t *mode,
    const certificate_data_t *certificate_data) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_CERTIFICATE_STAKE_DELEGATION;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       BECH32_PREFIX_POOL_ID,
                       certificate_data->poolKeyHash,
                       POOL_KEY_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_DELEGATION);
    }
}

static void plan_or_render_certificate_vote_delegation(const tx_processing_mode_t *mode,
                                                       const certificate_data_t *certificate_data) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_CERTIFICATE_VOTE_DELEGATION;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_voter_credential(&certificate_data->stakeCredential);
        render_drep(&certificate_data->drep, UI_STATIC_LABEL("DRep"));
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_VOTE_DELEGATION);
    }
}

static void plan_or_render_certificate_stake_pool_and_drep_delegation(
    const tx_processing_mode_t *mode,
    const certificate_data_t *certificate_data) {
    ASSERT(certificate_data->combinedDelegPoolKeyHash != NULL);
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       BECH32_PREFIX_POOL_ID,
                       certificate_data->combinedDelegPoolKeyHash,
                       POOL_KEY_HASH_LENGTH);
        render_drep(&certificate_data->drep, UI_STATIC_LABEL("DRep"));
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION);
    }
}

static void plan_or_render_certificate_account_registration_delegation_to_stake_pool(
    const tx_processing_mode_t *mode,
    const certificate_data_t *certificate_data) {
    ASSERT(certificate_data->combinedDelegPoolKeyHash != NULL);
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs +=
            UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       BECH32_PREFIX_POOL_ID,
                       certificate_data->combinedDelegPoolKeyHash,
                       POOL_KEY_HASH_LENGTH);
        render_deposit(certificate_data->deposit);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL);
    }
}

static void plan_or_render_certificate_account_registration_delegation_to_drep(
    const tx_processing_mode_t *mode,
    const certificate_data_t *certificate_data) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs +=
            UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        render_drep(&certificate_data->drep, UI_STATIC_LABEL("DRep"));
        render_deposit(certificate_data->deposit);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP);
    }
}

static void plan_or_render_certificate_account_registration_delegation_to_stake_pool_and_drep(
    const tx_processing_mode_t *mode,
    const certificate_data_t *certificate_data) {
    ASSERT(certificate_data->combinedDelegPoolKeyHash != NULL);
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs +=
            UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       BECH32_PREFIX_POOL_ID,
                       certificate_data->combinedDelegPoolKeyHash,
                       POOL_KEY_HASH_LENGTH);
        render_drep(&certificate_data->drep, UI_STATIC_LABEL("DRep"));
        render_deposit(certificate_data->deposit);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP);
    }
}

static void plan_or_render_certificate_authorize_committee_hot(
    const tx_processing_mode_t *mode,
    const certificate_data_t *certificate_data) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_CERTIFICATE_AUTHORIZE_COMMITTEE_HOT;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_committee_cold_credential(&certificate_data->coldCredential);
        render_committee_hot_credential(&certificate_data->hotCredential);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_AUTHORIZE_COMMITTEE_HOT);
    }
}

static void plan_or_render_certificate_resign_committee_cold(
    const tx_processing_mode_t *mode,
    const certificate_data_t *certificate_data) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_CERTIFICATE_RESIGN_COMMITTEE_COLD;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_committee_cold_credential(&certificate_data->coldCredential);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_RESIGN_COMMITTEE_COLD);
    }
}

static void plan_or_render_certificate_drep_registration(
    const tx_processing_mode_t *mode,
    const certificate_data_t *certificate_data) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_CERTIFICATE_DREP_REGISTRATION;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_drep_credential(&certificate_data->dRepCredential);
        render_deposit(certificate_data->deposit);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_DREP_REGISTRATION);
    }
}

static void plan_or_render_certificate_drep_deregistration(
    const tx_processing_mode_t *mode,
    const certificate_data_t *certificate_data) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_CERTIFICATE_DREP_DEREGISTRATION;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_drep_credential(&certificate_data->dRepCredential);
        render_deposit(certificate_data->deposit);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_DREP_DEREGISTRATION);
    }
}

static void plan_or_render_certificate_drep_update(const tx_processing_mode_t *mode,
                                                   const certificate_data_t *certificate_data) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_CERTIFICATE_DREP_UPDATE;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_drep_credential(&certificate_data->dRepCredential);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_DREP_UPDATE);
    }
}

static void plan_or_render_certificate_pool_retirement(const tx_processing_mode_t *mode,
                                                       const certificate_data_t *certificate_data) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_CERTIFICATE_POOL_RETIREMENT;
    } else if (mode->ui_render) {
        const ext_credential_t *pool_credential = &certificate_data->poolCredential;
        uint8_t pool_key_hash[POOL_KEY_HASH_LENGTH] = {0};
        STATIC_ASSERT(ADDRESS_KEY_HASH_LENGTH == POOL_KEY_HASH_LENGTH,
                      "pool credential hash size mismatch");

        switch (pool_credential->type) {
            case EXT_CREDENTIAL_KEY_PATH:
                keyPathToKeyHash(&pool_credential->keyPath, pool_key_hash, sizeof(pool_key_hash));
                break;
            case EXT_CREDENTIAL_KEY_HASH:
                ASSERT(pool_credential->keyHash != NULL);
                memcpy(pool_key_hash, pool_credential->keyHash, POOL_KEY_HASH_LENGTH);
                break;
            // LCOV_EXCL_START
            default:
                LEDGER_ASSERT(false, "Unsupported pool credential type for retirement");
                break;
                // LCOV_EXCL_STOP
        }

        START_COUNT();
        render_certificate_header(certificate_data->type);
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool ID"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       BECH32_PREFIX_POOL_ID,
                       pool_key_hash,
                       POOL_KEY_HASH_LENGTH);
        UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Retirement epoch", "Retire epoch"),
                       MAX_UINT64_STRING_LENGTH,
                       format_uint64,
                       certificate_data->retirementEpoch);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_POOL_RETIREMENT);
    }
}

// ---------------------------------------------------------------------------
// Pool registration plan/render helpers (no policy awareness)
// ---------------------------------------------------------------------------

void plan_or_render_pool_registration_header(const tx_processing_mode_t *mode,
                                             certificate_type_t type) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_CERTIFICATE_POOL_REGISTRATION_BASE;
    } else if (mode->ui_render) {
        START_COUNT();
        render_certificate_header(type);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_POOL_REGISTRATION_BASE);
    }
}

void plan_or_render_pool_id(const tx_processing_mode_t *mode, const pool_id_t *pool_id) {
    ASSERT(pool_id != NULL);
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_POOL_ID;
    } else if (mode->ui_render) {
        START_COUNT();
        uint8_t pool_key_hash[POOL_KEY_HASH_LENGTH] = {0};
        switch (pool_id->keyReferenceType) {
            case KEY_REFERENCE_PATH:
                keyPathToKeyHash(&pool_id->path, pool_key_hash, SIZEOF(pool_key_hash));
                break;
            case KEY_REFERENCE_HASH:
                ASSERT(pool_id->hash != NULL);
                memmove(pool_key_hash, pool_id->hash, SIZEOF(pool_key_hash));
                break;
            // LCOV_EXCL_START
            default:
                LEDGER_ASSERT(false, "Unknown pool ID key reference type");
                break;
                // LCOV_EXCL_STOP
        }
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool ID"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       BECH32_PREFIX_POOL_ID,
                       pool_key_hash,
                       POOL_KEY_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_POOL_ID);
    }
}

void plan_or_render_pool_vrf_key_hash(const tx_processing_mode_t *mode,
                                      const uint8_t *vrf_key_hash) {
    ASSERT(vrf_key_hash != NULL);
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_POOL_VRF_KEY;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT3(UI_STATIC_LABEL("VRF key hash"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       BECH32_PREFIX_VRF_KEY_HASH,
                       vrf_key_hash,
                       VRF_KEY_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_POOL_VRF_KEY);
    }
}

void plan_or_render_pool_financials(const tx_processing_mode_t *mode,
                                    const pool_registration_data_t *pool_registration) {
    ASSERT(pool_registration != NULL);
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_POOL_FIXED;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Pledge"),
                       MAX_ADA_AMOUNT_STRING_LENGTH,
                       format_ada_amount,
                       pool_registration->pledge);
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Cost"),
                       MAX_ADA_AMOUNT_STRING_LENGTH,
                       format_ada_amount,
                       pool_registration->cost);
        UI_ADD_FORMAT2(UI_STATIC_LABEL("Profit margin"),
                       MAX_PROFIT_MARGIN_STRING_LENGTH,
                       format_pool_margin,
                       pool_registration->marginNumerator,
                       pool_registration->marginDenominator);
        CHECK_COUNT(UI_PAIRS_POOL_FIXED);
    }
}

void plan_or_render_pool_reward_account(const tx_processing_mode_t *mode,
                                        uint8_t network_id,
                                        const pool_reward_account_t *reward_account) {
    ASSERT(reward_account != NULL);
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_POOL_REWARD_ACCOUNT;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Pool reward address", "Reward addr"),
                       MAX_HUMAN_ADDRESS_LENGTH,
                       format_pool_reward_account,
                       network_id,
                       reward_account);
        CHECK_COUNT(UI_PAIRS_POOL_REWARD_ACCOUNT);
    }
}

void plan_or_render_pool_owner(const tx_processing_mode_t *mode,
                               uint8_t network_id,
                               const ext_credential_t *owner_credential) {
    ASSERT(owner_credential != NULL);
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_POOL_OWNER;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Owner reward address", "Owner addr"),
                       MAX_HUMAN_ADDRESS_LENGTH,
                       format_reward_account_from_credential,
                       network_id,
                       owner_credential);
        CHECK_COUNT(UI_PAIRS_POOL_OWNER);
    }
}

void plan_or_render_pool_no_owners(const tx_processing_mode_t *mode) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_POOL_NO_OWNERS;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_STATIC(UI_STATIC_LABEL("Pool owners"), UI_STATIC_LABEL("(none)"));
        CHECK_COUNT(UI_PAIRS_POOL_NO_OWNERS);
    }
}

static uint16_t count_pool_relay_ui_pairs(const pool_relay_t *relay) {
    uint16_t pairs = UI_PAIRS_POOL_RELAY_HEADER;
    switch (relay->format) {
        case RELAY_SINGLE_HOST_IP:
            pairs += UI_PAIRS_POOL_RELAY_IPV4;
            pairs += UI_PAIRS_POOL_RELAY_IPV6;
            pairs += UI_PAIRS_POOL_RELAY_PORT;
            break;
        case RELAY_SINGLE_HOST_NAME:
            if (relay->dnsNameSize > 0) pairs += UI_PAIRS_POOL_RELAY_DNS;
            pairs += UI_PAIRS_POOL_RELAY_PORT;
            break;
        case RELAY_MULTIPLE_HOST_NAME:
            if (relay->dnsNameSize > 0) pairs += UI_PAIRS_POOL_RELAY_DNS;
            break;
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown relay format type");
            break;
            // LCOV_EXCL_STOP
    }
    return pairs;
}

void plan_or_render_pool_relay(const tx_processing_mode_t *mode,
                               uint16_t relay_index,
                               const pool_relay_t *relay) {
    ASSERT(relay != NULL);
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += count_pool_relay_ui_pairs(relay);
    } else if (mode->ui_render) {
        START_COUNT();
        uint16_t expected_pairs = count_pool_relay_ui_pairs(relay);
        ui_pairs_force_new_page();
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Relay"),
                       MAX_RELAY_INDEX_STRING_LENGTH,
                       format_index_with_prefix,
                       relay_index + 1);
        switch (relay->format) {
            case RELAY_SINGLE_HOST_IP:
                UI_ADD_FORMAT1(UI_STATIC_LABEL("IPv4"),
                               MAX_IPV4_TEXT_LENGTH,
                               format_ipv4,
                               &relay->ipv4);
                UI_ADD_FORMAT1(UI_STATIC_LABEL("IPv6"),
                               MAX_IPV6_TEXT_LENGTH,
                               format_ipv6,
                               &relay->ipv6);
                UI_ADD_FORMAT1(UI_STATIC_LABEL("Port"),
                               MAX_UINT64_STRING_LENGTH,
                               format_uint16,
                               relay->port.number);
                break;
            case RELAY_SINGLE_HOST_NAME:
                if (relay->dnsNameSize > 0) {
                    UI_ADD_FORMAT2(UI_STATIC_LABEL("DNS name"),
                                   MAX_DNS_NAME_LENGTH,
                                   format_dns_name,
                                   relay->dnsName,
                                   relay->dnsNameSize);
                }
                UI_ADD_FORMAT1(UI_STATIC_LABEL("Port"),
                               MAX_UINT64_STRING_LENGTH,
                               format_uint16,
                               relay->port.number);
                break;
            case RELAY_MULTIPLE_HOST_NAME:
                if (relay->dnsNameSize > 0) {
                    UI_ADD_FORMAT2(UI_STATIC_LABEL("SRV DNS"),
                                   MAX_DNS_NAME_LENGTH,
                                   format_dns_name,
                                   relay->dnsName,
                                   relay->dnsNameSize);
                }
                break;
            // LCOV_EXCL_START
            default:
                LEDGER_ASSERT(false, "Unknown relay format type");
                break;
                // LCOV_EXCL_STOP
        }
        CHECK_COUNT(expected_pairs);
    }
}

void plan_or_render_pool_no_relays(const tx_processing_mode_t *mode) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_POOL_NO_RELAYS;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_STATIC(UI_STATIC_LABEL("Pool relays"), UI_STATIC_LABEL("(none)"));
        CHECK_COUNT(UI_PAIRS_POOL_NO_RELAYS);
    }
}

void plan_or_render_pool_metadata(const tx_processing_mode_t *mode,
                                  const pool_metadata_t *pool_metadata) {
    ASSERT(pool_metadata != NULL);
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_POOL_METADATA;
    } else if (mode->ui_render) {
        START_COUNT();
        if (pool_metadata->urlSize == 0) {
            UI_ADD_STATIC(UI_LABEL_BY_SCREEN("Pool metadata url", "Metadata url"),
                          UI_STATIC_LABEL("(empty)"));
        } else {
            UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Pool metadata url", "Metadata url"),
                           MAX_POOL_METADATA_URL_LENGTH,
                           format_url,
                           pool_metadata->url,
                           pool_metadata->urlSize);
        }
        UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Pool metadata hash", "Metadata hash"),
                       MAX_POOL_METADATA_HASH_STRING_LENGTH,
                       format_hex_bytes,
                       pool_metadata->hash,
                       POOL_METADATA_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_POOL_METADATA);
    }
}

void plan_or_render_pool_no_metadata(const tx_processing_mode_t *mode) {
    if (mode->ui_count_pairs) {
        tx_body_ctx()->total_ui_pairs += UI_PAIRS_POOL_NO_METADATA;
    } else if (mode->ui_render) {
        START_COUNT();
        UI_ADD_STATIC(UI_STATIC_LABEL("Metadata"), UI_STATIC_LABEL("(none)"));
        CHECK_COUNT(UI_PAIRS_POOL_NO_METADATA);
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

void tx_ui_plan_or_render_certificate(const tx_processing_mode_t *mode,
                                      const certificate_data_t *certificate_data) {
    ASSERT(mode != NULL);
    ASSERT(certificate_data != NULL);
    TRACE_MODULE("certificate type=%u count=%d render=%d",
                 (unsigned) certificate_data->type,
                 (int) mode->ui_count_pairs,
                 (int) mode->ui_render);

    switch (certificate_data->type) {
        case CERTIFICATE_STAKE_REGISTRATION:
            plan_or_render_certificate_stake_registration(mode, certificate_data);
            break;

        case CERTIFICATE_STAKE_DEREGISTRATION:
            plan_or_render_certificate_stake_deregistration(mode, certificate_data);
            break;

        case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
            plan_or_render_certificate_stake_registration_conway(mode, certificate_data);
            break;

        case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY:
            plan_or_render_certificate_stake_deregistration_conway(mode, certificate_data);
            break;

        case CERTIFICATE_STAKE_DELEGATION:
            plan_or_render_certificate_stake_delegation(mode, certificate_data);
            break;

        case CERTIFICATE_VOTE_DELEGATION:
            plan_or_render_certificate_vote_delegation(mode, certificate_data);
            break;

        case CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION:
            plan_or_render_certificate_stake_pool_and_drep_delegation(mode, certificate_data);
            break;

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL:
            plan_or_render_certificate_account_registration_delegation_to_stake_pool(
                mode,
                certificate_data);
            break;

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP:
            plan_or_render_certificate_account_registration_delegation_to_drep(mode,
                                                                               certificate_data);
            break;

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP:
            plan_or_render_certificate_account_registration_delegation_to_stake_pool_and_drep(
                mode,
                certificate_data);
            break;

        case CERTIFICATE_AUTHORIZE_COMMITTEE_HOT:
            plan_or_render_certificate_authorize_committee_hot(mode, certificate_data);
            break;

        case CERTIFICATE_RESIGN_COMMITTEE_COLD:
            plan_or_render_certificate_resign_committee_cold(mode, certificate_data);
            if (certificate_data->anchor.isIncluded) {
                plan_or_render_anchor(mode, &certificate_data->anchor);
            }
            break;

        case CERTIFICATE_DREP_REGISTRATION:
            plan_or_render_certificate_drep_registration(mode, certificate_data);
            if (certificate_data->anchor.isIncluded) {
                plan_or_render_anchor(mode, &certificate_data->anchor);
            }
            break;

        case CERTIFICATE_DREP_DEREGISTRATION:
            plan_or_render_certificate_drep_deregistration(mode, certificate_data);
            break;

        case CERTIFICATE_DREP_UPDATE:
            plan_or_render_certificate_drep_update(mode, certificate_data);
            if (certificate_data->anchor.isIncluded) {
                plan_or_render_anchor(mode, &certificate_data->anchor);
            }
            break;

        case CERTIFICATE_STAKE_POOL_RETIREMENT:
            plan_or_render_certificate_pool_retirement(mode, certificate_data);
            break;

        // LCOV_EXCL_START
        case CERTIFICATE_STAKE_POOL_REGISTRATION:
            LEDGER_ASSERT(false, "CERTIFICATE_STAKE_POOL_REGISTRATION handled separately");
            break;
            // LCOV_EXCL_STOP

        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown certificate type");
            break;
            // LCOV_EXCL_STOP
    }
}
