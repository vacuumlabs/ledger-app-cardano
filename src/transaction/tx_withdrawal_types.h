#pragma once

#include "utils/list.h"
#include "cardano.h"
#include "addressUtils/addressUtilsShelley.h"

// Maximum number of withdrawals per transaction
#define MAX_WITHDRAWALS_PER_TX 10

// Withdrawal credential structure (similar to address params but for staking only)
typedef struct {
    staking_data_source_t type;  // KEY_PATH, KEY_HASH, or SCRIPT_HASH
    union {
        bip44_path_t keyPath;
        uint8_t keyHash[ADDRESS_KEY_HASH_LENGTH];
        uint8_t scriptHash[SCRIPT_HASH_LENGTH];
    };
} withdrawal_credential_t;

// Withdrawal structure (reward withdrawal from staking account)
typedef struct {
    withdrawal_credential_t credential;
    uint64_t amount;
    uint8_t previousRewardAccount[REWARD_ACCOUNT_SIZE];  // For canonical ordering validation
} withdrawal_data_t;

// Withdrawal list item with flist node
typedef struct {
    s_flist_node node;      /// flist node for linked list
    withdrawal_data_t withdrawal_data;
} tx_withdrawal_list_item_t;
