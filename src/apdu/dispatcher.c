/* SPDX-FileCopyrightText: 2016-2025 Ledger */
/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"
#include "io.h"
#include "ledger_assert.h"

#include "parser.h"
#include "dispatcher.h"
#include "globals.h"
#include "cardano_swo.h"
#include "assert.h"
#include "utils.h"
#include "app_context.h"
#include "get_serial.h"
#include "get_version.h"
#include "get_app_name.h"
#include "get_public_key.h"
#include "sign_tx.h"
#include "sign_tx_aux_data.h"
#include "sign_opcert.h"
#include "derive_address.h"
#include "derive_native_script_hash.h"
#include "sign_cvote.h"
#include "sign_msg.h"

#ifdef DEBUG
#include "debug_settings.h"
#endif

#ifdef HAVE_SWAP
#include "swap.h"
#include "swap_error_code_helpers.h"
#include "swap_lib.h"
#endif

#ifdef TRACE_HANDLERS
#define TRACE_MODULE(...) TRACE("[dispatcher] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0
#endif

/**
 * Map request type to its expected instruction
 * Used to detect instruction interleaving attacks
 *
 * Precondition: req_type != REQUEST_NONE
 */
static command_e req_type_to_instruction(request_type_e req_type) {
    ASSERT(req_type != REQUEST_NONE);

    switch (req_type) {
        case REQUEST_EXPORT_PUBKEY:
            return INS_GET_PUBLIC_KEY;
        case REQUEST_SIGN_TRANSACTION:
            return INS_SIGN_TX;
        case REQUEST_SIGN_OPCERT:
            return INS_SIGN_OPCERT;
        case REQUEST_DERIVE_ADDRESS:
            return INS_DERIVE_ADDRESS;
        case REQUEST_DERIVE_NATIVE_SCRIPT_HASH:
            return INS_DERIVE_NATIVE_SCRIPT_HASH;
        case REQUEST_CVOTE:
            return INS_SIGN_CVOTE;
        case REQUEST_SIGN_MSG:
            return INS_SIGN_MSG;
        // LCOV_EXCL_START
        default:
            ASSERT(false);
            return INS_GET_VERSION;  // Unreachable
                                     // LCOV_EXCL_STOP
    }
}

void apdu_dispatcher(const command_t *cmd) {
    ASSERT(cmd != NULL);
    TRACE_MODULE("G_context.req_type: %d", G_context.req_type);

    if (cmd->cla != CLA) {
        // No handler is invoked for malformed top-level APDUs; send the terminal SW directly.
        TRACE("Invalid CLA: got=0x%02x expected=0x%02x", cmd->cla, CLA);
        int io_send_result = io_send_sw(SWO_INVALID_CLA);
        ASSERT(io_send_result >= 0);
        return;
    }

    if (apdu_response_is_pending_ux()) {
        TRACE_MODULE("Deferred APDU still pending UX, rejecting new command ins=%d", cmd->ins);
        int io_send_result = io_send_sw(SWO_COMMAND_NOT_ALLOWED);
        ASSERT(io_send_result >= 0);
        return;
    }

    // Guard against instruction interleaving attacks
    // If an operation is in progress, only allow the same instruction to continue
    if (G_context.req_type != REQUEST_NONE) {
        command_e expected_ins = req_type_to_instruction(G_context.req_type);
        if (cmd->ins != expected_ins) {
            TRACE("Instruction interleaving detected: current=%d (req_type=%d), attempted=%d",
                  expected_ins,
                  G_context.req_type,
                  cmd->ins);
            int io_send_result = io_send_sw(SWO_COMMAND_NOT_ALLOWED);
            ASSERT(io_send_result >= 0);
            return;
        }
        TRACE_MODULE("Same instruction continuing: ins=%d", cmd->ins);
    } else {
        // This is a new request, ensure we start with a clean context
        reset_app_context();
    }

    apdu_response_begin(cmd->ins);

    // Log the appropriate state based on request type
    switch (G_context.req_type) {
        case REQUEST_SIGN_TRANSACTION:
            TRACE_MODULE("G_context.state.tx_state: %d", G_context.state.tx_state);
            break;
        case REQUEST_SIGN_OPCERT:
            TRACE_MODULE("G_context.state.opcert_state: %d", G_context.state.opcert_state);
            break;
        case REQUEST_DERIVE_ADDRESS:
            TRACE_MODULE("G_context.state.derive_address_state: %d",
                         G_context.state.derive_address_state);
            break;
        default:
            // Stateless operations (GET_PUBLIC_KEY, GET_VERSION, etc.)
            break;
    }

#ifdef HAVE_SWAP
    // In swap mode, only allow a restricted set of instructions
    if (G_called_from_swap) {
        if (cmd->ins != INS_GET_VERSION && cmd->ins != INS_GET_PUBLIC_KEY &&
            cmd->ins != INS_DERIVE_ADDRESS && cmd->ins != INS_SIGN_TX) {
            TRACE("Instruction %d not allowed in swap mode", cmd->ins);
            swap_reject_and_exit(SWAP_EC_ERROR_WRONG_METHOD, SWAP_APP_CODE_BAD_INS);
        }
    }
#endif

    // Create data buffer upfront from APDU data
    buffer_t data_buffer = {.ptr = cmd->data, .size = cmd->lc, .offset = 0};

#define REJECT_INCORRECT_P1_P2_IF(condition)         \
    do {                                             \
        if (condition) {                             \
            send_swo_and_reset(SWO_INCORRECT_P1_P2); \
            apdu_response_finalize_after_handler();  \
            return;                                  \
        }                                            \
    } while (0)
#define REJECT_USED_P1(p1) REJECT_INCORRECT_P1_P2_IF((p1) != P1_UNUSED)
#define REJECT_USED_P2(p2) REJECT_INCORRECT_P1_P2_IF((p2) != P2_UNUSED)

    switch (cmd->ins) {
        case INS_GET_SERIAL:
            REJECT_USED_P1(cmd->p1);
            REJECT_USED_P2(cmd->p2);
            handler_get_serial(&data_buffer);
            apdu_response_finalize_after_handler();
            return;

        case INS_GET_VERSION:
            REJECT_USED_P1(cmd->p1);
            REJECT_USED_P2(cmd->p2);
            handler_get_version(&data_buffer);
            apdu_response_finalize_after_handler();
            return;

        case INS_GET_APP_NAME:
            REJECT_USED_P1(cmd->p1);
            REJECT_USED_P2(cmd->p2);
            handler_get_app_name(&data_buffer);
            apdu_response_finalize_after_handler();
            return;

        case INS_GET_PUBLIC_KEY: {
            REJECT_USED_P1(cmd->p1);
            REJECT_USED_P2(cmd->p2);
            handler_get_public_key(&data_buffer);
            apdu_response_finalize_after_handler();
            return;
        }

        case INS_DERIVE_ADDRESS:
            REJECT_USED_P2(cmd->p2);
            switch (cmd->p1) {
                case P1_ADDRESS_RETURN:
                case P1_ADDRESS_DISPLAY:
                    handler_derive_address(&data_buffer, cmd->p1);
                    apdu_response_finalize_after_handler();
                    return;
                default:
                    send_swo_and_reset(SWO_INCORRECT_P1_P2);
                    apdu_response_finalize_after_handler();
                    return;
            }
            ASSERT(false);
            return;
        case INS_DERIVE_NATIVE_SCRIPT_HASH:
            REJECT_USED_P2(cmd->p2);
            switch (cmd->p1) {
                case P1_NATIVE_SCRIPT_INIT:
                case P1_NATIVE_SCRIPT_START_COMPLEX:
                case P1_NATIVE_SCRIPT_ADD_SIMPLE:
                case P1_NATIVE_SCRIPT_FINISH:
                    handler_derive_native_script_hash(&data_buffer, cmd->p1);
                    apdu_response_finalize_after_handler();
                    return;
                default:
                    send_swo_and_reset(SWO_INCORRECT_P1_P2);
                    apdu_response_finalize_after_handler();
                    return;
            }

        case INS_SIGN_TX:
            if (cmd->p1 == P1_TX_AUX_DATA) {
                if (cmd->p2 != P2_AUX_DATA_INIT && cmd->p2 != P2_AUX_DATA_DELEGATION) {
                    send_swo_and_reset(SWO_INCORRECT_P1_P2);
                    apdu_response_finalize_after_handler();
                    return;
                }

                handler_sign_tx_aux_data(&data_buffer, cmd->p2);
                apdu_response_finalize_after_handler();
                return;
            }

            // for other p1 values, p2 must be unused
            REJECT_USED_P2(cmd->p2);

            if (cmd->p1 == P1_TX_SIGN_WITNESS) {
                handler_sign_tx_witness(&data_buffer);
                apdu_response_finalize_after_handler();
                return;
            }

            handler_sign_tx(&data_buffer, cmd->p1);
            apdu_response_finalize_after_handler();
            return;

        case INS_SIGN_OPCERT: {
            REJECT_USED_P1(cmd->p1);
            REJECT_USED_P2(cmd->p2);
            handler_sign_opcert(&data_buffer);
            apdu_response_finalize_after_handler();
            return;
        }

        case INS_SIGN_CVOTE: {
            REJECT_USED_P2(cmd->p2);
            switch (cmd->p1) {
                case P1_CVOTE_INIT:
                case P1_CVOTE_CHUNK:
                case P1_CVOTE_CONFIRM:
                    handler_sign_cvote(&data_buffer, cmd->p1);
                    apdu_response_finalize_after_handler();
                    return;
                default:
                    send_swo_and_reset(SWO_INCORRECT_P1_P2);
                    apdu_response_finalize_after_handler();
                    return;
            }
        }

        case INS_SIGN_MSG: {
            REJECT_USED_P2(cmd->p2);
            switch (cmd->p1) {
                case P1_SIGN_MSG_INIT:
                case P1_SIGN_MSG_CHUNK:
                case P1_SIGN_MSG_CONFIRM:
                    handler_sign_msg(&data_buffer, cmd->p1);
                    apdu_response_finalize_after_handler();
                    return;
                default:
                    send_swo_and_reset(SWO_INCORRECT_P1_P2);
                    apdu_response_finalize_after_handler();
                    return;
            }
        }

#ifdef DEBUG
        case INS_DEBUG_SET_SETTINGS: {
            // Debug-only command to set app settings for testing
            REJECT_USED_P1(cmd->p1);
            REJECT_USED_P2(cmd->p2);
            handler_debug_set_settings(&data_buffer);
            apdu_response_finalize_after_handler();
            return;
        }
#endif

        default:
            send_swo_and_reset(SWO_INVALID_INS);
            apdu_response_finalize_after_handler();
            return;
    }

#undef REJECT_USED_P2
#undef REJECT_USED_P1
#undef REJECT_INCORRECT_P1_P2_IF
#undef TRACE_MODULE
}
