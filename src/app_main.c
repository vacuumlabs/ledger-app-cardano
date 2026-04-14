/* SPDX-FileCopyrightText: 2016-2025 Ledger */
/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>  // uint*_t
#include <string.h>  // memset, explicit_bzero

#include "os.h"
#include "ux.h"
#include "main_std_app.h"
#include "parser.h"  // command_t, apdu_parser

#include "globals.h"
#include "io.h"
#include "cardano_swo.h"
#include "menu.h"
#include "dispatcher.h"
#include "cardano_settings.h"
#include "mem.h"
#include "utils.h"
#include "app_context.h"
#include "app_main.h"
#ifdef HAVE_SWAP
#include "swap.h"
#endif

#ifndef APP_MAIN_EXTERNAL_GLOBALS
global_ctx_t G_context;

const internal_storage_t N_storage_real;
#endif

void app_main_process_one_apdu(void) {
    int input_len = 0;
    command_t cmd = {0};

    BEGIN_TRY {
        TRY {
            // Receive command bytes in G_io_apdu_buffer
            input_len = io_recv_command();
            if (input_len < 0) {
                TRACE("io_recv_command failure: %d", input_len);
                THROW(EXCEPTION_IO_RESET);
            }

            // Parse APDU command from G_io_apdu_buffer
            if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
                TRACE("BAD LENGTH:");
                TRACE_BUFFER(G_io_apdu_buffer, input_len);
                int io_send_result = io_send_sw(SWO_WRONG_DATA_LENGTH);
                LEDGER_ASSERT(io_send_result >= 0, "io_send_sw failed");
                reset_app_context();
            } else {
                TRACE("CLA=%02X | INS=%02X | P1=%02X | P2=%02X | Lc=%02X | CData=",
                      cmd.cla,
                      cmd.ins,
                      cmd.p1,
                      cmd.p2,
                      cmd.lc);
                TRACE_BUFFER(cmd.data, cmd.lc);

                // Dispatch structured APDU command to handler
                apdu_dispatcher(&cmd);
            }
        }
        CATCH(EXCEPTION_IO_RESET) {
            TRACE("EXCEPTION_IO_RESET");
            CLOSE_TRY;
            app_exit();
        }
        CATCH_OTHER(exception) {
            CLOSE_TRY;
            app_main_handle_unexpected_exception((uint16_t) exception);
        }
        FINALLY {
        }
    }
    END_TRY;
}

/**
 * Handle APDU command received and send back APDU response using handlers.
 */
void app_main(void) {
    // Structured APDU command

    // Initialize SDK memory allocator
    LEDGER_ASSERT(mem_utils_reset_app_heap(), "Failed to initialize memory allocator");

    io_init();

#ifdef HAVE_SWAP
    if (!G_called_from_swap)
#endif
    {
        ui_menu_main();
    }

    // Reset context
    reset_app_context();

    // Initialize the NVM data if required
    if (N_storage.initialized != STORAGE_INITIALIZED) {
        internal_storage_t storage = {0};
        storage.expert_mode_enabled = SETTINGS_NO;
        storage.silent_pubkey_export_enabled = SETTINGS_YES;
        storage.blind_signing_enabled = SETTINGS_NO;
        storage.initialized = STORAGE_INITIALIZED;
        nvm_write((void *) &N_storage, &storage, sizeof(internal_storage_t));
    }

    for (;;) {
        app_main_process_one_apdu();
    }
}
