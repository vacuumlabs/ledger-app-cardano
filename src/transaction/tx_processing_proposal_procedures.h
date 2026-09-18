/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "buffer.h"
#include "tx.h"
#include "tx_processing.h"

/**
 * Process all proposal_procedures in a transaction.
 *
 * Parses each proposal_procedure from the buffer and dispatches to the shared envelope
 * handling.
 *
 * @param[in]  buf      Buffer with transaction data
 * @param[in]  state    Transaction processing state
 *
 * @return true on success, false on error (send_swo_and_reset already called)
 */
bool tx_process_proposal_procedures(buffer_t *buf, tx_processing_state_t *state);
