#include <stdint.h>
#include <string.h>

#include "fuzz_utils.h"

#ifdef HAVE_SWAP
#include "swap.h"
#include "swap_lib.h"
#include "addressUtilsShelley.h"
#include "app_context.h"
#include "apdu/dispatcher.h"
#endif

// Fuzz the full swap sign-tx flow: establish Exchange-validated params, enable swap
// mode, then stream SIGN_TX APDUs (CLA/INS forced, P1/P2/payload fuzzed).
// Input: [dest_len][dest][amt_len][amt<=8][fee_len][fee<=8][ (p1,p2,lc,data)... ]
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (sigsetjmp(fuzz_exit_jump_ctx.jmp_buf, 1)) {
        return 0;
    }
    fuzzing_reset_state();

#ifdef HAVE_SWAP
    G_called_from_swap = false;
    G_swap_response_ready = false;

    if (size < 1) {
        return 0;
    }
    uint8_t destination_length = data[0];
    data += 1;
    size -= 1;
    if (destination_length >= MAX_HUMAN_ADDRESS_LENGTH || size < destination_length) {
        return 0;
    }
    char destination[MAX_HUMAN_ADDRESS_LENGTH];
    memcpy(destination, data, destination_length);
    destination[destination_length] = '\0';
    data += destination_length;
    size -= destination_length;

    if (size < 1) {
        return 0;
    }
    uint8_t amount_length = data[0];
    data += 1;
    size -= 1;
    if (amount_length > 8) {
        amount_length = 8;  // swap_str_to_u64 rejects >8 bytes
    }
    if (size < amount_length) {
        return 0;
    }
    uint8_t amount[8] = {0};
    memcpy(amount, data, amount_length);
    data += amount_length;
    size -= amount_length;

    if (size < 1) {
        return 0;
    }
    uint8_t fee_length = data[0];
    data += 1;
    size -= 1;
    if (fee_length > 8) {
        fee_length = 8;
    }
    if (size < fee_length) {
        return 0;
    }
    uint8_t fee[8] = {0};
    memcpy(fee, data, fee_length);
    data += fee_length;
    size -= fee_length;

    static const char empty_extra_id[] = "";
    create_transaction_parameters_t swap_params;
    memset(&swap_params, 0, sizeof(swap_params));
    swap_params.destination_address = destination;
    swap_params.destination_address_extra_id = (char *) empty_extra_id;
    swap_params.amount = amount;
    swap_params.amount_length = amount_length;
    swap_params.fee_amount = fee;
    swap_params.fee_amount_length = fee_length;

    if (!swap_copy_transaction_parameters(&swap_params)) {
        return 0;
    }
    G_called_from_swap = true;
    G_swap_response_ready = false;

    static const uint8_t dummy = 0;
    while (size >= 3) {
        command_t cmd = {0};
        cmd.cla = CLA;
        cmd.ins = INS_SIGN_TX;
        cmd.p1 = data[0];
        cmd.p2 = data[1];
        cmd.lc = data[2];
        data += 3;
        size -= 3;
        if (size < cmd.lc) {
            break;
        }

        // Point at the input (read-only for the call) — no heap, so a swap_reject_and_exit
        // longjmp mid-dispatch can't leak.
        cmd.data = (cmd.lc > 0) ? (uint8_t *) data : (uint8_t *) &dummy;

        apdu_dispatcher(&cmd);
        apdu_response_state_force_reset();

        data += cmd.lc;
        size -= cmd.lc;
    }

    G_called_from_swap = false;
    G_swap_response_ready = false;
#else
    (void) data;
    (void) size;
#endif
    return 0;
}
