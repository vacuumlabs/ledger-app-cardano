#include <stdint.h>
#include <string.h>

#include "fuzz_utils.h"

#ifdef HAVE_SWAP
#include "swap.h"
#endif

// Fuzz the swap GET_PRINTABLE_AMOUNT callback.
// Input: [is_fee flag][big-endian amount bytes]
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (sigsetjmp(fuzz_exit_jump_ctx.jmp_buf, 1)) {
        return 0;
    }
    fuzzing_reset_state();

#ifdef HAVE_SWAP
    if (size < 1) {
        return 0;
    }
    bool is_fee = (data[0] & 1u) != 0;

    // amount_length is a uint8_t on the wire; cap it and point straight at the input
    // (read-only for the call) — no heap, so a longjmp can't leak.
    size_t amount_bytes = size - 1;
    uint8_t amount_length = (amount_bytes > UINT8_MAX) ? UINT8_MAX : (uint8_t) amount_bytes;

    get_printable_amount_parameters_t params;
    memset(&params, 0, sizeof(params));
    params.amount = (uint8_t *) (data + 1);
    params.amount_length = amount_length;
    params.is_fee = is_fee;

    swap_handle_get_printable_amount(&params);
#else
    (void) data;
    (void) size;
#endif
    return 0;
}
