#include <stdint.h>
#include <string.h>

#include "fuzz_utils.h"

#ifdef HAVE_SWAP
#include "swap.h"
#include "addressUtilsShelley.h"
#endif

// Fuzz the swap CHECK_ADDRESS callback.
// Input: [path_len][packed BIP44 path][address_to_check string]
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (sigsetjmp(fuzz_exit_jump_ctx.jmp_buf, 1)) {
        return 0;
    }
    fuzzing_reset_state();

#ifdef HAVE_SWAP
    if (size < 1) {
        return 0;
    }
    uint8_t path_length = data[0];
    if ((size_t) 1 + path_length > size) {
        return 0;
    }
    size_t address_length = size - 1 - path_length;


    char address_to_check[MAX_HUMAN_ADDRESS_LENGTH];
    if (address_length >= sizeof(address_to_check)) {
        return 0;
    }
    memcpy(address_to_check, data + 1 + path_length, address_length);
    address_to_check[address_length] = '\0';

    check_address_parameters_t params;
    memset(&params, 0, sizeof(params));
    // Read-only for the call and valid for its duration, so point straight at the input.
    params.address_parameters = (uint8_t *) (data + 1);
    params.address_parameters_length = path_length;
    params.address_to_check = address_to_check;
    params.extra_id_to_check = NULL;
    params.result = 0;

    swap_handle_check_address(&params);
#else
    (void) data;
    (void) size;
#endif
    return 0;
}
