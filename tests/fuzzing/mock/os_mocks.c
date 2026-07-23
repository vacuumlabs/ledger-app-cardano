#include <cx.h>
#include <os.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ux.h>
#include <setjmp.h>

#include "buffer.h"
#include "cardano_constants.h"
#include "fuzz_utils.h"
#include "globals.h"

typedef struct nbgl_warning_s nbgl_warning_t;

int io_send_sw(uint16_t swo) {
    (void) swo;
    return 0;
}

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    (void) buffer;
    (void) bufferLength;
    (void) swo;
    return 0;
}

// Global context for the app
global_ctx_t G_context;
uint16_t G_apdu_error = 0;

// Mock storage for fuzzing
const internal_storage_t N_storage_real = {.expert_mode_enabled = 1,
                                           .silent_pubkey_export_enabled = 0,
                                           .blind_signing_enabled = 0,
                                           .initialized = 1};

int io_send_response_buffers(const buffer_t *buffer_list, size_t buffer_count, uint16_t swo) {
    (void) buffer_list;
    (void) buffer_count;
    (void) swo;
    return 0;
}

void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len) {
    memcpy(dst_adr, src_adr, src_len);
}

bool swap_check_validity(uint64_t amount, tx_output_destination_t *destination) {
    (void) amount;
    (void) destination;
    return true;
}

unsigned int os_serial(unsigned char *serial, unsigned int maxlength) {
    memset(serial, 'A', maxlength);
    return maxlength;
}

void __attribute__((noreturn)) os_sched_exit(bolos_task_status_t exit_code) {
    (void) exit_code;
    siglongjmp(fuzz_exit_jump_ctx.jmp_buf, 1);
}


void __wrap_os_explicit_zero_BSS_segment(void) {
}

void __attribute__((noreturn)) os_lib_end(void) {
    siglongjmp(fuzz_exit_jump_ctx.jmp_buf, 1);
}

try_context_t *current_context = NULL;
try_context_t *try_context_get(void) {
    return current_context;
}

try_context_t *try_context_set(try_context_t *ctx) {
    try_context_t *previous_ctx = current_context;
    current_context = ctx;
    return previous_ctx;
}

void *pic(void *linked_addr) {
    return linked_addr;
}
// void ui_idle(){};
void halt() {
    for (;;);
};

void io_send_buf(unsigned short code, unsigned char *buffer, size_t tx) {
    (void) code;
    (void) buffer;
    (void) tx;
}

unsigned short io_exchange(unsigned char chan, unsigned short tx_len) {
    (void) chan;
    (void) tx_len;
    return 0;
}

unsigned short io_seph_recv(unsigned char *buffer, unsigned short maxlength, unsigned int flags) {
    (void) buffer;
    (void) maxlength;
    (void) flags;
    return 0;
}

uint16_t cx_crc16(const void *buf, size_t len) {
    (void) buf;
    (void) len;
    return 0xFFFF;
}

uint16_t cx_crc16_update(uint16_t crc, const void *buf, size_t len) {
    (void) crc;
    (void) buf;
    (void) len;
    return 0xFFFF;
}

cx_err_t cx_blake2b_init_no_throw(cx_blake2b_t *hash, size_t size) {
    (void) hash;
    (void) size;
    return CX_OK;
}

cx_err_t cx_hash_no_throw(cx_hash_t *hash,
                          uint32_t mode,
                          const uint8_t *in,
                          size_t len,
                          uint8_t *out,
                          size_t out_len) {
    (void) hash;
    (void) mode;
    (void) in;
    (void) len;
    (void) out;
    (void) out_len;
    return CX_OK;
}

size_t cx_hash_get_size(const cx_hash_t *ctx) {
    (void) ctx;
    return 32;
}

void io_seph_send(const unsigned char *buffer, unsigned short length) {
    (void) buffer;
    (void) length;
}

cx_err_t cx_sha3_init_no_throw(cx_sha3_t *hash, size_t size) {
    (void) hash;
    (void) size;
    return CX_OK;
}

unsigned int io_seph_is_status_sent(void) {
    return 0;
}

bolos_bool_t os_perso_isonboarded(void) {
    return (bolos_bool_t) BOLOS_UX_OK;
}

void io_seproxyhal_init_ux(void) {
}

bolos_task_status_t os_sched_last_status(unsigned int task_idx) {
    (void) task_idx;
    return 1;
}

bolos_bool_t os_global_pin_is_validated(void) {
    return (bolos_bool_t) BOLOS_UX_OK;
}

cx_err_t cx_eddsa_get_public_key_no_throw(const cx_ecfp_private_key_t *pv_key,
                                          cx_md_t hashID,
                                          cx_ecfp_public_key_t *pu_key,
                                          uint8_t *a,
                                          size_t a_len,
                                          uint8_t *h,
                                          size_t h_len) {
    (void) pv_key;
    (void) hashID;
    (void) a;
    (void) a_len;
    (void) h;
    (void) h_len;
    pu_key->W_len = 65;
    memset(pu_key->W, 'A', pu_key->W_len);
    return CX_OK;
}

cx_err_t cx_eddsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey,
                                cx_md_t hashID,
                                const uint8_t *hash,
                                size_t hash_len,
                                uint8_t *sig,
                                size_t sig_len) {
    (void) pvkey;
    (void) hashID;

    if (sig == NULL || sig_len == 0) {
        return CX_INVALID_PARAMETER;
    }

    if (hash == NULL || hash_len == 0) {
        memset(sig, 0, sig_len);
        return CX_OK;
    }

    for (size_t i = 0; i < sig_len; i++) {
        // Deterministic non-cryptographic bytes for fuzzing-only signature flow.
        sig[i] = (uint8_t) (hash[i % hash_len] ^ (uint8_t) (0xA5u + i));
    }

    return CX_OK;
}

cx_err_t cx_ecdomain_parameters_length(cx_curve_t cv, size_t *length) {
    // cardano uses CX_CURVE_Ed25519
    if (cv == CX_CURVE_Ed25519) {
        *length = 32;
        return CX_OK;
    }

    siglongjmp(fuzz_exit_jump_ctx.jmp_buf, 1);
    return CX_INVALID_PARAMETER;
}

void os_perso_derive_node_with_seed_key(unsigned int mode,
                                        cx_curve_t curve,
                                        const unsigned int *path,
                                        unsigned int pathLength,
                                        unsigned char *privateKey,
                                        unsigned char *chain,
                                        unsigned char *seed_key,
                                        unsigned int seed_key_length) {
    (void) mode;
    (void) curve;
    (void) path;
    (void) pathLength;
    (void) privateKey;
    (void) chain;
    (void) seed_key;
    (void) seed_key_length;
}

void __attribute__((noreturn)) assert_exit(bool confirm) {
    (void) confirm;
    siglongjmp(fuzz_exit_jump_ctx.jmp_buf, 1);
}

void __attribute__((noreturn)) app_exit(void) {
    siglongjmp(fuzz_exit_jump_ctx.jmp_buf, 1);
}
