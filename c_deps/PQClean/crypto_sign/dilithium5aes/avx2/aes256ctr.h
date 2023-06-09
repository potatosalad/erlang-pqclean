#ifndef PQCLEAN_DILITHIUM5AES_AVX2_AES256CTR_H
#define PQCLEAN_DILITHIUM5AES_AVX2_AES256CTR_H

#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>


#define AES256CTR_BLOCKBYTES 64

typedef struct {
    __m128i rkeys[16];
    __m128i n;
} aes256ctr_ctx;

void PQCLEAN_DILITHIUM5AES_AVX2_aes256ctr_init(aes256ctr_ctx *state,
        const uint8_t key[32],
        uint64_t nonce);

void PQCLEAN_DILITHIUM5AES_AVX2_aes256ctr_squeezeblocks(uint8_t *out,
        size_t nblocks,
        aes256ctr_ctx *state);

#endif
