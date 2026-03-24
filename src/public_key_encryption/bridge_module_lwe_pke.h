#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct module_lwe_engine module_lwe_engine_t;
typedef struct module_lwe_ciphertext module_lwe_ciphertext_t;

// Engine lifecycle
module_lwe_engine_t *bridge_init(int k, unsigned int log2q, int eta);
void bridge_free_engine(module_lwe_engine_t *engine);

// Key generation
int bridge_keygen(module_lwe_engine_t *engine,
                  const uint8_t seedA[32],
                  const uint8_t seedS[32]);

// Ciphertext lifecycle
void bridge_free_ct(module_lwe_ciphertext_t *ct);

// Encrypt / decrypt
module_lwe_ciphertext_t *bridge_encrypt(module_lwe_engine_t *engine,
                                        const uint8_t *msg,
                                        size_t msg_bitlen,
                                        const uint8_t seedE[32]);

int bridge_decrypt(module_lwe_engine_t *engine,
                   const module_lwe_ciphertext_t *ct,
                   uint8_t *msg_out,
                   size_t msg_bitlen);

size_t bridge_msg_capacity_bits(module_lwe_engine_t *engine);
size_t bridge_msg_capacity_bytes(module_lwe_engine_t *engine);

#ifdef __cplusplus
}
#endif