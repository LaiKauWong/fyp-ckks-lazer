#include "module_lwe_pke.h"
#include "demo_params.h" 
#include "lazer.h"
#include <stdlib.h>

typedef struct {
    lwe_pke_ctx_t ctx;
    lwe_pke_pk_t pk;
    lwe_pke_sk_t sk;
} LWE_Engine;

#ifdef __cplusplus
extern "C" {
#endif

void* bridge_init(size_t k, unsigned int log2q, int eta) {
    lazer_init(); 
    LWE_Engine *engine = (LWE_Engine*)malloc(sizeof(LWE_Engine));
    
    lwe_pke_ctx_init(engine->ctx, &_param_ring, k, log2q, eta);
    lwe_pke_pk_alloc(engine->pk, engine->ctx);
    lwe_pke_sk_alloc(engine->sk, engine->ctx);
    return engine;
}

void bridge_keygen(void* ptr, const uint8_t seedA[32], const uint8_t seedS[32]) {
    LWE_Engine *engine = (LWE_Engine*)ptr;
    lwe_pke_keygen(engine->ctx, engine->pk, engine->sk, seedA, seedS);
}

void* bridge_encrypt(void* ptr, const uint8_t* msg, size_t msg_bits, const uint8_t seedE[32]) {
    LWE_Engine *engine = (LWE_Engine*)ptr;
    lwe_pke_ct_t *ct = (lwe_pke_ct_t*)malloc(sizeof(lwe_pke_ct_t));
    lwe_pke_ct_alloc(*ct, engine->ctx);
    lwe_pke_encrypt(engine->ctx, *ct, engine->pk, msg, msg_bits, seedE);
    return ct;
}

void bridge_decrypt(void* ptr, void* ct_ptr, uint8_t* msg_out, size_t msg_bits) {
    LWE_Engine *engine = (LWE_Engine*)ptr;
    lwe_pke_ct_t *ct = (lwe_pke_ct_t*)ct_ptr;
    lwe_pke_decrypt(engine->ctx, msg_out, msg_bits, *ct, engine->sk);
}

void bridge_free(void* ptr, void* ct_ptr) {
    if (ptr) {
        LWE_Engine *engine = (LWE_Engine*)ptr;
        lwe_pke_pk_free(engine->pk);
        lwe_pke_sk_free(engine->sk);
        free(engine);
    }
    if (ct_ptr) {
        lwe_pke_ct_t *ct = (lwe_pke_ct_t*)ct_ptr;
        lwe_pke_ct_free(*ct);
        free(ct);
    }
}

#ifdef __cplusplus
}
#endif