#include "bridge_module_lwe_pke.h"

#include <stdlib.h>
#include <string.h>

#include "lazer.h"
#include "module_lwe_pke.h"
#include "demo_params.h"

// -----------------------------------------------------------------------------
// Internal opaque structs
// -----------------------------------------------------------------------------

struct module_lwe_engine {
    lwe_pke_ctx_t ctx;
    lwe_pke_pk_t pk;
    lwe_pke_sk_t sk;
    int has_keypair;
};

struct module_lwe_ciphertext {
    lwe_pke_ct_t ct;
};

// -----------------------------------------------------------------------------
// Engine lifecycle
// -----------------------------------------------------------------------------

module_lwe_engine_t *bridge_init(int k, unsigned int log2q, int eta) {
    lazer_init();

    module_lwe_engine_t *engine =
        (module_lwe_engine_t *)calloc(1, sizeof(module_lwe_engine_t));
    if (engine == NULL) {
        return NULL;
    }

    if (lwe_pke_ctx_init(engine->ctx, &_param_ring, (size_t)k, log2q, eta) != 0) {
        free(engine);
        return NULL;
    }

    if (lwe_pke_pk_alloc(engine->pk, engine->ctx) != 0) {
        free(engine);
        return NULL;
    }

    if (lwe_pke_sk_alloc(engine->sk, engine->ctx) != 0) {
        lwe_pke_pk_free(engine->pk);
        free(engine);
        return NULL;
    }

    engine->has_keypair = 0;
    return engine;
}

void bridge_free_engine(module_lwe_engine_t *engine) {
    if (engine == NULL) {
        return;
    }

    lwe_pke_sk_free(engine->sk);
    lwe_pke_pk_free(engine->pk);
    free(engine);
}

// -----------------------------------------------------------------------------
// Key generation
// -----------------------------------------------------------------------------

int bridge_keygen(module_lwe_engine_t *engine,
                  const uint8_t seedA[32],
                  const uint8_t seedS[32]) {
    if (engine == NULL || seedA == NULL || seedS == NULL) {
        return -1;
    }

    int rc = lwe_pke_keygen(engine->ctx, engine->pk, engine->sk, seedA, seedS);
    if (rc != 0) {
        return rc;
    }

    engine->has_keypair = 1;
    return 0;
}

// -----------------------------------------------------------------------------
// Ciphertext lifecycle
// -----------------------------------------------------------------------------

void bridge_free_ct(module_lwe_ciphertext_t *ct) {
    if (ct == NULL) {
        return;
    }

    lwe_pke_ct_free(ct->ct);
    free(ct);
}

// -----------------------------------------------------------------------------
// Encrypt / decrypt
// -----------------------------------------------------------------------------

module_lwe_ciphertext_t *bridge_encrypt(module_lwe_engine_t *engine,
                                        const uint8_t *msg,
                                        size_t msg_bitlen,
                                        const uint8_t seedE[32]) {
    if (engine == NULL || msg == NULL || seedE == NULL) {
        return NULL;
    }

    if (!engine->has_keypair) {
        return NULL;
    }

    module_lwe_ciphertext_t *wrapper =
        (module_lwe_ciphertext_t *)calloc(1, sizeof(module_lwe_ciphertext_t));
    if (wrapper == NULL) {
        return NULL;
    }

    if (lwe_pke_ct_alloc(wrapper->ct, engine->ctx) != 0) {
        free(wrapper);
        return NULL;
    }

    int rc = lwe_pke_encrypt(engine->ctx,
                             wrapper->ct,
                             engine->pk,
                             msg,
                             msg_bitlen,
                             seedE);
    if (rc != 0) {
        lwe_pke_ct_free(wrapper->ct);
        free(wrapper);
        return NULL;
    }

    return wrapper;
}

int bridge_decrypt(module_lwe_engine_t *engine,
                   const module_lwe_ciphertext_t *ct,
                   uint8_t *msg_out,
                   size_t msg_bitlen) {
    if (engine == NULL || ct == NULL || msg_out == NULL) {
        return -1;
    }

    if (!engine->has_keypair) {
        return -2;
    }

    return lwe_pke_decrypt(engine->ctx,
                           msg_out,
                           msg_bitlen,
                           ct->ct,
                           engine->sk);
}

//message capacity
size_t bridge_msg_capacity_bits(module_lwe_engine_t *engine) {
    if (engine == NULL) return 0;
    return lwe_pke_msg_capacity_bits(engine->ctx);
}

size_t bridge_msg_capacity_bytes(module_lwe_engine_t *engine) {
    if (engine == NULL) return 0;
    return lwe_pke_msg_capacity_bytes(engine->ctx);
}