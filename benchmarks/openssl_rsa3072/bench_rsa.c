#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NTRIALS 1000
#define WARMUP_TRIALS 100
#define PT_LEN 32   /* 256 bits */

static double diff_ms(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1000.0 +
           (double)(b.tv_nsec - a.tv_nsec) / 1e6;
}

static void print_errors(void) {
    ERR_print_errors_fp(stderr);
}

int main(void) {
    int ret = 1;

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *enc_ctx = NULL;
    EVP_PKEY_CTX *dec_ctx = NULL;
    unsigned char *ct = NULL;
    unsigned char *dec = NULL;

    struct timespec s, e;
    double t_kg = 0.0, t_enc = 0.0, t_dec = 0.0;

    unsigned char pt[PT_LEN];
    for (size_t i = 0; i < PT_LEN; i++) {
        pt[i] = (unsigned char)(i ^ 0xAA);
    }

    /* --- KeyGen setup --- */
    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (kctx == NULL ||
        EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 3072) <= 0) {
        print_errors();
        goto cleanup;
    }

    /* --- KeyGen warmup --- */
    for (int i = 0; i < WARMUP_TRIALS; i++) {
        EVP_PKEY *tmp = NULL;
        if (EVP_PKEY_keygen(kctx, &tmp) <= 0) {
            print_errors();
            goto cleanup;
        }
        EVP_PKEY_free(tmp);
    }

    /* --- KeyGen benchmark --- */
    clock_gettime(CLOCK_MONOTONIC, &s);
    for (int i = 0; i < NTRIALS; i++) {
        EVP_PKEY *tmp = NULL;
        if (EVP_PKEY_keygen(kctx, &tmp) <= 0) {
            print_errors();
            goto cleanup;
        }
        if (i == NTRIALS - 1) {
            pkey = tmp;   /* keep last keypair for encrypt/decrypt */
        } else {
            EVP_PKEY_free(tmp);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &e);
    t_kg = diff_ms(s, e) / NTRIALS;

    if (pkey == NULL) {
        fprintf(stderr, "Key generation produced no key\n");
        goto cleanup;
    }

    int pk_len = i2d_PUBKEY(pkey, NULL);
    int sk_len = i2d_PrivateKey(pkey, NULL);
    if (pk_len <= 0 || sk_len <= 0) {
        print_errors();
        goto cleanup;
    }

    /* --- Encrypt setup --- */
    enc_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (enc_ctx == NULL ||
        EVP_PKEY_encrypt_init(enc_ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        print_errors();
        goto cleanup;
    }

    size_t ct_len = 0;
    if (EVP_PKEY_encrypt(enc_ctx, NULL, &ct_len, pt, PT_LEN) <= 0) {
        print_errors();
        goto cleanup;
    }

    ct = malloc(ct_len);
    if (ct == NULL) {
        fprintf(stderr, "malloc(ct) failed\n");
        goto cleanup;
    }

    /* --- Encrypt warmup --- */
    for (int i = 0; i < WARMUP_TRIALS; i++) {
        size_t tmp_len = ct_len;
        if (EVP_PKEY_encrypt(enc_ctx, ct, &tmp_len, pt, PT_LEN) <= 0) {
            print_errors();
            goto cleanup;
        }
    }

    /* --- Encrypt benchmark --- */
    clock_gettime(CLOCK_MONOTONIC, &s);
    for (int i = 0; i < NTRIALS; i++) {
        size_t tmp_len = ct_len;
        if (EVP_PKEY_encrypt(enc_ctx, ct, &tmp_len, pt, PT_LEN) <= 0) {
            print_errors();
            goto cleanup;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &e);
    t_enc = diff_ms(s, e) / NTRIALS;

    /* Prepare one explicit ciphertext for decrypt benchmark */
    {
        size_t tmp_len = ct_len;
        if (EVP_PKEY_encrypt(enc_ctx, ct, &tmp_len, pt, PT_LEN) <= 0) {
            print_errors();
            goto cleanup;
        }
        ct_len = tmp_len;
    }

    /* --- Decrypt setup --- */
    dec_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (dec_ctx == NULL ||
        EVP_PKEY_decrypt_init(dec_ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        print_errors();
        goto cleanup;
    }

    size_t dec_cap = 0;
    if (EVP_PKEY_decrypt(dec_ctx, NULL, &dec_cap, ct, ct_len) <= 0) {
        print_errors();
        goto cleanup;
    }

    dec = malloc(dec_cap);
    if (dec == NULL) {
        fprintf(stderr, "malloc(dec) failed\n");
        goto cleanup;
    }

    /* --- Decrypt warmup --- */
    for (int i = 0; i < WARMUP_TRIALS; i++) {
        size_t tmp_len = dec_cap;
        if (EVP_PKEY_decrypt(dec_ctx, dec, &tmp_len, ct, ct_len) <= 0) {
            print_errors();
            goto cleanup;
        }
    }

    /* --- Decrypt benchmark --- */
    size_t last_dec_len = 0;
    clock_gettime(CLOCK_MONOTONIC, &s);
    for (int i = 0; i < NTRIALS; i++) {
        size_t tmp_len = dec_cap;
        if (EVP_PKEY_decrypt(dec_ctx, dec, &tmp_len, ct, ct_len) <= 0) {
            print_errors();
            goto cleanup;
        }
        last_dec_len = tmp_len;
    }
    clock_gettime(CLOCK_MONOTONIC, &e);
    t_dec = diff_ms(s, e) / NTRIALS;

    if (last_dec_len != PT_LEN || memcmp(pt, dec, PT_LEN) != 0) {
        fprintf(stderr, "Correctness check failed! Mismatch at 256 bits.\n");
        goto cleanup;
    }

    printf("=========================================================\n");
    printf("OpenSSL RSA-3072 OAEP Benchmark\n");
    printf("=========================================================\n");
    printf("Scheme                : RSA-3072 (OAEP)\n");
    printf("Plaintext size        : %d bits (%d bytes)\n", PT_LEN * 8, PT_LEN);
    printf("Public key size       : %d bytes (DER)\n", pk_len);
    printf("Private key size      : %d bytes (DER)\n", sk_len);
    printf("Ciphertext size       : %zu bytes\n", ct_len);
    printf("Encryption seed size  : internal RNG\n");
    printf("Benchmark trials      : %d\n", NTRIALS);
    printf("Warmup trials         : %d\n", WARMUP_TRIALS);
    printf("=========================================================\n");
    printf("KeyGen (ms)           : %.6f\n", t_kg);
    printf("Encrypt (ms)          : %.6f\n", t_enc);
    printf("Decrypt (ms)          : %.6f\n", t_dec);
    printf("=========================================================\n\n");

    printf("CSV:\n");
    printf("scheme,msg_bits,keygen_ms,encrypt_ms,decrypt_ms,pk_bytes,sk_bytes,ct_bytes\n");
    printf("openssl_rsa3072_oaep,%d,%.6f,%.6f,%.6f,%d,%d,%zu\n",
           PT_LEN * 8,
           t_kg,
           t_enc,
           t_dec,
           pk_len,
           sk_len,
           ct_len);

    ret = 0;

cleanup:
    free(ct);
    free(dec);
    EVP_PKEY_CTX_free(enc_ctx);
    EVP_PKEY_CTX_free(dec_ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    return ret;
}