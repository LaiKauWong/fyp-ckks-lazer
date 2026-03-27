#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WARMUP_TRIALS 50
#define BENCHMARK_TRIALS 1000

double calc_avg_ms(struct timespec start, struct timespec end, int trials) {
    double elapsed_ns = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    return (elapsed_ns / trials) / 1000000.0;
}

int main() {
    int msg_sizes[] = {32, 64, 128, 256, 512, 1024};
    int num_sizes = sizeof(msg_sizes) / sizeof(msg_sizes[0]);
    struct timespec start, end;

    printf("=========================================================================\n");
    printf("Scheme                : OpenSSL RSA-3072 (OAEP PADDING)\n");
    printf("Benchmark trials      : %d\n", BENCHMARK_TRIALS);
    printf("Warmup trials         : %d\n", WARMUP_TRIALS);
    printf("=========================================================================\n");
    printf("Msg(bits)\tKeyGen(ms)\tEncrypt(ms)\tDecrypt(ms)\n");
    printf("-------------------------------------------------------------------------\n");

    for (int s = 0; s < num_sizes; s++) {
        int msg_bits = msg_sizes[s];
        size_t msg_bytes = msg_bits / 8;
        unsigned char *pt = calloc(msg_bytes, 1);
        unsigned char *ct = NULL;
        unsigned char *dec = NULL;
        size_t ct_len, dec_len;
        EVP_PKEY *pkey = NULL;

        EVP_PKEY_CTX *initial_kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        EVP_PKEY_keygen_init(initial_kctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(initial_kctx, 3072);
        EVP_PKEY_keygen(initial_kctx, &pkey);
        EVP_PKEY_CTX_free(initial_kctx);

        clock_gettime(CLOCK_MONOTONIC, &start);
        for(int i=0; i<BENCHMARK_TRIALS; i++) {
            EVP_PKEY *tmp_pkey = NULL;
            EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            EVP_PKEY_keygen_init(kctx);
            EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 3072);
            EVP_PKEY_keygen(kctx, &tmp_pkey);
            EVP_PKEY_free(tmp_pkey); 
            EVP_PKEY_CTX_free(kctx);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double keygen_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
        EVP_PKEY_encrypt_init(ctx);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        
        EVP_PKEY_encrypt(ctx, NULL, &ct_len, pt, msg_bytes);
        ct = malloc(ct_len);

        clock_gettime(CLOCK_MONOTONIC, &start);
        for(int i=0; i<BENCHMARK_TRIALS; i++) {
            size_t tmp_ct_len = ct_len; 
            EVP_PKEY_encrypt(ctx, ct, &tmp_ct_len, pt, msg_bytes);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double encrypt_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

        EVP_PKEY_decrypt_init(ctx);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        dec = malloc(ct_len);

        clock_gettime(CLOCK_MONOTONIC, &start);
        for(int i=0; i<BENCHMARK_TRIALS; i++) {
            size_t tmp_dec_len = ct_len; 
            EVP_PKEY_decrypt(ctx, dec, &tmp_dec_len, ct, ct_len);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double decrypt_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

        printf("%d\t\t%.6f\t%.6f\t%.6f\n", msg_bits, keygen_ms, encrypt_ms, decrypt_ms);

        free(pt); free(ct); free(dec);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
    }
    printf("=========================================================================\n");
    return 0;
}