/*
 * Minimal PoC: NULL pointer write in fix_rsa_padding_mode() /
 * fix_rsa_pss_saltlen() when p2 = NULL is passed to EVP_PKEY_CTX_get_rsa_padding
 * or EVP_PKEY_CTX_get_rsa_pss_saltlen.
 *
 * EVP_PKEY_CTX_get_rsa_padding() and EVP_PKEY_CTX_get_rsa_pss_saltlen() have
 * no NULL check on their output-pointer argument. The ctrl translation layer
 * stores the pointer in ctx->orig_p2 and then unconditionally writes through it.
 *
 * Expected: return an error when the output pointer is NULL.
 * Actual: crash (store to null pointer of type 'int').
 *
 * Tested on OpenSSL 4.0.0 (tag openssl-4.0.0, commit 11b7b6e).
 */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>

int main(void) {
    /* Generate RSA key */
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 1024);
    if (!pkey) { ERR_print_errors_fp(stderr); return 1; }

    /* --- Test 1: EVP_PKEY_CTX_get_rsa_padding with NULL output --- */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);

    int padding = -1;
    fprintf(stderr, "Normal call (valid pointer): ret=%d, padding=%d\n",
            EVP_PKEY_CTX_get_rsa_padding(ctx, &padding), padding);

    fprintf(stderr, "Calling EVP_PKEY_CTX_get_rsa_padding(ctx, NULL) ...\n");
    /* Crashes: fix_rsa_padding_mode writes *(int*)NULL = RSA_PKCS1_PADDING */
    int ret = EVP_PKEY_CTX_get_rsa_padding(ctx, NULL);
    fprintf(stderr, "Returned %d (should not reach here)\n", ret);

    EVP_PKEY_CTX_free(ctx);

    /* --- Test 2: EVP_PKEY_CTX_get_rsa_pss_saltlen with NULL output --- */
    EVP_PKEY_CTX *pss_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_sign_init(pss_ctx);
    EVP_PKEY_CTX_set_rsa_padding(pss_ctx, RSA_PKCS1_PSS_PADDING);

    fprintf(stderr, "Calling EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, NULL) ...\n");
    /* Crashes: fix_rsa_pss_saltlen writes *(int*)NULL = saltlen */
    ret = EVP_PKEY_CTX_get_rsa_pss_saltlen(pss_ctx, NULL);
    fprintf(stderr, "Returned %d (should not reach here)\n", ret);

    EVP_PKEY_CTX_free(pss_ctx);
    EVP_PKEY_free(pkey);
    return 0;
}
