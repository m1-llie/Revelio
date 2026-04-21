/*
 * PoC: NULL pointer dereference in SSL_CTX_use_certificate_ASN1()
 * Confirmed on: OpenSSL master, commit 6983b5c (2026-04-16)
 *
 * Trigger: SSL_CTX_use_certificate_ASN1(NULL, len, data)
 * Crash:   ssl_rsa.c:367 — ctx->libctx member access through NULL ctx
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
