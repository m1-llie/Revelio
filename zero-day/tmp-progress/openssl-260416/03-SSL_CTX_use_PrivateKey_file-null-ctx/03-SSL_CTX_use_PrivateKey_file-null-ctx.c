/*
 * PoC: NULL pointer dereference in SSL_CTX_use_PrivateKey_file()
 * Confirmed on: OpenSSL master, commit 6983b5c (2026-04-16)
 *
 * Trigger: SSL_CTX_use_PrivateKey_file(NULL, path, SSL_FILETYPE_PEM)
 * Crash:   ssl_rsa.c:417 — ctx->default_passwd_callback member access through NULL ctx
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>

int main(void)
{
    OPENSSL_init_ssl(0, NULL);

    /*
     * SSL_CTX_use_PrivateKey_file() opens a BIO to the file successfully,
     * then immediately dereferences ctx->default_passwd_callback (line 393)
     * without first checking ctx != NULL.
     *
     * Any readable path works; the crash occurs before the file is parsed.
     */
    SSL_CTX *ctx = NULL;   /* intentionally NULL */
    SSL_CTX_use_PrivateKey_file(ctx, "/dev/null", SSL_FILETYPE_PEM);  /* crash here */

    return 0;
}
