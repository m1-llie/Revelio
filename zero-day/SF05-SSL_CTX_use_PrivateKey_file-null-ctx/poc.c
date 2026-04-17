/*
 * PoC: SF05 — NULL pointer dereference in SSL_CTX_use_PrivateKey_file()
 * Target: OpenSSL 3.3 (openssl33/ssl/ssl_rsa.c)
 *
 * Trigger: call SSL_CTX_use_PrivateKey_file(NULL, path, SSL_FILETYPE_PEM)
 * Crash:   ssl_rsa.c:393 — ctx->default_passwd_callback deref with NULL ctx
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
