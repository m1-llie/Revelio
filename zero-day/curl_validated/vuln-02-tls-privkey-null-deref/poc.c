/*
 * SF15 PoC - NULL deref in EVP_PKEY_id() when SSL_get_privatekey returns NULL
 *
 * Affected: curl/lib/vtls/openssl.c, client_cert() function, lines 1568-1570
 *
 * The vulnerable code (under #if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)):
 *   EVP_PKEY *priv_key = SSL_get_privatekey(ssl);
 *   if(EVP_PKEY_id(priv_key) == EVP_PKEY_RSA) {   <- no NULL check on priv_key!
 *
 * SSL_get_privatekey() returns NULL if no private key is associated with the SSL object.
 * While this typically follows a successful SSL_CTX_use_PrivateKey_file() call,
 * there are edge cases where SSL_new() can create an SSL without inheriting the key.
 *
 * EVP_PKEY_id(NULL) dereferences NULL -> SIGSEGV
 */
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main(void) {
    fprintf(stderr, "=== SF15 PoC: NULL deref in client_cert() via EVP_PKEY_id(NULL) ===\n\n");

    /* Show that SSL_get_privatekey returns NULL for a fresh SSL object */
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    
    EVP_PKEY *priv_key = SSL_get_privatekey(ssl);
    fprintf(stderr, "SSL_get_privatekey on SSL without loaded key: %p\n", (void*)priv_key);
    fprintf(stderr, "(NULL when no private key is set)\n\n");

    /* Demonstrate that EVP_PKEY_id(NULL) crashes */
    fprintf(stderr, "Calling EVP_PKEY_id(NULL) - the vulnerable pattern in client_cert()...\n");
    fflush(stderr);

    /* VULNERABLE CODE from openssl.c line 1570:
     *   EVP_PKEY *priv_key = SSL_get_privatekey(ssl);
     *   if(EVP_PKEY_id(priv_key) == EVP_PKEY_RSA) {    <- no NULL check!
     */
    int id = EVP_PKEY_id(priv_key);
    fprintf(stderr, "SHOULD NOT REACH HERE (id=%d)\n", id);
    
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
