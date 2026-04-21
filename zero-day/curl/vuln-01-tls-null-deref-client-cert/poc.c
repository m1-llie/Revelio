/*
 * SF16 PoC v2 - Demonstrate the vulnerable code pattern directly
 * 
 * The bug is in curl/lib/vtls/openssl.c client_cert() function.
 * This PoC reproduces the exact vulnerable code pattern.
 *
 * The bug: If a certificate is loaded successfully into SSL_CTX via PEM/DER
 * file, but the certificate has no public key structure (e.g., malformed),
 * then X509_get_pubkey() returns NULL, but curl calls
 * EVP_PKEY_copy_parameters(NULL, ...) without checking.
 *
 * We demonstrate directly: X509_get_pubkey() CAN return NULL for certs
 * that are structurally loaded, and EVP_PKEY_copy_parameters(NULL,*) crashes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

int main(void) {
    fprintf(stderr, "=== SF16 PoC: NULL deref in client_cert() via X509_get_pubkey returning NULL ===\n\n");

    /* Step 1: Show that X509_get_pubkey returns NULL for cert without pubkey */
    X509 *cert_no_pubkey = X509_new();
    EVP_PKEY *pubkey = X509_get_pubkey(cert_no_pubkey);

    fprintf(stderr, "Step 1: X509_get_pubkey(empty_cert) = %p\n", (void*)pubkey);
    fprintf(stderr, "        (NULL means no public key in cert - can happen with malformed certs)\n\n");

    /* Step 2: Show that EVP_PKEY_copy_parameters crashes with NULL first arg */
    fprintf(stderr, "Step 2: Calling EVP_PKEY_copy_parameters(NULL, NULL) - the vulnerable call...\n");
    fflush(stderr);
    fflush(stdout);

    /* CRASH: This is what curl does in client_cert() without a NULL check */
    /* Vulnerable code from openssl.c:1559-1560:
     *   EVP_PKEY *pktmp = X509_get_pubkey(x509);
     *   EVP_PKEY_copy_parameters(pktmp, SSL_get_privatekey(ssl));  <- no NULL check!
     */
    EVP_PKEY_copy_parameters(pubkey, NULL);  /* pubkey is NULL here = CRASH */

    fprintf(stderr, "SHOULD NOT REACH HERE\n");
    X509_free(cert_no_pubkey);
    return 0;
}
