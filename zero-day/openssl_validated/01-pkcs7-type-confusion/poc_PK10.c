#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>

int main() {
    OPENSSL_init_crypto(0, NULL);
    
    // PK10: Type confusion with different type combinations
    // Try: set to signedAndEnveloped, then change type to signed
    fprintf(stderr, "Test PK10: signedAndEnveloped → signed type confusion\n");
    PKCS7 *p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signedAndEnveloped);
    fprintf(stderr, "d.signed_and_enveloped = %p\n", (void*)p7->d.signed_and_enveloped);
    // Change type to enveloped (different struct layout)
    ASN1_OBJECT_free(p7->type);
    p7->type = OBJ_nid2obj(NID_pkcs7_enveloped);
    BIO *b = PKCS7_dataInit(p7, NULL);
    fprintf(stderr, "PK10 result: %p\n", (void*)b);
    if (b) BIO_free_all(b);
    ERR_print_errors_fp(stderr);
    PKCS7_free(p7);
    
    // PK09: Use-after-free via BIO memory set to ASN1_STRING
    // PKCS7_dataDecode with content BIO
    fprintf(stderr, "\nTest PK09: Use-after-free via BIO in PKCS7\n");
    PKCS7 *p7b = PKCS7_new();
    PKCS7_set_type(p7b, NID_pkcs7_data);
    // Set content with a BIO that may be freed
    BIO *content_bio = BIO_new_mem_buf("test content", -1);
    // Simulate the UAF path: write content then free bio
    if (p7b->d.data) {
        // d.data is ASN1_OCTET_STRING
        unsigned char *buf = NULL;
        long len = BIO_get_mem_data(content_bio, &buf);
        ASN1_STRING_set(p7b->d.data, buf, len);
    }
    BIO_free(content_bio); // free the BIO — if ASN1_STRING has a pointer into it, UAF
    // Try to use the data
    BIO *out = BIO_new(BIO_s_mem());
    int ret = PKCS7_dataFinal(p7b, out);
    fprintf(stderr, "PK09 dataFinal: %d\n", ret);
    ERR_print_errors_fp(stderr);
    BIO_free(out);
    PKCS7_free(p7b);
    
    fprintf(stderr, "\nAll tests done\n");
    return 0;
}
