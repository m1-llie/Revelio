#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

int main() {
    OPENSSL_init_crypto(0, NULL);
    
    // PK20: NULL deref in PKCS7_dataInit when p7 is NULL
    fprintf(stderr, "Test PK20: PKCS7_dataInit(NULL, NULL)\n");
    BIO *bio = PKCS7_dataInit(NULL, NULL);
    fprintf(stderr, "PKCS7_dataInit(NULL) returned: %p\n", (void*)bio);
    if (bio) BIO_free_all(bio);
    
    // PK03: NULL deref when p7->d.signed_data is NULL
    fprintf(stderr, "Test PK03: PKCS7_dataInit with signed type but null d.sign\n");
    PKCS7 *p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signed);
    // d.sign is allocated by PKCS7_set_type, but let's verify
    fprintf(stderr, "p7->d.sign = %p\n", (void*)p7->d.sign);
    BIO *b = PKCS7_dataInit(p7, NULL);
    fprintf(stderr, "PKCS7_dataInit returned: %p\n", (void*)b);
    if (b) BIO_free_all(b);
    PKCS7_free(p7);
    
    // PK08: Type confusion - set type to enveloped, set d.sign, then change type
    fprintf(stderr, "Test PK08: type confusion\n");
    PKCS7 *p7b = PKCS7_new();
    PKCS7_set_type(p7b, NID_pkcs7_enveloped);
    // Overwrite type OID to cause type confusion
    if (p7b->type) {
        ASN1_OBJECT_free(p7b->type);
        p7b->type = OBJ_nid2obj(NID_pkcs7_signed);
    }
    BIO *b2 = PKCS7_dataInit(p7b, NULL);
    fprintf(stderr, "Type confusion dataInit returned: %p\n", (void*)b2);
    if (b2) BIO_free_all(b2);
    ERR_print_errors_fp(stderr);
    PKCS7_free(p7b);
    
    fprintf(stderr, "All tests done\n");
    return 0;
}
