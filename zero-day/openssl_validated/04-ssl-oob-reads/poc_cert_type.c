#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>

int main() {
    OPENSSL_init_ssl(0, NULL);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    
    // SF06: validate_cert_type OOB read
    // SSL_set1_client_cert_type(ssl, val, len) where len > allocated val size
    unsigned char cert_types[1] = {TLSEXT_cert_type_x509}; // 1 byte
    fprintf(stderr, "Test SF06: SSL_set1_client_cert_type with len=64 but 1-byte buf\n");
    int r = SSL_set1_client_cert_type(ssl, cert_types, 64); // claim 64 bytes
    fprintf(stderr, "SSL_set1_client_cert_type returned: %d\n", r);
    ERR_print_errors_fp(stderr);
    
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
