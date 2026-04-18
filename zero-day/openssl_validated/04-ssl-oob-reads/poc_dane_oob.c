#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>

int main() {
    OPENSSL_init_ssl(0, NULL);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_dane_enable(ctx);
    SSL *ssl = SSL_new(ctx);
    SSL_dane_enable(ssl, "example.com");
    
    // SF05: mtype=0 (MATCHING_FULL) skips size validation
    // Pass a 4-byte buffer but claim dlen=256
    unsigned char small_buf[4] = {0x01, 0x02, 0x03, 0x04};
    fprintf(stderr, "Test SF05: SSL_dane_tlsa_add with small buf but large dlen\n");
    int r = SSL_dane_tlsa_add(ssl, 3, 0, 0, small_buf, 256);
    fprintf(stderr, "SSL_dane_tlsa_add returned: %d\n", r);
    ERR_print_errors_fp(stderr);
    
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
