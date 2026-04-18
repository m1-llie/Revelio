#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <string.h>

int main() {
    OPENSSL_init_ssl(0, NULL);
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    SSL *ssl = SSL_new(ctx);
    
    // SF09: SSL_set1_initial_peer_addr with stack buffer smaller than BIO_ADDR
    // BIO_ADDR is a union of sockaddr variants (could be 128 bytes)
    // Passing a 4-byte buffer that ASAN should catch as OOB when copied
    char tiny_buf[4] = {0x02, 0x00, 0x00, 0x01}; // AF_INET = 2
    const BIO_ADDR *fake_addr = (const BIO_ADDR *)tiny_buf;
    
    fprintf(stderr, "SF09: SSL_set1_initial_peer_addr with undersized buffer\n");
    int r = SSL_set1_initial_peer_addr(ssl, fake_addr);
    fprintf(stderr, "returned: %d\n", r);
    ERR_print_errors_fp(stderr);
    
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
