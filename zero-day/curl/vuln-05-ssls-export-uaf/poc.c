/*
 *
 * The export callback is called while iterating peer->sessions linked list.
 * If the callback calls curl_easy_ssls_import (which can add sessions, pushing
 * out old ones), and the session being iterated is evicted, the next iteration
 * accesses freed/stale memory via Curl_node_next(n).
 *
 * Test: import 2 sessions, then export and during callback, import a new one
 * to evict the second. The iterator for the second session may be stale.
 *
 * Note: This requires max_sessions to be configured to 1, so that adding a new
 * session evicts the existing one. Then export iterates session 1, callback
 * imports session 2 which evicts session 1 (already processed), so session 2
 * is now in the list. n = Curl_node_next(session1_node) returns NULL or stale.
 *
 * Actually to trigger UAF, we need:
 * - Multiple sessions (max_sessions >= 2)
 * - While iterating session[0], callback removes session[1]
 * - Iterator was pointing at session[1] for the next iteration
 *
 * This test tries to simulate the scenario.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>

static CURL *g_curl = NULL;

/* Valid packed session data template */
static unsigned char make_session(unsigned char id, unsigned char out[20]) {
    out[0] = 0x01;  /* CURL_SPACK_VERSION */
    out[1] = 0x04;  /* CURL_SPACK_TICKET */
    out[2] = 0x00;
    out[3] = 0x04;  /* length = 4 */
    out[4] = 0xDE; out[5] = id; out[6] = 0xBE; out[7] = 0xEF;
    out[8] = 0x02;  /* CURL_SPACK_IETF_ID */
    out[9] = 0x03;
    out[10] = 0x04; /* TLS 1.3 */
    out[11] = 0x03; /* CURL_SPACK_VALID_UNTIL */
    /* valid_until = time_t far in future */
    out[12] = 0x00; out[13] = 0x00; out[14] = 0x00; out[15] = 0x00;
    out[16] = 0x7F; out[17] = 0xFF; out[18] = 0xFF; out[19] = 0xFF;
    return 20;
}

static CURLcode export_callback(CURL *handle, void *userptr,
                                const char *session_key,
                                const unsigned char *shmac, size_t shmac_len,
                                const unsigned char *sdata, size_t sdata_len,
                                curl_off_t valid_until, int ietf_tls_id,
                                const char *alpn, size_t earlydata_max)
{
    (void)handle; (void)userptr; (void)session_key;
    (void)shmac; (void)shmac_len; (void)sdata; (void)sdata_len;
    (void)valid_until; (void)ietf_tls_id; (void)alpn; (void)earlydata_max;

    fprintf(stderr, "[CB] export callback called for session_key=%s\n",
            session_key ? session_key : "(null)");

    /* During export callback, try to import a new session to the same cache.
     * Since lock is only held if share is present (and we have no share),
     * this can modify the sessions list while export is iterating! */
    unsigned char new_sdata[20];
    make_session(0xFF, new_sdata);

    fprintf(stderr, "[CB] Importing new session during export callback (iterator mutation!)\n");
    CURLcode r = curl_easy_ssls_import(g_curl,
                                        "example.com:443:IMPL-OpenSSL:G",
                                        NULL, 0,
                                        new_sdata, 20);
    fprintf(stderr, "[CB] Import during export result: %d\n", r);

    return CURLE_OK;
}

int main(void)
{
    CURLcode res;
    CURLM *multi;
    unsigned char sdata1[20], sdata2[20];

    make_session(0x01, sdata1);
    make_session(0x02, sdata2);

    curl_global_init(CURL_GLOBAL_ALL);
    g_curl = curl_easy_init();
    if(!g_curl) return 1;

    multi = curl_multi_init();
    if(!multi) { curl_easy_cleanup(g_curl); return 1; }
    curl_multi_add_handle(multi, g_curl);

    /* Import 2 TLS 1.3 sessions for the same peer */
    fprintf(stderr, "[*] Importing session 1 for example.com\n");
    res = curl_easy_ssls_import(g_curl,
                                "example.com:443:IMPL-OpenSSL:G",
                                NULL, 0, sdata1, sizeof(sdata1));
    fprintf(stderr, "[*] Import 1 result: %d\n", res);

    fprintf(stderr, "[*] Importing session 2 for example.com\n");
    res = curl_easy_ssls_import(g_curl,
                                "example.com:443:IMPL-OpenSSL:G",
                                NULL, 0, sdata2, sizeof(sdata2));
    fprintf(stderr, "[*] Import 2 result: %d\n", res);

    /* Export sessions - during callback, the callback imports a new session
     * which may evict existing ones and invalidate the iterator */
    fprintf(stderr, "[*] Exporting sessions (callback will try to mutate the list)\n");
    res = curl_easy_ssls_export(g_curl, export_callback, NULL);
    fprintf(stderr, "[*] Export result: %d (%s)\n", res, curl_easy_strerror(res));

    curl_multi_remove_handle(multi, g_curl);
    curl_multi_cleanup(multi);
    curl_easy_cleanup(g_curl);
    curl_global_cleanup();
    return 0;
}
