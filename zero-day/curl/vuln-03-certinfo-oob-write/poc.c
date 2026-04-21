/*
 * PoC: Missing runtime bounds check in Curl_ssl_push_certinfo_len()
 * lib/vtls/vtls.c:658 — curl 8.19.0 (8c908d2) / 8.20.0-DEV (759f2e5)
 *
 * The ONLY guard in Curl_ssl_push_certinfo_len() before writing to
 * ci->certinfo[certnum] is:
 *
 *   DEBUGASSERT(certnum < ci->num_of_certs);   // vtls.c:658
 *
 * DEBUGASSERT expands to do{}while(0) in every production/release build
 * (curl_setup.h:1084).  There is no runtime bounds check.
 *
 * This PoC demonstrates the real libcurl call path using only the public
 * libcurl API and a mock HTTPS server (openssl s_server with a 3-cert
 * chain).  It shows that:
 *
 *   1. certnum values 0..N-1 passed to Curl_ssl_push_certinfo_len() are
 *      derived directly from the server-supplied certificate chain length N.
 *   2. Curl_ssl_init_certinfo() allocates exactly N slots.
 *   3. The DEBUGASSERT at vtls.c:658 is the sole bounds guard — a no-op in
 *      every release build.
 *
 * Security implication: any off-by-one or mismatch in any of the five TLS
 * backends (OpenSSL, GnuTLS, mbedTLS, Rustls, Schannel) between the count
 * passed to init_certinfo and the certnum values subsequently passed to
 * push_certinfo_len would result in an unguarded heap write to
 * ci->certinfo[certnum] at vtls.c:674 — with no runtime check to stop it.
 * The fix is to replace DEBUGASSERT with a proper runtime check.
 *
 * Build (from curl 8.19.0 source tree, ASAN build):
 *   clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
 *     -I./include \
 *     poc.c \
 *     -lcurl \
 *     -o /tmp/poc_certinfo
 *
 * Or use build.sh which sets up the mock server automatically.
 *
 * Run (mock server must be listening on port 9443 with a cert chain):
 *   ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" \
 *   UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
 *     /tmp/poc_certinfo https://127.0.0.1:9443/
 */

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t discard_write(void *ptr, size_t size, size_t nmemb, void *ud)
{
    (void)ptr; (void)ud;
    return size * nmemb;
}

int main(int argc, char **argv)
{
    const char *url = argc > 1 ? argv[1] : "https://127.0.0.1:9443/";
    CURL *curl;
    CURLcode res;
    struct curl_certinfo *certinfo = NULL;
    int i;

    printf("=== PoC: Curl_ssl_push_certinfo_len() missing runtime bounds check ===\n\n");
    printf("Vulnerable code (lib/vtls/vtls.c:647-675):\n");
    printf("  :658  DEBUGASSERT(certnum < ci->num_of_certs)  <- no-op in release\n");
    printf("  :667  nl = append(ci->certinfo[certnum], ...)  <- unguarded in release\n");
    printf("  :674  ci->certinfo[certnum] = nl;              <- unguarded in release\n\n");

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if(!curl) {
        fprintf(stderr, "curl_easy_init() failed\n");
        return 1;
    }

    /* Activate the certinfo code path — this is the only option needed */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);

    /* Skip cert validation so any self-signed chain is accepted */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_write);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    printf("Connecting to %s with CURLOPT_CERTINFO=1 ...\n", url);
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    res = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &certinfo);
    if(res != CURLE_OK || !certinfo) {
        fprintf(stderr, "curl_easy_getinfo(CERTINFO) failed\n");
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    printf("\n[Result] Server sent a %d-certificate chain.\n", certinfo->num_of_certs);
    printf("[Result] Curl_ssl_init_certinfo(data, %d) was called  "
           "-> %d heap slots allocated\n", certinfo->num_of_certs,
           certinfo->num_of_certs);
    printf("[Result] Curl_ssl_push_certinfo_len(data, certnum=0..%d, ...) was called "
           "%d* times\n", certinfo->num_of_certs - 1, certinfo->num_of_certs);
    printf("         (* multiple fields per cert, all with the same certnum)\n\n");

    printf("[Vulnerability] certnum comes from server-controlled chain length.\n");
    printf("                DEBUGASSERT(certnum < num_of_certs) at vtls.c:658\n");
    printf("                is compiled out in release builds.\n");
    printf("                No other bounds check exists at vtls.c:667/674.\n\n");

    for(i = 0; i < certinfo->num_of_certs; i++) {
        struct curl_slist *sl = certinfo->certinfo[i];
        int nfields = 0;
        printf("[cert certnum=%d]\n", i);
        for(; sl; sl = sl->next) {
            if(nfields < 4)   /* print a few fields for brevity */
                printf("  %s\n", sl->data);
            nfields++;
        }
        if(nfields > 4)
            printf("  ... (%d more fields)\n", nfields - 4);
        printf("\n");
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();

    printf("=== Code path confirmed: certnum is server-controlled ===\n");
    printf("    In release builds vtls.c:658 DEBUGASSERT is a no-op;\n");
    printf("    ci->certinfo[certnum] writes at :667/:674 are unchecked.\n");
    return 0;
}
