/*
 * Standalone reproducer: heap-buffer-overflow in dnsmasq log_query()
 *
 * Affected code: src/cache.c, function log_query()
 *   Line 2357-2358:
 *     else if (flags & F_KEYTAG)
 *       sprintf(daemon->addrbuff, arg, addr->log.keytag, addr->log.algo, addr->log.digest);
 *
 * Buffer allocation: src/option.c:5967
 *   daemon->addrbuff = safe_malloc(ADDRSTRLEN);
 *   where ADDRSTRLEN = INET6_ADDRSTRLEN = 46 (dnsmasq.h:171)
 *
 * Vulnerable format string (src/dnssec.c:1104):
 *   "DS for keytag %hu, algo %hu, digest %hu (not supported)"
 *   Max output with wire-legal values:
 *     "DS for keytag 65535, algo 255, digest 255 (not supported)"
 *     = 57 chars + null terminator = 58 bytes > 46-byte buffer
 *     -> OVERFLOW by 12 bytes
 *
 * Wire value constraints (from dnssec.c:1095-1099):
 *   GETSHORT(keytag, p)  -> uint16_t -> max 65535 (5 decimal digits)
 *   algo = *p++          -> uint8_t  -> max 255   (3 decimal digits)
 *   digest = *p++;       -> uint8_t  -> max 255   (3 decimal digits)
 *
 * Trigger conditions:
 *   1. dnsmasq compiled with HAVE_DNSSEC (default on Debian/Ubuntu)
 *   2. Running with --dnssec --log-queries
 *   3. Upstream/MITM DNS server returns DS record with:
 *      key_tag=65535, algorithm=255, digest_type=255
 *      (algo=255 and digest=255 are IANA-unassigned, so
 *       ds_digest_name(255)==NULL and algo_digest_name(255)==NULL
 *       triggers the "(not supported)" branch at dnssec.c:1099-1104)
 *
 * Build and run:
 *   clang -fsanitize=address,undefined -g -o poc poc_reproducer.c
 *   ASAN_OPTIONS=detect_leaks=0 ./poc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* src/dnsmasq.h:171 */
#define ADDRSTRLEN 46

int main(void) {
    /* Mirrors: daemon->addrbuff = safe_malloc(ADDRSTRLEN); [option.c:5967] */
    char *addrbuff = (char *)malloc(ADDRSTRLEN);
    if (!addrbuff) return 1;

    /* Max real wire values: keytag=65535, algo=255, digest=255
     * Stored as unsigned short in union all_addr.log [dnsmasq.h:343-346] */
    unsigned short keytag = 65535;
    unsigned short algo   = 255;
    unsigned short digest = 255;

    /* Format string from dnssec.c:1104 */
    const char *fmt = "DS for keytag %hu, algo %hu, digest %hu (not supported)";

    int needed = snprintf(NULL, 0, fmt, keytag, algo, digest) + 1;
    printf("Buffer size : %d bytes\n", ADDRSTRLEN);
    printf("String needs: %d bytes\n", needed);
    printf("Overflow by : %d bytes\n\n", needed - ADDRSTRLEN);

    /* Mirrors: sprintf(daemon->addrbuff, arg,
     *                  addr->log.keytag, addr->log.algo, addr->log.digest);
     * [cache.c:2358] */
    sprintf(addrbuff, fmt, keytag, algo, digest);

    free(addrbuff);
    return 0;
}
