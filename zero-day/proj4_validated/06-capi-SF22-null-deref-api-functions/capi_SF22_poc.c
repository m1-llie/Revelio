/*
 * SF22 - Null Pointer Dereference in Multiple PROJ C API Functions
 *
 * Affected functions in src/iso19111/c_api.cpp:
 *   - proj_normalize_for_visualization() @ line 9203
 *   - proj_get_ellipsoid()               @ line 2361
 *   - proj_get_celestial_body_name()     @ line 2391
 *   - proj_get_prime_meridian()          @ line 2530
 *
 * All functions dereference 'obj' (a PJ*) without checking if it is NULL first.
 * SANITIZE_CTX only sanitizes the context, not obj.
 *
 * Compile:
 *   clang++ -std=c++17 -fsanitize=address -g -O1 \
 *     -I/src/PROJ/include -I/src/PROJ/src \
 *     capi_SF22_poc.c \
 *     /proj4-build/lib/libproj.a \
 *     -lpthread /host-lib/libsqlite3.so.0 -ldl -lm \
 *     -o poc_sf22
 *
 * Run:
 *   ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan ./poc_sf22
 */

#include <proj.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static PJ_CONTEXT *g_ctx = NULL;

static void test_normalize(void) {
    printf("[*] Calling proj_normalize_for_visualization(ctx, NULL)...\n");
    fflush(stdout);
    /* Crashes at c_api.cpp:9203: if (!obj->alternativeCoordinateOperations.empty()) */
    proj_normalize_for_visualization(g_ctx, NULL);
    printf("[!] No crash (unexpected)\n");
}

static void test_ellipsoid(void) {
    printf("[*] Calling proj_get_ellipsoid(ctx, NULL)...\n");
    fflush(stdout);
    /* Crashes at c_api.cpp:2361: auto ptr = obj->iso_obj.get(); */
    proj_get_ellipsoid(g_ctx, NULL);
    printf("[!] No crash (unexpected)\n");
}

static void test_celestial(void) {
    printf("[*] Calling proj_get_celestial_body_name(ctx, NULL)...\n");
    fflush(stdout);
    /* Crashes at c_api.cpp:2391: const BaseObject *ptr = obj->iso_obj.get(); */
    proj_get_celestial_body_name(g_ctx, NULL);
    printf("[!] No crash (unexpected)\n");
}

static void test_prime_meridian(void) {
    printf("[*] Calling proj_get_prime_meridian(ctx, NULL)...\n");
    fflush(stdout);
    /* Crashes at c_api.cpp:2530: auto ptr = obj->iso_obj.get(); */
    proj_get_prime_meridian(g_ctx, NULL);
    printf("[!] No crash (unexpected)\n");
}

static void run_test(void (*fn)(void), const char *desc) {
    pid_t pid = fork();
    if (pid == 0) {
        g_ctx = proj_context_create();
        fn();
        proj_context_destroy(g_ctx);
        exit(0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            printf("[CRASH] %s -> signal %d (SIGSEGV=11)\n\n", desc, WTERMSIG(status));
        } else if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            printf("[ASAN ABORT] %s -> exit %d\n\n", desc, WEXITSTATUS(status));
        } else {
            printf("[SAFE] %s\n\n", desc);
        }
    }
}

int main(void) {
    printf("=== SF22: Null Pointer Dereference in PROJ C API ===\n\n");
    run_test(test_normalize,      "proj_normalize_for_visualization");
    run_test(test_ellipsoid,      "proj_get_ellipsoid");
    run_test(test_celestial,      "proj_get_celestial_body_name");
    run_test(test_prime_meridian, "proj_get_prime_meridian");
    return 0;
}
