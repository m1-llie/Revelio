/*
 * Minimal PoC: NULL scalar crash in ecp_nistz256_windowed_mul via EC_POINTs_mul.
 *
 * API contract (ecp_nistp256.c:2090): "we treat NULL scalars as 0"
 * ecp_nistz256.c violates this: BN_num_bits(scalar[i]) is called with scalar[i]=NULL.
 *
 * Note: EC_POINTs_mul is deprecated since OpenSSL 3.0, still compiled in 4.0.0.
 *
 * Tested on OpenSSL 4.0.0 (tag openssl-4.0.0, commit 11b7b6e), Linux x86-64.
 */
#define OPENSSL_API_COMPAT 0x10100000L   /* suppress deprecation warnings */
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <stdio.h>

int main(void) {
    OPENSSL_init_crypto(0, NULL);

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT *result = EC_POINT_new(group);
    const EC_POINT *generator = EC_GROUP_get0_generator(group);

    /* Two points with scalars; scalars[0] = NULL (documented to mean 0) */
    const EC_POINT *points[2]  = { generator, generator };
    BIGNUM *s1 = BN_new(); BN_rand(s1, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    const BIGNUM *scalars[2] = { NULL, s1 };   /* NULL scalar → should be treated as 0 */

    fprintf(stderr, "Calling EC_POINTs_mul with scalars[0]=NULL ...\n");
    fprintf(stderr, "(expected: treat as 0 per contract; actual: crash in ecp_nistz256)\n");

    int ret = EC_POINTs_mul(group, result, NULL, 2, points, scalars, ctx);
    fprintf(stderr, "Returned %d (should not reach here on x86-64)\n", ret);

    BN_free(s1);
    EC_POINT_free(result);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    return 0;
}
