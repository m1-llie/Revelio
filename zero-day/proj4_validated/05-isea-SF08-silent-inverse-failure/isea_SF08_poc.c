/*
 * SF08 PoC: Silent inverse projection failure in ISEA due to unimplemented configurations
 *
 * Bug description:
 * In PROJ/src/projections/isea.cpp, the pj_isea_data::initialize() function only
 * initializes the Q->p (ISEAPlanarProjection*) pointer for a narrow set of supported
 * configurations (ISEA_PLANE output, aperture=3, resolution=4, standard or polar orientation).
 * For ALL other configurations, Q->p is left as nullptr.
 *
 * The isea_s_inverse() function correctly checks `if (p)` and returns {inf, inf} when
 * p is nullptr. However, it does NOT set an error code (proj_errno). This means:
 *   - Forward projection works fine (it uses the legacy isea_forward() path, not Q->p)
 *   - Inverse projection silently returns infinity coordinates with errno=0
 *   - Callers cannot distinguish successful "no result" from a bug
 *
 * This affects:
 *   - Any non-default +lat_0 or +lon_0 (custom orientation)
 *   - +azi != 0
 *   - +mode=di, +mode=dd, +mode=hex (output != ISEA_PLANE)
 *   - +aperture != 3
 *   - +resolution != 4
 *
 * Compile:
 *   clang++ -std=c++17 -fsanitize=address,undefined -g -O1 \
 *     -I/src/PROJ/include -I/src/PROJ/src \
 *     isea_SF08_poc.c \
 *     /proj4-build/lib/libproj.a \
 *     -lpthread /host-lib/libsqlite3.so.0 -ldl -lm \
 *     -o sf08_poc
 *   ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan ./sf08_poc
 */
#include <stdio.h>
#include <math.h>
#include <assert.h>
#include "proj.h"

static void confirm_bug(PJ_CONTEXT *ctx, const char *proj_str, const char *desc) {
    PJ *P = proj_create(ctx, proj_str);
    if (!P) {
        printf("  [%s] SKIP: creation failed\n", desc);
        return;
    }

    PJ_COORD c;
    c.lp.lam = 0.5; /* ~28.6 deg lon */
    c.lp.phi = 0.3; /* ~17.2 deg lat */

    /* Forward projection succeeds */
    PJ_COORD fwd = proj_trans(P, PJ_FWD, c);
    int fwd_err = proj_errno(P);
    proj_errno_reset(P);

    /* Inverse projection silently fails */
    PJ_COORD inv = proj_trans(P, PJ_INV, fwd);
    int inv_err = proj_errno(P);

    int is_inf = isinf(inv.lp.lam) || isinf(inv.lp.phi);
    int is_nan = isnan(inv.lp.lam) || isnan(inv.lp.phi);

    if ((is_inf || is_nan) && inv_err == 0) {
        printf("  [%s] *** BUG CONFIRMED: fwd=(%f,%f) err=%d, inv=(%f,%f) err=%d (SILENT FAILURE) ***\n",
               desc, fwd.xy.x, fwd.xy.y, fwd_err,
               inv.lp.lam, inv.lp.phi, inv_err);
    } else if (is_inf || is_nan) {
        printf("  [%s] Inverse failed with error %d (expected behavior)\n", desc, inv_err);
    } else {
        printf("  [%s] OK: fwd=(%f,%f), inv=(%f,%f)\n",
               desc, fwd.xy.x, fwd.xy.y, inv.lp.lam, inv.lp.phi);
    }

    proj_destroy(P);
}

int main() {
    PJ_CONTEXT *ctx = proj_context_create();

    printf("=== SF08: ISEA inverse silent failure ===\n\n");

    /* Working case: standard config */
    printf("Working configurations (p != nullptr):\n");
    confirm_bug(ctx, "+proj=isea +R=6371007", "default standard");
    confirm_bug(ctx, "+proj=isea +orient=isea +R=6371007", "+orient=isea");
    confirm_bug(ctx, "+proj=isea +orient=pole +R=6371007", "+orient=pole");

    printf("\nBuggy configurations (p == nullptr, inverse silently returns inf):\n");

    /* Non-default lat_0: silently fails */
    confirm_bug(ctx, "+proj=isea +lat_0=30 +R=6371007", "+lat_0=30");
    confirm_bug(ctx, "+proj=isea +lat_0=45 +R=6371007", "+lat_0=45");
    confirm_bug(ctx, "+proj=isea +lat_0=0 +R=6371007", "+lat_0=0");

    /* Non-zero azi */
    confirm_bug(ctx, "+proj=isea +azi=45 +R=6371007", "+azi=45");

    /* Non-PLANE output modes */
    confirm_bug(ctx, "+proj=isea +mode=di +R=6371007", "+mode=di");
    confirm_bug(ctx, "+proj=isea +mode=dd +R=6371007", "+mode=dd");
    confirm_bug(ctx, "+proj=isea +mode=hex +R=6371007", "+mode=hex");

    /* Non-standard aperture */
    confirm_bug(ctx, "+proj=isea +aperture=4 +R=6371007", "+aperture=4");

    /* Non-standard resolution */
    confirm_bug(ctx, "+proj=isea +resolution=6 +R=6371007", "+resolution=6");
    confirm_bug(ctx, "+proj=isea +resolution=1 +R=6371007", "+resolution=1");

    proj_context_destroy(ctx);
    printf("\nDone.\n");
    return 0;
}
