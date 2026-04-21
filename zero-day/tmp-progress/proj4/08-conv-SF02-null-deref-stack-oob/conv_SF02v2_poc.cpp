// SF02 v2 PoC: C API proj_create_conversion with extreme param_count values
// and NULL/invalid params pointer - testing for OOB and NULL deref
//
// The setSingleOperationElements function does:
//   for (int i = 0; i < param_count; i++) { params[i].name ... }
//
// If params is NULL but param_count > 0: NULL pointer dereference
// If params points to small array but param_count is large: OOB read
// These are REAL bugs if they crash - callers must trust the API but
// the C API should defend against misuse.

#include "proj.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void test_conversion(PJ_CONTEXT *ctx, const char *label,
                             const char *method_name,
                             const char *method_code,
                             int param_count,
                             const PJ_PARAM_DESCRIPTION *params) {
    printf("\n[%s]\n", label);
    printf("  method=%s, epsg=%s, param_count=%d, params=%s\n",
           method_name ? method_name : "NULL",
           method_code ? method_code : "NULL",
           param_count,
           params ? "non-null" : "NULL");
    PJ *conv = proj_create_conversion(ctx,
        "test", NULL, NULL,
        method_name, "EPSG", method_code,
        param_count, params);
    if (conv) {
        printf("  RESULT: created OK\n");
        // Try to export to various formats
        const char *ps = proj_as_proj_string(ctx, conv, PJ_PROJ_5, NULL);
        printf("  PROJ string: %s\n", ps ? ps : "NULL");
        const char *wkt = proj_as_wkt(ctx, conv, PJ_WKT2_2019, NULL);
        printf("  WKT2: %s\n", wkt ? "OK" : "NULL");
        proj_destroy(conv);
    } else {
        printf("  RESULT: creation failed: %s\n",
               proj_context_errno_string(ctx, proj_context_errno(ctx)));
    }
}

int main(void) {
    PJ_CONTEXT *ctx = proj_context_create();
    proj_log_level(ctx, PJ_LOG_NONE);

    printf("=== SF02v2: Testing proj_create_conversion with extreme param_count ===\n");

    // Test 1: param_count=0, params=NULL - safe (empty loop)
    test_conversion(ctx, "param_count=0, params=NULL",
                    "Transverse Mercator", "9807", 0, NULL);

    // Test 2: param_count=-1, params=NULL - should be safe (loop not entered)
    test_conversion(ctx, "param_count=-1, params=NULL",
                    "Transverse Mercator", "9807", -1, NULL);

    // Test 3: param_count=1, params=NULL - POTENTIAL NULL DEREF
    // The loop runs once and accesses params[0].name which is NULL deref
    test_conversion(ctx, "param_count=1, params=NULL",
                    "Transverse Mercator", "9807", 1, NULL);

    // Test 4: param_count=5, params=NULL - NULL DEREF
    test_conversion(ctx, "param_count=5, params=NULL",
                    "Transverse Mercator", "9807", 5, NULL);

    // Test 5: Use a valid small params array but lie about param_count
    // This tests OOB read beyond the array boundary
    PJ_PARAM_DESCRIPTION valid_params[2];
    memset(valid_params, 0, sizeof(valid_params));
    valid_params[0].name = "Latitude of natural origin";
    valid_params[0].auth_name = "EPSG";
    valid_params[0].code = "8801";
    valid_params[0].value = 0.0;
    valid_params[0].unit_conv_factor = 0.0174532925199433;
    valid_params[0].unit_name = "degree";
    valid_params[0].unit_type = PJ_UT_ANGULAR;
    valid_params[1].name = "Longitude of natural origin";
    valid_params[1].auth_name = "EPSG";
    valid_params[1].code = "8802";
    valid_params[1].value = 0.0;
    valid_params[1].unit_conv_factor = 0.0174532925199433;
    valid_params[1].unit_name = "degree";
    valid_params[1].unit_type = PJ_UT_ANGULAR;

    // Correct count - baseline
    test_conversion(ctx, "param_count=2 (correct), 2 valid params",
                    "Transverse Mercator", "9807", 2, valid_params);

    // Lie: say there are 100 params but only 2 are valid - OOB read
    test_conversion(ctx, "param_count=100, only 2 valid (OOB!)",
                    "Transverse Mercator", "9807", 100, valid_params);

    // INT_MAX param count with NULL params - huge loop with null deref
    // (only try if we're feeling brave - this WILL crash)
    // Don't do INT_MAX as it would take forever even without crash
    // But small count with NULL pointer IS a real test:
    // Already done above in Test 3 and 4.

    printf("\n=== SF02v2 tests completed ===\n");
    proj_context_destroy(ctx);
    return 0;
}
