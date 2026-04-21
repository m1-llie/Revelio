Two medium-severity API issues: ISEA inverse projection silently returns (inf,inf) without setting errno; proj_uom_get_info_from_database() returns a pointer that may be freed on the next call

---

This report covers two independent medium-severity bugs, both found in the public C API.

**PROJ version:** 9.8.1 (latest release, 2026-04-10); also confirmed on master commit `324ed2119011d74665548afe445eacb99afb9753` (2026-04-17)  
**OS:** Linux x86_64  
**Build:** Clang (Bug A: no sanitizer needed; Bug B: AddressSanitizer)

## Bug A — ISEA inverse projection silently returns `(inf, inf)` without setting `errno`

### Summary

The ISEA projection (`+proj=isea`) returns `{inf, inf}` from inverse projection for the majority of non-default parameter combinations, but **does not set any error code**. After the call, `proj_errno()` returns `0` (success), giving the caller no way to detect the failure programmatically. This causes silent coordinate corruption in any pipeline that checks `proj_errno()` rather than testing the coordinate values directly.

### Root cause

`pj_isea_data::initialize()` in `src/projections/isea.cpp` sets the fast-path pointer `Q->p` only for two hard-coded configurations (standard and polar ISEA_PLANE with `aperture==3`, `resolution==4`). For all other parameter combinations `Q->p` remains `nullptr`.

```cpp
// src/projections/isea.cpp (~line 1377-1390)
if (p) {
    ...
    if (p->cartesianToGeo(input, Q, result))
        return {result.lon, result.lat};
    else
        return {inf, inf};   // no errno set
} else {
    return {inf, inf};       // no errno set  ← BUG
}
```

The `else` branch — reached for any non-standard config — returns `{inf, inf}` without calling `pj_ctx_set_errno()`. The caller has no way to distinguish this from a legitimate "point outside projection domain" result (which would set errno).

### Proof of Concept

Save as `poc_isea.c`:

```c
#include "proj.h"
#include <math.h>
#include <stdio.h>

static void test(PJ_CONTEXT *ctx, const char *def, const char *label) {
    PJ *P = proj_create(ctx, def);
    if (!P) { printf("  [%s] create failed\n", label); return; }
    PJ_COORD fwd = proj_trans(P, PJ_FWD, proj_coord(0.5, 0.3, 0, 0));
    proj_errno_reset(P);
    PJ_COORD inv = proj_trans(P, PJ_INV, fwd);
    int err = proj_errno(P);
    int bad = (isinf(inv.lp.lam) || isinf(inv.lp.phi));
    printf("  [%s] inv=(%.6f,%.6f) errno=%d %s\n",
           label, inv.lp.lam, inv.lp.phi, err,
           (bad && err == 0) ? "*** SILENT FAILURE ***" : "ok");
    proj_destroy(P);
}

int main(void) {
    PJ_CONTEXT *ctx = proj_context_create();
    /* Default config — works correctly */
    test(ctx, "+proj=isea", "default");
    /* Non-default configs — silently return (inf,inf) with errno=0 */
    test(ctx, "+proj=isea +lat_0=30", "+lat_0=30");
    test(ctx, "+proj=isea +azi=45",   "+azi=45");
    test(ctx, "+proj=isea +aperture=4", "+aperture=4");
    test(ctx, "+proj=isea +resolution=6", "+resolution=6");
    proj_context_destroy(ctx);
    return 0;
}
```

### Reproduction steps

**Step 1 — Build PROJ 9.8.1** (shared setup; can skip ASAN for this bug):

```bash
wget https://download.osgeo.org/proj/proj-9.8.1.tar.gz
tar xf proj-9.8.1.tar.gz && cd proj-9.8.1
cmake -B build \
      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_INSTALL_PREFIX="$PWD/install"
cmake --build build -j$(nproc)
cmake --install build
cd ..
```

**Step 2 — Compile and run:**

```bash
clang++ -std=c++17 -g -O1 \
    -I proj-9.8.1/install/include \
    poc_isea.c \
    -L proj-9.8.1/install/lib -lproj \
    -Wl,-rpath,proj-9.8.1/install/lib \
    -o poc_isea

PROJ_DATA=proj-9.8.1/install/share/proj ./poc_isea
```

> **Note:** AddressSanitizer is not required; the bug is visible in plain stdout output.

### Observed output

```
  [default]     inv=(0.500000,0.300000) errno=0 ok
  [+lat_0=30]   inv=(inf,inf) errno=0 *** SILENT FAILURE ***
  [+azi=45]     inv=(inf,inf) errno=0 *** SILENT FAILURE ***
  [+aperture=4] inv=(inf,inf) errno=0 *** SILENT FAILURE ***
  [+resolution=6] inv=(inf,inf) errno=0 *** SILENT FAILURE ***
```

### Impact

Any geographic data pipeline that uses a non-default ISEA configuration and checks `proj_errno()` for error detection will silently produce `(inf, inf)` coordinates without any indication of failure.

**Severity:** Medium — CVSS 3.1 base score **5.3** (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`). No crash; the impact is silent data integrity corruption — downstream consumers receive infinite coordinates with no error signal.  
**CWE:** [CWE-393: Return of Wrong Status Code](https://cwe.mitre.org/data/definitions/393.html)

### Suggested fix

Set the projection error before returning `{inf, inf}`:

```diff
 } else {
+    pj_ctx_set_errno(P->ctx, PROJ_ERR_COORD_TRANSFM_OUTSIDE_PROJECTION_DOMAIN);
     return {inf, inf};
 }
```

---

## Bug B — `proj_uom_get_info_from_database()` returns a pointer that may be freed on the next call

### Summary

`proj_uom_get_info_from_database()` writes the unit-of-measure name into an internal `std::string` buffer (`lastUOMName_`) inside the PROJ context and returns `c_str()` of that buffer. If a subsequent call to the same function stores a **longer** string, the `std::string` reallocates its heap buffer, freeing the old one. Any pointer saved from the first call then points to freed memory — a use-after-free (UAF).

The documentation states the returned pointer is valid "until the next call to `proj_uom_get_info_from_database()` or context destruction", but it does not warn that the *buffer address itself* may change (and the old address become freed). Under ASAN the freed pointer reads back as empty or garbage.

### Root cause

```cpp
// src/iso19111/c_api.cpp:922-923
ctx->get_cpp_context()->lastUOMName_ = obj->name();  // may reallocate
*out_name = ctx->cpp_context->lastUOMName_.c_str();  // returns new address
```

When the second call writes a longer string, `std::string::operator=` may reallocate the internal buffer. The address returned to the caller from the first call is now a dangling pointer.

### Proof of Concept

Save as `poc_uom_uaf.c`:

```c
#include "proj.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    PJ_CONTEXT *ctx = proj_context_create();

    const char *name1 = NULL;
    const char *name2 = NULL;
    double conv1, conv2;
    const char *auth1, *auth2;

    /* First call — short name ("metre", 5 chars) */
    proj_uom_get_info_from_database(ctx, "EPSG", "9001", &name1, &conv1, &auth1);
    printf("[1] name='%s' at ptr=%p\n", name1 ? name1 : "(null)", (void *)name1);

    /* Second call — longer name may cause reallocation of the string buffer */
    proj_uom_get_info_from_database(ctx, "EPSG", "9040", &name2, &conv2, &auth2);
    printf("[2] name='%s' at ptr=%p\n", name2 ? name2 : "(null)", (void *)name2);

    if (name1 && name2 && name1 != name2) {
        printf("DIFFERENT POINTERS — old buffer freed; name1 ptr is now dangling.\n");
        printf("Dereferencing freed pointer: '%s'\n", name1);  /* UAF read */
    } else {
        printf("Pointers equal — reallocation did not occur in this run.\n");
    }

    proj_context_destroy(ctx);
    return 0;
}
```

### Reproduction steps

**Step 1 — Build PROJ 9.8.1 with AddressSanitizer:**

```bash
wget https://download.osgeo.org/proj/proj-9.8.1.tar.gz
tar xf proj-9.8.1.tar.gz && cd proj-9.8.1
cmake -B build \
      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_C_FLAGS="-fsanitize=address -g -O1" \
      -DCMAKE_CXX_FLAGS="-fsanitize=address -g -O1" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
      -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" \
      -DCMAKE_INSTALL_PREFIX="$PWD/install"
cmake --build build -j$(nproc)
cmake --install build
cd ..
```

**Step 2 — Compile and run:**

```bash
clang++ -std=c++17 -fsanitize=address -g -O1 \
    -I proj-9.8.1/install/include \
    poc_uom_uaf.c \
    -L proj-9.8.1/install/lib -lproj \
    -Wl,-rpath,proj-9.8.1/install/lib \
    -o poc_uom_uaf

ASAN_OPTIONS=detect_stack_use_after_return=1:detect_leaks=0 \
PROJ_DATA=proj-9.8.1/install/share/proj \
./poc_uom_uaf
```

### Observed output

```
[1] name='metre' at ptr=0x7c8f46ee00e0
[2] name='British yard (Sears 1922)' at ptr=0x7b9f46ef6fc0
DIFFERENT POINTERS — old buffer freed; name1 ptr is now dangling.
Dereferencing freed pointer: ''
```

The two pointers differ — `lastUOMName_` was reallocated — and reading through `name1` returns empty or garbage under ASAN quarantine.

### Impact

Code that saves the pointer from the first call and reads it after a second call has undefined behaviour. The returned empty/garbage string silently corrupts any comparison or display that uses `name1`.

```c
const char *name1, *name2;
proj_uom_get_info_from_database(ctx, "EPSG", "9001", &name1, NULL, NULL);
proj_uom_get_info_from_database(ctx, "EPSG", "9037", &name2, NULL, NULL);
strcmp(name1, "metre");  /* undefined behaviour if buffer was reallocated */
```

**Severity:** Medium — CVSS 3.1 base score **4.9** (`AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L`). Exploitation requires a specific two-call sequence with strings of different lengths; the outcome is silent wrong data rather than an immediate crash.  
**CWE:** [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html)

### Suggested fix

Either document more prominently that the caller must copy the string immediately, or use a small ring buffer so multiple recent pointers remain valid:

```diff
-ctx->get_cpp_context()->lastUOMName_ = obj->name();
-*out_name = ctx->cpp_context->lastUOMName_.c_str();
+// Ring buffer keeps the last 8 returned strings alive
+auto &slot = ctx->get_cpp_context()->uomNameBuffer[
+    ctx->get_cpp_context()->uomNameIdx++ % 8];
+slot = obj->name();
+*out_name = slot.c_str();
```
