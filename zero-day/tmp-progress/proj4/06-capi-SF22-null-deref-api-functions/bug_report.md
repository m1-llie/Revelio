# NULL Pointer Dereference in Four PROJ C API Functions

## Summary

Four public C API functions in `src/iso19111/c_api.cpp` dereference the `obj` parameter (a `PJ *`) without a NULL guard. The `SANITIZE_CTX(ctx)` macro handles a NULL context but does not validate `obj`. Passing `NULL` as `obj` crashes the process immediately.

**Affected functions:**

| Function | Line | Crash expression |
|---|---|---|
| `proj_normalize_for_visualization` | ~9203 | `obj->alternativeCoordinateOperations.empty()` |
| `proj_get_ellipsoid` | ~2361 | `obj->iso_obj.get()` |
| `proj_get_celestial_body_name` | ~2391 | `obj->iso_obj.get()` |
| `proj_get_prime_meridian` | ~2530 | `obj->iso_obj.get()` |

- **Affected file:** `src/iso19111/c_api.cpp`
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17); latest affected release: PROJ **9.8.1** (2026-04-10)
- **Sanitizer required:** None (plain SIGSEGV); ASAN gives exact trace
- **Impact:** Denial of service — process crash (NULL pointer read)

---

## Vulnerable Code Pattern

All four functions follow this pattern:

```cpp
PJ *proj_get_ellipsoid(PJ_CONTEXT *ctx, const PJ *obj) {
    SANITIZE_CTX(ctx);  // handles NULL ctx only
    // obj is NOT checked for NULL:
    auto ptr = obj->iso_obj.get();  // CRASH if obj == NULL
    ...
}
```

Contrast with `proj_get_area_of_use()`, which does guard `obj`:
```cpp
if (!obj) return false;
```

---

## Proof of Concept

See `capi_SF22_poc.c`. The PoC forks a child process per function to capture each crash independently.

### Reproduction Steps

**Step 1 — Build PROJ 9.8.1 with AddressSanitizer** (one-time):

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
    06-capi-SF22-null-deref-api-functions/capi_SF22_poc.c \
    -L proj-9.8.1/install/lib -lproj \
    -Wl,-rpath,proj-9.8.1/install/lib \
    -o poc_06

ASAN_OPTIONS=detect_leaks=0 \
PROJ_DATA=proj-9.8.1/install/share/proj \
./poc_06
```

> **Note:** ASAN is not strictly required — each function produces a plain SIGSEGV
> without any sanitizer.

### Observed Output

```
=== SF22: Null Pointer Dereference in PROJ C API ===

[ASAN ABORT] proj_normalize_for_visualization -> exit 1
[ASAN ABORT] proj_get_ellipsoid -> exit 1
[ASAN ABORT] proj_get_celestial_body_name -> exit 1
[ASAN ABORT] proj_get_prime_meridian -> exit 1
```

ASAN stack trace for each shows the dereference in `c_api.cpp` at the lines listed above.

---

## Impact

Any caller that receives a NULL `PJ *` from a failed allocation or failed lookup and then passes it directly to these functions will crash the process. This is a common pattern when applications do not rigorously check intermediate results.

**Severity:** Medium — CVSS 3.1 base score **6.2** (`AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`). Rises to **7.5 High** (`AV:N`) if the `PJ *` object is constructed from attacker-controlled input (e.g., a CRS definition string supplied over a network).  
**CWE:** [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)

---

## Suggested Fix

Add a NULL check at the top of each function, consistent with `proj_get_area_of_use()`:

```diff
 PJ *proj_get_ellipsoid(PJ_CONTEXT *ctx, const PJ *obj) {
     SANITIZE_CTX(ctx);
+    if (!obj) { proj_log_error(ctx, __FUNCTION__, "obj is NULL"); return nullptr; }
     auto ptr = obj->iso_obj.get();
```

Apply the same pattern to all four affected functions.
