# NULL Pointer Dereference / `std::logic_error` in `proj_grid_info(NULL)`

## Summary

`proj_grid_info()` in `src/grids.cpp` does not validate the `gridname` parameter before use. Passing `NULL` causes `std::string` construction from a NULL pointer inside `VerticalShiftGridSet::open()`, throwing `std::logic_error: basic_string::_M_construct null not valid`. Because this exception is not caught, the runtime calls `std::terminate()`, aborting the process.

- **Affected file:** `src/grids.cpp`, function `proj_grid_info()`
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17); latest affected release: PROJ **9.8.1** (2026-04-10)
- **Crash type:** `std::terminate()` called after uncaught `std::logic_error`
- **Sanitizer required:** None — plain abort without sanitizers
- **Impact:** Denial of service — process abort (uncaught exception)

---

## Vulnerable Code

```cpp
// src/grids.cpp (~line 3927)
PJ_GRID_INFO proj_grid_info(const char *gridname) {
    PJ_GRID_INFO grinfo = {};
    // No NULL check on gridname before passing it to open():
    auto setPtr = NS_PROJ::VerticalShiftGridSet::open(ctx, gridname);
    //                                                      ^^^^^^^^ NULL → std::string(NULL) → logic_error
```

---

## Proof of Concept

See `grids_SF01_poc.cpp`.

### Reproduction Steps

**Step 1 — Build PROJ 9.8.1** (ASAN not required for this bug; plain build is sufficient):

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
    09-grids-SF01-proj-grid-info-null/grids_SF01_poc.cpp \
    -L proj-9.8.1/install/lib -lproj \
    -Wl,-rpath,proj-9.8.1/install/lib \
    -o poc_09

PROJ_DATA=proj-9.8.1/install/share/proj ./poc_09
```

> **Note:** No sanitizer required — the abort fires unconditionally via `std::terminate()`
> on any standard build.

### Observed Output

```
Testing SF01: proj_grid_info(NULL) - NULL parameter crash
terminate called after throwing an instance of 'std::logic_error'
  what():  basic_string::_M_construct null not valid
Aborted (core dumped)
```

---

## Impact

Any caller that passes `NULL` as the grid name (e.g., from a failed lookup or uninitialized pointer) to `proj_grid_info()` will abort the entire process via unhandled exception.

**Severity:** Medium — CVSS 3.1 base score **6.2** (`AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`).  
**CWE:** [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html), [CWE-248: Uncaught Exception](https://cwe.mitre.org/data/definitions/248.html)

---

## Suggested Fix

```diff
 PJ_GRID_INFO proj_grid_info(const char *gridname) {
     PJ_GRID_INFO grinfo = {};
+    if (!gridname) {
+        return grinfo;  // return empty/zeroed struct
+    }
     ...
```
