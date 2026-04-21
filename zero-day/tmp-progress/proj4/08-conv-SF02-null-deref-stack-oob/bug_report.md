# NULL Pointer Dereference in `setSingleOperationElements()` via `proj_create_conversion()`

## Summary

`setSingleOperationElements()` in `src/iso19111/c_api.cpp` does not validate the `params` pointer before dereferencing it in a loop. Calling `proj_create_conversion()` or `proj_create_transformation()` with `param_count > 0` and `params = NULL` causes a NULL pointer dereference (SIGSEGV) at `c_api.cpp:4446`.

- **Affected file:** `src/iso19111/c_api.cpp`, line ~4446
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17); latest affected release: PROJ **9.8.1** (2026-04-10)
- **Crash address:** `c_api.cpp:4446` — `params[i].name` access through NULL
- **Sanitizer required:** None (plain SIGSEGV); ASAN gives exact trace
- **Impact:** Denial of service — process crash (NULL pointer dereference)

---

## Vulnerable Code

```cpp
// src/iso19111/c_api.cpp:4443-4449
for (int i = 0; i < param_count; i++) {
    // No NULL check on 'params' before this loop!
    propParam.set(IdentifiedObject::NAME_KEY,
                  params[i].name ? params[i].name : "unnamed");  // line 4446: CRASH
    ...
}
```

The caller contract (`proj_create_conversion()`) accepts `param_count > 0` with `params == NULL`, and there is no pre-loop guard.

---

## Proof of Concept

See `conv_SF02_poc.cpp`. The PoC calls `proj_create_conversion()` with `param_count=1` and `params=NULL`.

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
    08-conv-SF02-null-deref-stack-oob/conv_SF02_poc.cpp \
    -L proj-9.8.1/install/lib -lproj \
    -Wl,-rpath,proj-9.8.1/install/lib \
    -o poc_08

ASAN_OPTIONS=detect_leaks=0 \
PROJ_DATA=proj-9.8.1/install/share/proj \
./poc_08
```

> **Note:** ASAN is not strictly required — the NULL dereference produces a plain
> SIGSEGV without any sanitizer.

### Observed Output

```
==PID==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
The signal is caused by a READ memory access.
    #0 setSingleOperationElements(...)  c_api.cpp:4446:33
    #1 proj_create_conversion  c_api.cpp:4524:9
    #2 test_bug1_null_deref(pj_ctx*)  conv_SF02_poc.cpp:45
    #3 main  conv_SF02_poc.cpp:109
SUMMARY: AddressSanitizer: SEGV c_api.cpp:4446 in setSingleOperationElements(...)
```

---

## Impact

Any caller that passes `param_count > 0` with a NULL `params` array to `proj_create_conversion()` or `proj_create_transformation()` crashes the process.

**Severity:** Medium — CVSS 3.1 base score **6.2** (`AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`). Rises to **7.5 High** (`AV:N`) if conversion parameters are derived from attacker-controlled input.  
**CWE:** [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)

---

## Suggested Fix

```diff
 static PJ *setSingleOperationElements(..., int param_count, const PJ_PARAM_DESCRIPTION *params, ...) {
+    if (param_count > 0 && !params) {
+        proj_log_error(ctx, __FUNCTION__, "params is NULL but param_count > 0");
+        return nullptr;
+    }
     ...
     for (int i = 0; i < param_count; i++) {
```
