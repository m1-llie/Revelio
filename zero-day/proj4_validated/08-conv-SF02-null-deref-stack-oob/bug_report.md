# NULL Pointer Dereference in `setSingleOperationElements()` via `proj_create_conversion()`

## Summary

`setSingleOperationElements()` in `src/iso19111/c_api.cpp` does not validate the `params` pointer before dereferencing it in a loop. Calling `proj_create_conversion()` or `proj_create_transformation()` with `param_count > 0` and `params = NULL` causes a NULL pointer dereference (SIGSEGV) at `c_api.cpp:4446`.

- **Affected file:** `src/iso19111/c_api.cpp`, line ~4446
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17)
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

```bash
docker run --rm \
  -v /path/to/bugs:/bugs \
  -v /path/to/PROJ-latest:/src/PROJ-latest:ro \
  -v /path/to/proj4-latest-build:/proj4-latest-build:ro \
  vulagent/proj4-asan:latest bash -c "
    clang++ -std=c++17 -fsanitize=address -g -O1 \
      -I/src/PROJ-latest/src -I/src/PROJ-latest/include \
      /bugs/08-conv-SF02-null-deref-stack-oob/conv_SF02_poc.cpp \
      /proj4-latest-build/lib/libproj.a \
      -lpthread /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 -ldl -lm \
      -o /tmp/poc_08

    ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan /tmp/poc_08
  "
```

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
