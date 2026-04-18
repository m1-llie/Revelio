# NULL Pointer Dereference / `std::logic_error` in `proj_grid_info(NULL)`

## Summary

`proj_grid_info()` in `src/grids.cpp` does not validate the `gridname` parameter before use. Passing `NULL` causes `std::string` construction from a NULL pointer inside `VerticalShiftGridSet::open()`, throwing `std::logic_error: basic_string::_M_construct null not valid`. Because this exception is not caught, the runtime calls `std::terminate()`, aborting the process.

- **Affected file:** `src/grids.cpp`, function `proj_grid_info()`
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17)
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

```bash
docker run --rm \
  -v /path/to/bugs:/bugs \
  -v /path/to/PROJ-latest:/src/PROJ-latest:ro \
  -v /path/to/proj4-latest-build:/proj4-latest-build:ro \
  vulagent/proj4-asan:latest bash -c "
    clang++ -std=c++17 -fsanitize=address -g -O1 \
      -I/src/PROJ-latest/src -I/src/PROJ-latest/include \
      /bugs/09-grids-SF01-proj-grid-info-null/grids_SF01_poc.cpp \
      /proj4-latest-build/lib/libproj.a \
      -lpthread /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 -ldl -lm \
      -o /tmp/poc_09

    ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan /tmp/poc_09
  "
```

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
