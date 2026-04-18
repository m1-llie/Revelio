# Stack Overflow via Unbounded Recursion in `DerivedCRS::_exportToJSON()` and PROJJSON Parsing

## Summary

Two related unbounded-recursion paths exist in PROJ's PROJJSON handling:

1. **Parser path** — `proj_create()` feeds deeply nested PROJJSON into `nlohmann::json`, whose recursive copy constructor exhausts the stack.
2. **Export path** — `DerivedCRS::_exportToJSON()` (`crs.cpp:4234`) recursively calls `baseCRS()->_exportToJSON()` with no depth limit on chains of `DerivedGeographicCRS`.

Both paths crash with a stack overflow when nesting depth is large enough.

- **Affected files:** `src/iso19111/crs.cpp` (line 4234), `src/iso19111/io.cpp`
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17)
- **Sanitizer required:** AddressSanitizer (ASAN) — also reproducible without sanitizer at higher depths
- **Impact:** Denial of service — process crash (stack exhaustion)

---

## Vulnerable Code

### Path 1: JSON parsing (`proj_create`)

`nlohmann::json` (bundled at `include/proj/internal/vendor/nlohmann/json.hpp`) has no explicit maximum nesting depth. A PROJJSON string with thousands of nested `"base_crs"` objects causes recursive construction/copy of the JSON value tree, exhausting the stack.

### Path 2: JSON export (`crs.cpp:4234`)

```cpp
// src/iso19111/crs.cpp:4230-4240
void DerivedCRS::_exportToJSON(JSONFormatter *formatter) const {
    ...
    auto &anchor = formatter->MakeObjectContext(...);
    ...
    baseCRS()->_exportToJSON(formatter);  // line 4234: UNBOUNDED RECURSION
    derivingConversionRef()->_exportToJSON(formatter);
    ...
}
```

No depth counter exists. A `DerivedGeographicCRS` whose `base_crs` is itself a `DerivedGeographicCRS` (and so on) recurses arbitrarily deep.

---

## Proof of Concept

Three PoCs are provided:

| File | Trigger |
|------|---------|
| `crs_SF01_gen.py` | Generates deeply nested PROJJSON (usage: `python3 crs_SF01_gen.py 5000 > input.json`) |
| `crs_SF01_poc_capi.cpp` | Calls `proj_create()` + `proj_as_projjson()` with generated input |
| `crs_SF01_poc_cppapi.cpp` | Builds chain via internal C++ API, calls `exportToJSON()` directly |

### Reproduction Steps

```bash
# 1. Generate input
python3 crs_SF01_gen.py 5000 > /tmp/sf01_5000.json

# 2. Run inside Docker (using reduced stack to trigger faster)
docker run --rm \
  -v /path/to/bugs:/bugs \
  -v /path/to/PROJ-latest:/src/PROJ-latest:ro \
  -v /path/to/proj4-latest-build:/proj4-latest-build:ro \
  -v /tmp/sf01_5000.json:/tmp/sf01_5000.json:ro \
  vulagent/proj4-asan:latest bash -c "
    clang++ -std=c++17 -fsanitize=address -g -O1 \
      -I/src/PROJ-latest/src -I/src/PROJ-latest/include \
      /bugs/02-crs-SF01-projjson-stack-overflow/crs_SF01_poc_capi.cpp \
      /proj4-latest-build/lib/libproj.a \
      -lpthread /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 -ldl -lm \
      -o /tmp/poc_02

    # Reduce stack to expose the bug more reliably
    (ulimit -s 512; ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan /tmp/poc_02 /tmp/sf01_5000.json)
  "
```

### Observed Output (parser path, 1000-depth JSON, 512 KB stack)

```
JSON length: 412393 bytes
Creating object from JSON...
==PID==ERROR: AddressSanitizer: stack-overflow on address 0x7ffc... (pc ...)
SUMMARY: AddressSanitizer: stack-overflow
==PID==ABORTING
```

---

## Impact

Any application that accepts PROJJSON from untrusted sources and calls `proj_create()`, or that serializes deeply nested CRS chains via `proj_as_projjson()`, can be crashed. This is a denial-of-service vector.

---

## Suggested Fix

**Parser path:** Enforce a maximum nesting depth in the PROJJSON parser before passing the JSON to nlohmann, similar to the WKT parser's `recLevel == 16` guard.

**Export path:** Add a depth counter to `DerivedCRS::_exportToJSON()`:

```diff
 void DerivedCRS::_exportToJSON(JSONFormatter *formatter) const {
+    if (formatter->depth() > MAX_EXPORT_DEPTH)
+        throw io::FormattingException("CRS chain too deep to export");
     ...
     baseCRS()->_exportToJSON(formatter);
```
