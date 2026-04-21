# Stack Overflow via Unbounded Recursion in `DerivedCRS::_exportToJSON()` and PROJJSON Parsing

## Summary

Two related unbounded-recursion paths exist in PROJ's PROJJSON handling:

1. **Parser path** — `proj_create()` feeds deeply nested PROJJSON into `nlohmann::json`, whose recursive copy constructor exhausts the stack.
2. **Export path** — `DerivedCRS::_exportToJSON()` (`crs.cpp:4234`) recursively calls `baseCRS()->_exportToJSON()` with no depth limit on chains of `DerivedGeographicCRS`.

Both paths crash with a stack overflow when nesting depth is large enough.

- **Affected files:** `src/iso19111/crs.cpp` (line 4234), `src/iso19111/io.cpp`
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17); latest affected release: PROJ **9.8.1** (2026-04-10)
- **Sanitizer required:** AddressSanitizer (ASAN) — also reproducible without sanitizer at higher depths
- **Impact:** Denial of service — process crash (stack exhaustion)


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


## Proof of Concept

Three PoCs are provided:

| File | Trigger |
|------|---------|
| `crs_SF01_gen.py` | Generates deeply nested PROJJSON (usage: `python3 crs_SF01_gen.py 5000 > input.json`) |
| `crs_SF01_poc_capi.cpp` | Calls `proj_create()` + `proj_as_projjson()` with generated input |
| `crs_SF01_poc_cppapi.cpp` | Builds chain via internal C++ API, calls `exportToJSON()` directly |

### Reproduction Steps

**Step 1 — Build PROJ 9.8.1 with AddressSanitizer**:

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

**Step 2 — Generate deeply nested PROJJSON input:**

```bash
python3 crs_SF01_gen.py 1000 > /tmp/sf01_input.json
```

**Step 3 — Compile and run:**

```bash
clang++ -std=c++17 -fsanitize=address -g -O1 \
    -I proj-9.8.1/install/include \
    crs_SF01_poc_capi.cpp \
    -L proj-9.8.1/install/lib -lproj \
    -Wl,-rpath,proj-9.8.1/install/lib \
    -o poc_02

# Reduce stack size to trigger the crash at lower nesting depth
(ulimit -s 512; \
 ASAN_OPTIONS=detect_leaks=0 \
 PROJ_DATA=proj-9.8.1/install/share/proj \
 ./poc_02 /tmp/sf01_input.json)
```

### Observed Output (parser path, 1000-depth JSON, 512 KB stack)

```
JSON length: 412393 bytes
Creating object from JSON...
==PID==ERROR: AddressSanitizer: stack-overflow on address 0x7ffc... (pc ...)
SUMMARY: AddressSanitizer: stack-overflow
==PID==ABORTING
```

## Impact

Any application that accepts PROJJSON from untrusted sources and calls `proj_create()`, or that serializes deeply nested CRS chains via `proj_as_projjson()`, can be crashed. This is a denial-of-service vector.

**Severity:** High — CVSS 3.1 base score **7.5** (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`). Attackers can supply crafted PROJJSON input over any network channel that feeds into `proj_create()`.  
**CWE:** [CWE-674: Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html)

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
