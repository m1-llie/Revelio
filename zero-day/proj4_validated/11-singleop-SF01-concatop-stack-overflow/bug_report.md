# Stack Overflow via Unbounded Recursion in `ConcatenatedOperation::_exportToWKT/JSON()`

## Summary

`ConcatenatedOperation::_exportToWKT()` and `_exportToJSON()` in `src/iso19111/operation/concatenatedoperation.cpp` iterate over their steps and call `operation->_exportToWKT()` / `operation->_exportToJSON()` recursively. When each step is itself a `ConcatenatedOperation`, this recurses without any depth limit, causing a stack overflow.

- **Affected file:** `src/iso19111/operation/concatenatedoperation.cpp`
- **Affected functions:** `ConcatenatedOperation::_exportToWKT()` (line ~835), `ConcatenatedOperation::_exportToJSON()` (line ~886)
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17)
- **Sanitizer required:** AddressSanitizer (ASAN)
- **Impact:** Denial of service — process crash (stack overflow)

---

## Vulnerable Code

```cpp
// src/iso19111/operation/concatenatedoperation.cpp:826-835
for (const auto &operation : operations()) {
    ...
    operation->_exportToWKT(formatter);  // line 835: UNBOUNDED RECURSION if operation is ConcatenatedOperation
    ...
}

// lines 884-886
for (const auto &operation : operations()) {
    operation->_exportToJSON(formatter);  // line 886: same issue
}
```

No recursion depth counter exists in either export path.

---

## Proof of Concept

See `singleop_SF01_poc.cpp`. The PoC builds a deeply nested `ConcatenatedOperation` chain (50 000 levels) and calls `exportToWKT()`.

### Reproduction Steps

```bash
docker run --rm \
  -v /path/to/bugs:/bugs \
  -v /path/to/PROJ-latest:/src/PROJ-latest:ro \
  -v /path/to/proj4-latest-build:/proj4-latest-build:ro \
  vulagent/proj4-asan:latest bash -c "
    clang++ -std=c++17 -DFROM_PROJ_CPP -fsanitize=address -g -O1 \
      -I/src/PROJ-latest/src -I/src/PROJ-latest/include \
      /bugs/11-singleop-SF01-concatop-stack-overflow/singleop_SF01_poc.cpp \
      /proj4-latest-build/lib/libproj.a \
      -lpthread /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 -ldl -lm \
      -o /tmp/poc_11

    ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan /tmp/poc_11
  "
```

### Observed Output

```
SF01 PoC: Stack overflow via deeply nested ConcatenatedOperation
Building 50000 nesting levels (stack=512KB)...
Structure built. Now calling exportToWKT()...
...
    #236 in ConcatenatedOperation::_exportToWKT(WKTFormatter*) const  concatenatedoperation.cpp:835:24
    #237 in ConcatenatedOperation::_exportToWKT(WKTFormatter*) const  concatenatedoperation.cpp:835:24
    ...
SUMMARY: AddressSanitizer: stack-overflow  (/lib/x86_64-linux-gnu/libsqlite3.so.0+...)
```

---

## Impact

Applications that serialize coordinate operation objects received from or constructed with user input can be crashed. The WKT and PROJJSON export APIs are both affected.

---

## Suggested Fix

Add a depth counter to `WKTFormatter` and `JSONFormatter` and enforce a limit during export:

```diff
 for (const auto &operation : operations()) {
+    if (formatter->depth() > MAX_EXPORT_DEPTH)
+        throw io::FormattingException("ConcatenatedOperation chain too deep to export");
     ...
     operation->_exportToWKT(formatter);
```

Alternatively, cap the allowed nesting depth when building `ConcatenatedOperation` chains through the public API.
