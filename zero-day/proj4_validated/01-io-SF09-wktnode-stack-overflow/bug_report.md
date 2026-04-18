# Stack Overflow via Unbounded Recursion in `WKTNode::toString()`

## Summary

`WKTNode::toString()` in `src/iso19111/io.cpp` recurses through child nodes with no depth limit. A WKT tree built programmatically (bypassing the parser's 16-level guard) causes a stack overflow when serialized.

- **Affected file:** `src/iso19111/io.cpp`
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17)
- **Crash address:** `io.cpp:1247` — recursive `child->toString()` call
- **Sanitizer required:** AddressSanitizer (ASAN)
- **Impact:** Denial of service — process crash (stack exhaustion)

---

## Vulnerable Code

```cpp
// src/iso19111/io.cpp:1237-1252
std::string WKTNode::toString() const {
    std::string str(escapeIfQuotedString(d->value_));
    if (!d->children_.empty()) {
        str += "[";
        bool first = true;
        for (auto &child : d->children_) {
            if (!first) { str += ','; }
            first = false;
            str += child->toString();  // line 1247: UNBOUNDED RECURSION
        }
        str += "]";
    }
    return str;
}
```

The WKT *parser* caps nesting at 16 levels (`io.cpp:1114`), but the `toString()` serializer has no corresponding guard. Any code that constructs a `WKTNode` tree programmatically—or that operates on a tree deserialized through a non-guarded path—can produce arbitrarily deep recursion here.

---

## Proof of Concept

See `io_SF09_poc.cpp`. The PoC constructs a `WKTNode` tree with 50 000 nesting levels through the internal C++ API and calls `toString()`.

### Reproduction Steps

```bash
docker run --rm \
  -v /path/to/proj4-bugs:/bugs \
  -v /path/to/PROJ-latest:/src/PROJ-latest:ro \
  -v /path/to/proj4-latest-build:/proj4-latest-build:ro \
  vulagent/proj4-asan:latest bash -c "
    clang++ -std=c++17 -DFROM_PROJ_CPP -fsanitize=address -g -O1 \
      -I/src/PROJ-latest/src -I/src/PROJ-latest/include \
      /bugs/01-io-SF09-wktnode-stack-overflow/io_SF09_poc.cpp \
      /proj4-latest-build/lib/libproj.a \
      -lpthread /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 -ldl -lm \
      -o /tmp/poc_01

    ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan /tmp/poc_01
  "
```

### Observed Output

```
...
    #248 in osgeo::proj::io::WKTNode::toString() const  io.cpp:1247
    #249 in osgeo::proj::io::WKTNode::toString() const  io.cpp:1247
    ...
SUMMARY: AddressSanitizer: stack-overflow
         iso19111/io.cpp:1228 in escapeIfQuotedString(...)
```

---

## Impact

Any application that constructs WKT trees programmatically and serializes them via `WKTNode::toString()` can be crashed. Server-side processes accepting or generating WKT from untrusted sources are at particular risk.

---

## Suggested Fix

Add a recursion depth counter to `toString()`, matching the existing parser guard in `WKTParser::parse()`:

```diff
-std::string WKTNode::toString() const {
+std::string WKTNode::toString(int depth) const {
+    if (depth > 16) throw ParsingException("too many nesting levels");
     std::string str(escapeIfQuotedString(d->value_));
     if (!d->children_.empty()) {
         str += "[";
         bool first = true;
         for (auto &child : d->children_) {
             if (!first) { str += ','; }
             first = false;
-            str += child->toString();
+            str += child->toString(depth + 1);
         }
         str += "]";
     }
     return str;
 }
```
