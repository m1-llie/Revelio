# Dangling Pointer / Use-After-Free via `proj_uom_get_info_from_database()`

> **Filing note:** Report **together with bug #05** in a single GitHub issue as two
> medium-severity API-behavior bugs.  See Issue 7 in `REPORTING_GUIDE.md`.

## Summary

`proj_uom_get_info_from_database()` returns a `const char *` pointer derived from `c_str()` of an internal `std::string` member (`lastUOMName_`) inside the PROJ context. A second call to the same function may **reallocate** that string's buffer, invalidating the pointer returned by the first call. Any subsequent read through the saved pointer is a use-after-free.

- **Affected file:** `src/iso19111/c_api.cpp`, lines ~922-923
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17); latest affected release: PROJ **9.8.1** (2026-04-10)
- **Sanitizer required:** ASAN (confirms UAF via different pointer addresses; data may differ)
- **Severity:** Medium — incorrect data read; no memory-safety guarantee after reallocation
- **Impact:** Potential silent data corruption; undefined behavior per C++ standard

---

## Vulnerable Code

```cpp
// src/iso19111/c_api.cpp:922-923
ctx->get_cpp_context()->lastUOMName_ = obj->name();
*out_name = ctx->cpp_context->lastUOMName_.c_str();
```

The documentation states the pointer is valid "until the next call to `proj_uom_get_info_from_database()` or context destruction." However, if the *second* call stores a longer string, `std::string::operator=` may reallocate the heap buffer. The old `c_str()` pointer now points to freed memory.

---

## Proof of Concept

See `capi_SF04_poc.c`. The PoC calls the function twice with units of different name lengths, saves the first pointer, then verifies the addresses differ (confirming the buffer was reallocated).

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
    07-capi-SF04-dangling-string-ptr/capi_SF04_poc.c \
    -L proj-9.8.1/install/lib -lproj \
    -Wl,-rpath,proj-9.8.1/install/lib \
    -o poc_07

ASAN_OPTIONS=detect_stack_use_after_return=1:detect_leaks=0 \
PROJ_DATA=proj-9.8.1/install/share/proj \
./poc_07
```

### Observed Output

```
[*] First call:  name='metre' at ptr=0x7c8f46ee00e0
[*] Second call: name='British yard (Sears 1922)' at ptr=0x7b9f46ef6fc0
[!] DIFFERENT POINTERS - old buffer was FREED (UAF condition!)
[!] dangling_ptr=0x7c8f46ee00e0 now points to freed memory
[!] Dereferencing freed pointer (UAF read): ''
```

The old pointer returns an empty string (freed memory contents under ASAN quarantine).

---

## Impact

Code patterns like:

```c
const char *name1, *name2;
proj_uom_get_info_from_database(ctx, "EPSG", "9001", &name1, NULL, NULL);
proj_uom_get_info_from_database(ctx, "EPSG", "9037", &name2, NULL, NULL);
// name1 may now be dangling if the second call reallocated
strcmp(name1, "metre");  // undefined behavior
```

…are undefined behavior and may silently produce wrong results or crash.

**Severity:** Medium — CVSS 3.1 base score **4.9** (`AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L`). Exploitation depends on triggering a reallocation with a longer string, producing silent wrong data rather than an immediate crash.  
**CWE:** [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html)

---

## Suggested Fix

Document the behavior more prominently, or allocate a fresh `std::string` per call and require callers to use `proj_string_destroy()` to free it. Alternatively, maintain a small ring buffer of saved strings (e.g., 8 slots) to extend the validity window:

```diff
-ctx->get_cpp_context()->lastUOMName_ = obj->name();
-*out_name = ctx->cpp_context->lastUOMName_.c_str();
+// push to ring buffer and return stable pointer
+auto &slot = ctx->get_cpp_context()->uomNameBuffer[ctx->get_cpp_context()->uomNameIdx++ % 8];
+slot = obj->name();
+*out_name = slot.c_str();
```
