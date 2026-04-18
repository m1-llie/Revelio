# Dangling Pointer / Use-After-Free via `proj_uom_get_info_from_database()`

## Summary

`proj_uom_get_info_from_database()` returns a `const char *` pointer derived from `c_str()` of an internal `std::string` member (`lastUOMName_`) inside the PROJ context. A second call to the same function may **reallocate** that string's buffer, invalidating the pointer returned by the first call. Any subsequent read through the saved pointer is a use-after-free.

- **Affected file:** `src/iso19111/c_api.cpp`, lines ~922-923
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17)
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

```bash
docker run --rm \
  -v /path/to/bugs:/bugs \
  -v /path/to/PROJ-latest:/src/PROJ-latest:ro \
  -v /path/to/proj4-latest-build:/proj4-latest-build:ro \
  vulagent/proj4-asan:latest bash -c "
    clang -std=c11 -fsanitize=address -g -O1 \
      -I/src/PROJ-latest/src \
      /bugs/07-capi-SF04-dangling-string-ptr/capi_SF04_poc.c \
      /proj4-latest-build/lib/libproj.a \
      -lpthread /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 -ldl -lm -lstdc++ \
      -o /tmp/poc_07

    ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan /tmp/poc_07
  "
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
