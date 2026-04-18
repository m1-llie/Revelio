# Signed-to-Unsigned Integer Wrap in Metadata Size Parameter Causes Abort

## Summary

The `size` parameter in metadata-writing functions is typed `int` but used directly in
`data_array.resize(size)` without sign validation. A negative value (e.g., -1) wraps
to `SIZE_MAX` as `size_t`, causing `std::length_error` abort or allocation failure.

- **Affected functions:** `heif_context_add_generic_metadata()`, `heif_context_add_XMP_metadata()`, `heif_context_add_exif_metadata()`
- **Type:** CWE-195 Signed to Unsigned Conversion Error
- **Severity:** Medium — DoS (process abort via uncaught `std::length_error`)
- **Docker image tested:** `vulagent/libheif:latest`
- **Validated:** Yes — deterministic abort with exit code 134 (SIGABRT)

---

## Root Cause

**File:** `libheif/context.cc`, lines ~1732–1796

```cpp
Error HeifContext::add_generic_metadata(const std::shared_ptr<ImageItem>& master_image,
                                        const void* data, int size,       // <-- signed int
                                        uint32_t item_type, ...)
{
    // ... setup ...

    std::vector<uint8_t> data_array;

    // ... (compression branches skipped) ...

    // Uncompressed path:
    data_array.resize(size);            // <-- BUG: if size < 0, implicit cast to size_t
                                        //    (size_t)(-1) == SIZE_MAX on 64-bit
                                        //    -> std::length_error thrown, not caught
    memcpy(data_array.data(), data, size);
}
```

The `size` parameter is typed `int` in the public C API:

```c
// heif_metadata.h
LIBHEIF_API
heif_error heif_context_add_generic_metadata(heif_context* ctx,
                                             const heif_image_handle* image_handle,
                                             const void* data,
                                             int size,           // signed!
                                             const char* item_type,
                                             const char* content_type);
```

The same `int size` signature propagates through:
- `heif_context_add_XMP_metadata(ctx, hdl, data, int size)`
- `heif_context_add_exif_metadata(ctx, hdl, data, int size)`

All three eventually call `HeifContext::add_generic_metadata()` with the raw `int`
value, which is then passed to `std::vector::resize()` (which takes `size_type` =
`size_t`). The implicit signed-to-unsigned conversion produces `SIZE_MAX` for `-1`,
and `std::vector` throws `std::length_error`.

The exception propagates through the C++ stack and is not caught anywhere in the C API
wrappers, causing `std::terminate()` to be called, which invokes `abort()`.

---

## Vulnerable Code

**File:** `libheif/context.cc`

```cpp
// Lines ~1793-1796 (uncompressed metadata path)
data_array.resize(size);           // int size=-1 -> size_t SIZE_MAX -> length_error
memcpy(data_array.data(), data, size);
```

**Call chains:**

```
heif_context_add_generic_metadata(ctx, hdl, data, -1, "test", "text/plain")
  -> heif_metadata.cc:227  HeifContext::add_generic_metadata(..., data, -1, ...)
  -> context.cc:1795        data_array.resize(-1)
                             -> std::length_error -> terminate() -> SIGABRT

heif_context_add_XMP_metadata(ctx, hdl, data, -1)
  -> heif_metadata.cc:194  heif_context_add_XMP_metadata2(...)
  -> heif_metadata.cc:207  HeifContext::add_XMP_metadata(..., data, -1, off)
  -> context.cc:1728        add_generic_metadata(..., data, -1, ...)
  -> context.cc:1795        data_array.resize(-1) -> SIGABRT

heif_context_add_exif_metadata(ctx, hdl, data, -1)
  -> context.cc:~1715      data_array.resize(-1 + 4)   // wraps to SIZE_MAX-3
  -> SIGABRT (same path)
```

---

## Trigger

```c
/* Minimal trigger — any negative size causes abort */
heif_context* ctx = heif_context_alloc();
heif_image_handle* hdl = /* ... any valid handle ... */;
const char data[4] = {0};

heif_context_add_generic_metadata(ctx, hdl, data, -1, "test", "text/plain");  // ABORT
heif_context_add_XMP_metadata(ctx, hdl, data, -1);                             // ABORT
heif_context_add_exif_metadata(ctx, hdl, data, -1);                            // ABORT
```

---

## Impact

Any caller that passes a negative size to these public API functions will abort the
process via `std::terminate()`. The crash is deterministic and reproducible. In a
server or long-running process, this constitutes a denial-of-service vulnerability.

The `int` parameter type in the public API implies the user may reasonably expect the
library to return an error for invalid values; instead, the process is killed.

---

## Fix

Add a sign check at the C API wrapper layer (or at the `HeifContext` internal entry
point) before using `size` in any arithmetic or container operations:

```cpp
// Option A: in the C API wrapper (heif_metadata.cc)
heif_error heif_context_add_generic_metadata(heif_context* ctx,
                                             const heif_image_handle* image_handle,
                                             const void* data, int size, ...)
{
    if (size < 0) {
        return { heif_error_Usage_error, heif_suberror_Invalid_parameter_value,
                 "size parameter must not be negative" };
    }
    // ...
}

// Option B: in HeifContext::add_generic_metadata() (context.cc)
Error HeifContext::add_generic_metadata(..., int size, ...)
{
    if (size < 0) {
        return Error(heif_error_Usage_error, heif_suberror_Invalid_parameter_value,
                     "size parameter must not be negative");
    }
    // ...
}

// Option C: change the parameter type from int to uint32_t or size_t
//   throughout the public API (breaking change, but semantically correct)
```

---

## Reproduction

```bash
# Build and run the POC inside the Docker container:
bash build.sh

# Or manually:
docker run --rm vulagent/libheif:latest bash -c "..."
# See build.sh for complete commands.

# Run variants:
./poc_trigger 1    # heif_context_add_generic_metadata with size=-1
./poc_trigger 2    # heif_context_add_XMP_metadata with size=-1
./poc_trigger 3    # heif_context_add_exif_metadata with size=-1
```

POC source: `poc_trigger.cc`
Crash output: `asan_output_validated.txt`
