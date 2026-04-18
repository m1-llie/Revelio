# NULL Data Pointer Causes SEGV in `read_from_memory()` and `add_generic_metadata()`

## Summary

Two libheif C API functions pass a caller-supplied data pointer to `memcpy()` without
null-checking it. Passing `data=NULL` with `size>0` causes a SIGSEGV.

- **Affected functions:** `heif_context_read_from_memory()`, `heif_context_add_generic_metadata()`, `heif_context_add_XMP_metadata()`, `heif_context_add_exif_metadata()`
- **Type:** CWE-476 NULL Pointer Dereference
- **Severity:** Medium — API-level; DoS (process abort / SIGSEGV)
- **Docker image tested:** `vulagent/libheif:latest`
- **ASAN confirmed:** Yes (see `asan_output_validated.txt`)

---

## Root Cause

### Crash Site 1 — `heif_context_read_from_memory()`

**File:** `libheif/bitstream.cc`, line 83

```cpp
StreamReader_memory::StreamReader_memory(const uint8_t* data, size_t size, bool copy)
    : m_length(size), m_position(0)
{
    if (copy) {
        m_owned_data = new uint8_t[m_length];
        memcpy(m_owned_data, data, size);  // <-- BUG: data may be NULL
        m_data = m_owned_data;
    } else {
        m_data = data;
    }
}
```

When `copy=true` (the default for `heif_context_read_from_memory`), the constructor
allocates a buffer and immediately calls `memcpy` with the caller-supplied `data`
pointer. No null check is performed before the allocation or the copy.

**Call chain:**
```
heif_context_read_from_memory(ctx, NULL, 64, NULL)
  -> heif_context.cc:67  heif_context_read_from_memory(ctx, mem=NULL, 64, ...)
  -> context.cc:220      HeifContext::read_from_memory(NULL, 64, copy=true)
  -> file.cc:123         HeifFile::read_from_memory(NULL, 64, true)
                         make_shared<StreamReader_memory>((const uint8_t*)NULL, 64, true)
  -> bitstream.cc:83     memcpy(m_owned_data, NULL, 64)  -->  SIGSEGV
```

### Crash Site 2 — `heif_context_add_generic_metadata()`

**File:** `libheif/context.cc`, lines 1793–1796

```cpp
Error HeifContext::add_generic_metadata(const std::shared_ptr<ImageItem>& master_image,
                                        const void* data, int size, ...)
{
    // ...
    std::vector<uint8_t> data_array;
    // ...
    data_array.resize(size);
    memcpy(data_array.data(), data, size);  // <-- BUG: data may be NULL
}
```

No null check is performed on `data` before `memcpy`. The same function is the
implementation target for:
- `heif_context_add_generic_metadata()`
- `heif_context_add_XMP_metadata()` (via `add_XMP_metadata()`)
- `heif_context_add_exif_metadata()` (via `add_exif_metadata()`)

**Call chain:**
```
heif_context_add_generic_metadata(ctx, hdl, NULL, 64, "test", "text/plain")
  -> heif_metadata.cc:227  HeifContext::add_generic_metadata(..., NULL, 64, ...)
  -> context.cc:1795       data_array.resize(64);
  -> context.cc:1796       memcpy(data_array.data(), NULL, 64)  -->  SIGSEGV
```

---

## Vulnerable Code

| File | Line | Expression |
|------|------|-----------|
| `libheif/bitstream.cc` | 83 | `memcpy(m_owned_data, data, size)` |
| `libheif/context.cc` | 1796 | `memcpy(data_array.data(), data, size)` |

---

## Trigger

```c
/* POC 1 — heif_context_read_from_memory */
heif_context* ctx = heif_context_alloc();
heif_context_read_from_memory(ctx, NULL, 64, NULL);  // SIGSEGV

/* POC 2 — heif_context_add_generic_metadata */
heif_context* ctx = heif_context_alloc();
heif_image_handle* hdl = /* ... any valid handle ... */;
heif_context_add_generic_metadata(ctx, hdl, NULL, 64, "test", "text/plain");  // SIGSEGV
```

---

## Impact

Any caller (application or library consumer) that passes a NULL data pointer with a
non-zero size to these public API functions will cause an immediate SIGSEGV, aborting
the process. If the library is used in a server or long-running process, this constitutes
a denial-of-service vulnerability.

The crash is deterministic and reproducible with a single API call.

---

## Fix

Add a null pointer guard at the top of each affected function (or at the common
internal entry point):

```cpp
// In heif_context_read_from_memory() wrapper, or in HeifContext::read_from_memory():
if (data == nullptr && size > 0) {
    return Error(heif_error_Usage_error, heif_suberror_Null_pointer_argument,
                 "data pointer is NULL but size > 0");
}

// In HeifContext::add_generic_metadata() before the memcpy:
if (data == nullptr && size > 0) {
    return Error(heif_error_Usage_error, heif_suberror_Null_pointer_argument,
                 "metadata data pointer is NULL but size > 0");
}
```

Alternatively, the `StreamReader_memory` constructor at `bitstream.cc:83` should
validate its `data` argument before calling `memcpy`.

---

## Reproduction

```bash
# Build and run both POCs inside the Docker container:
bash build.sh

# Or manually:
docker run --rm vulagent/libheif:latest bash -c "..."
# See build.sh for complete commands.
```

POC source files:
- `poc_read_from_memory.cc` — triggers crash in `heif_context_read_from_memory()`
- `poc_add_metadata_null.cc` — triggers crash in `heif_context_add_generic_metadata()`

ASAN output: `asan_output_validated.txt`
