# Undefined Behavior via Unvalidated `heif_metadata_compression` Enum

## Summary

`heif_context_add_XMP_metadata2()` accepts any integer as the `compression` enum
parameter without range validation, triggering UBSan "invalid value for enum type"
and causing type confusion in the produced HEIF file.

- **Type:** CWE-20 Improper Input Validation / UB (CWE-704 Incorrect Type Conversion)
- **Severity:** Low-Medium — API-level; UB exploitable by compiler
- **Affected version:** libheif 1.21.2 (current HEAD)
- **Affected file:** `libheif/context.cc` lines 1728, 1762, 1767, 1774, 1783
- **Also:** `libheif/api/libheif/heif_metadata.cc` line 204

---

## Vulnerability Details

### Root Cause

`heif_metadata_compression` is defined in `heif_metadata.h` as:

```c
typedef enum heif_metadata_compression {
  heif_metadata_compression_off     = 0,
  heif_metadata_compression_auto    = 1,
  heif_metadata_compression_unknown = 2,
  heif_metadata_compression_deflate = 3,
  heif_metadata_compression_zlib    = 4,
  heif_metadata_compression_brotli  = 5
} heif_metadata_compression;
```

Valid values are 0–5. The public API function `heif_context_add_XMP_metadata2()`
passes the caller-supplied `compression` parameter directly, without bounds
checking, into `HeifContext::add_XMP_metadata()` and then into
`HeifContext::add_generic_metadata()` in `context.cc`.

`add_generic_metadata()` performs a series of equality comparisons against the enum
value (lines 1762, 1767, 1774, 1783). Under C/C++ rules, loading an out-of-range
integer through an enum type is undefined behavior. UBSan reports this as:

```
runtime error: load of value 99, which is not a valid value for type
'heif_metadata_compression' (aka 'enum heif_metadata_compression')
```

### Type Confusion Side-Effect

Because value 99 matches none of the explicit branches, the code falls through to
the `else` branch (raw byte copy, no compression). The `content_encoding` field is
**not set** in the resulting `infe` box, yet the caller intended some compression
method. A reader that relies on `content_encoding` to determine how to decode the
metadata block will find the data in the wrong format. The function nonetheless
returns `heif_error_Ok`, silently producing a malformed file.

### Affected Code (`context.cc`)

```cpp
// line 1762
if (compression == heif_metadata_compression_auto) {        // UB: loads 99
    compression = heif_metadata_compression_off;
}
// line 1767
if (compression != heif_metadata_compression_off &&         // UB: loads 99
    item_type != fourcc("mime")) { ... }
// line 1774
if (compression == heif_metadata_compression_zlib) {        // UB: loads 99
    ...
} else if (compression == heif_metadata_compression_deflate) { // UB: loads 99 (line 1783)
    ...
}
```

---

## Reproduction

### Environment

- Docker image: `vulagent/libheif:latest`
- Compiler: `clang++ 14` with `-fsanitize=address,undefined`
- Input: any readable `.heic` file (e.g., `/src/libheif/examples/example.heic`)

### Steps

```bash
# Build and run (takes ~1-2 min to compile libheif from source)
./build.sh
```

Or manually:

```bash
docker run --rm \
  -v "$(pwd):/poc" \
  -e ASAN_OPTIONS="detect_leaks=0:halt_on_error=0" \
  -e UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  vulagent/libheif:latest \
  bash -c '
    # ... (see build.sh for full commands)
    /tmp/poc11_trigger
  '
```

### UBSan Output (excerpt from `ubsan_output_validated.txt`)

```
/src/libheif/libheif/context.cc:1728:105: runtime error: load of value 99, which
is not a valid value for type 'heif_metadata_compression'
    #0 HeifContext::add_XMP_metadata(...)  context.cc:1728

/src/libheif/libheif/context.cc:1762:7: runtime error: load of value 99 ...
    #0 HeifContext::add_generic_metadata(...) context.cc:1762

/src/libheif/libheif/context.cc:1767:7: runtime error: load of value 99 ...
/src/libheif/libheif/context.cc:1774:7: runtime error: load of value 99 ...
/src/libheif/libheif/context.cc:1783:12: runtime error: load of value 99 ...

[*] Return code: 0 (Ok -- data stored with no content_encoding despite invalid
compression request [type confusion])
```

**8 UBSan errors total** from a single call, spanning `heif_metadata.cc:204` and
`context.cc:1728,1762,1767,1774,1783`.

---

## Impact

1. **Undefined Behavior:** Aggressive compilers may optimize the enum comparisons
   in unexpected ways (dead-code elimination, branch removal), potentially changing
   behavior silently across compiler versions or optimization levels.

2. **Type Confusion / File Corruption:** The file is written without a
   `content_encoding` header, so any downstream reader that parses the HEIF file
   will attempt to interpret compressed-intended XMP data as uncompressed, or
   vice-versa if a future code path writes incorrect headers.

3. **API Contract Violation:** The function accepts an integer disguised as a valid
   enum member and returns `heif_error_Ok`, giving the caller false confidence that
   the operation succeeded correctly.

---

## Suggested Fix

Add an explicit range check before using `compression` in
`HeifContext::add_generic_metadata()`:

```cpp
// context.cc, before any use of 'compression':
if (compression < heif_metadata_compression_off ||
    compression > heif_metadata_compression_brotli) {
  return Error(heif_error_Invalid_input,
               heif_suberror_Invalid_parameter_value,
               "Unknown/unsupported heif_metadata_compression value");
}
```

Or alternatively, use a `switch` with a `default:` that returns an error:

```cpp
switch (compression) {
  case heif_metadata_compression_off:
  case heif_metadata_compression_auto:
  case heif_metadata_compression_deflate:
  case heif_metadata_compression_zlib:
  case heif_metadata_compression_brotli:
    break;
  default:
    return Error(heif_error_Invalid_input, heif_suberror_Invalid_parameter_value,
                 "Unknown heif_metadata_compression value");
}
```

---

## Files

| File | Description |
|------|-------------|
| `poc_trigger.cc` | C POC — passes `(heif_metadata_compression)99` to trigger UB |
| `build.sh` | Build + run script (compiles libheif from source with ASAN+UBSan) |
| `ubsan_output_validated.txt` | Captured UBSan output showing 8 runtime errors |
| `11-metadata-invalid-compression-enum.md` | This report |
