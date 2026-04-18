# [INTEGER OVERFLOW / ALLOCATION-SIZE-TOO-BIG] decmpfs uncSize overflow - sleuthkit

## Summary

A malicious HFS+ filesystem image with a `com.apple.decmpfs` attribute claiming a
near-maximum `uncompressed_size` causes an integer overflow in
`decmpfs_decompress_zlib_attr()`. The expression `new(std::nothrow) char[uncSize + 100]`
overflows when `uncSize` is close to `UINT64_MAX`, resulting in an undersized heap
allocation followed by either a crash (ASAN allocation limit exceeded) or an
out-of-bounds write during zlib decompression.

- **Affected file**: `tsk/fs/decmpfs.cpp` (line 1090)
- **Confirmed on commit**: `01de034` (2026-04-15, sleuthkit main)
- **Sanitizer**: ASAN (crash confirmed)
- **Impact**: DoS / potential heap-based buffer overflow

## Root Cause

In `decmpfs_decompress_zlib_attr()` (decmpfs.cpp line 1090):

```cpp
std::unique_ptr<char[]> decmpfs_decompress_zlib_attr(
  char* rawBuf, uint32_t rawSize, uint64_t uncSize, uint64_t* dstSize)
{
    // add some extra space
    std::unique_ptr<char[]> uncBuf{new(std::nothrow) char[uncSize + 100]};
    //                                                  ^^^^^^^^^^^
    // INTEGER OVERFLOW: uncSize near UINT64_MAX causes uncSize+100 to wrap around
    // e.g. uncSize = 0xFFFFFFFFFFFFFF00 => uncSize+100 = 0xFFFFFFFFFFFFFF64
```

`uncSize` is read directly from the `uncompressed_size` field of the
`DECMPFS_DISK_HEADER`, which is fully attacker-controlled. When
`uncSize = 0xFFFFFFFFFFFFFF00`, the addition `uncSize + 100` overflows to
`0xFFFFFFFFFFFFFF64`.

On systems without ASAN, `new(std::nothrow)` would either fail with `nullptr` (with
no null check — `nullptr` would then be passed to `zlib_inflate`) or on 32-bit systems
successfully allocate only 100 bytes, followed by zlib writing much more data — a
heap-based buffer overflow.

## Proof of Concept

### Reproduction

```bash
docker run --rm --memory=2g \
  -v /scr2/yiwei/vul-agent/zero-day/sleuthkit/07-decmpfs-SF02-uncsize-integer-overflow:/h \
  vulagent/sleuthkit:20260417 \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_hfs_fuzzer /h/decmpfs_sf02_uncsize_overflow.img"
```

### Sanitizer Output

```
==7==ERROR: AddressSanitizer: requested allocation size 0xffffffffffffff64
  (0x768 after adjustments for alignment, red zones etc.)
  exceeds maximum supported size of 0x10000000000 (thread T0)
    #0 in operator new[](unsigned long, std::nothrow_t const&) (asan_new_delete.cpp:118)
    #1 in decmpfs_decompress_zlib_attr() decmpfs.cpp:1090
    #2 in decmpfs_file_read_compressed_attr() decmpfs.cpp:1224
    #3 in decmpfs_file_read_zlib_attr() decmpfs.cpp:1281
    #4 in hfs_load_extended_attrs() hfs.cpp:4284
    #5 in hfs_load_attrs() hfs.cpp:4774
    #6 in hfs_inode_lookup() hfs.cpp:2536

SUMMARY: AddressSanitizer: allocation-size-too-big decmpfs.cpp:1090
```

## Impact

- **Denial of Service**: Crash in any application processing HFS+ images with
  compressed files.
- **Heap-based Buffer Overflow**: On non-ASAN builds or 32-bit platforms, the overflow
  wraps `uncSize+100` to a small value, allocating a tiny buffer. Subsequent zlib
  decompression writes far more data than the buffer holds, leading to heap corruption.
- **Attack scenario**: Forensic analyst opens a malicious HFS+ disk image with any
  TSK-based tool (`fls`, `icat`, Autopsy, etc.).

## CWE

- CWE-190: Integer Overflow or Wraparound
- CWE-122: Heap-based Buffer Overflow

## Suggested Fix

Check for integer overflow before allocation:

```cpp
// Check for integer overflow before allocation
if (uncSize > SIZE_MAX - 100) {
    error_returned(" - %s, uncSize too large for allocation", __func__);
    return nullptr;
}
std::unique_ptr<char[]> uncBuf{new(std::nothrow) char[uncSize + 100]};
if (!uncBuf) {
    error_returned(" - %s, space for the uncompressed attr", __func__);
    return nullptr;
}
```
