# [HEAP-BUFFER-OVERFLOW] decmpfs noncompressed attr rawSize ignored OOB read - sleuthkit

## Summary

A malicious HFS+ filesystem image with a crafted `com.apple.decmpfs` extended attribute
causes a **65536-byte (or larger) heap buffer over-read** in The Sleuth Kit (TSK). The
bug is in `decmpfs_decompress_noncompressed_attr()` which sets the output size to an
attacker-controlled value (`uncSize`) without validating that it is bounded by the
actual buffer size (`rawSize - 1`). This results in `tsk_fs_attr_set_str()` calling
`memcpy()` to read tens of thousands of bytes past the end of a small heap allocation.

This is the same underlying bug confirmed by two independent PoC images (issues 08 and
12 in the original research set). Both trigger identical ASAN output via the same
vulnerable code path.

- **Affected file**: `tsk/fs/decmpfs.cpp` (lines 1036–1051, 1252)
- **Confirmed on commit**: `01de034` (2026-04-15, sleuthkit main)
- **Sanitizer**: ASAN (crash confirmed)
- **Impact**: DoS / information disclosure

## Root Cause

In `decmpfs_decompress_noncompressed_attr()` (decmpfs.cpp lines 1036–1051):

```cpp
static int decmpfs_decompress_noncompressed_attr(
  char* rawBuf,
  [[maybe_unused]] uint32_t rawSize,  // <-- rawSize is IGNORED (marked maybe_unused!)
  uint64_t uncSize,
  char** dstBuf,
  uint64_t* dstSize)
{
    // ...
    *dstBuf = rawBuf + 1;  // pointer into small attribute data buffer
    *dstSize = uncSize;    // ATTACKER-CONTROLLED value from DECMPFS header!
    return 1;
}
```

The parameter `rawSize` is marked `[[maybe_unused]]` and completely ignored. The
function returns a pointer to `rawBuf + 1` (skipping a 1-byte indicator) with
`*dstSize = uncSize` where `uncSize` comes directly from the `uncompressed_size` field
of the `DECMPFS_DISK_HEADER` — fully attacker-controlled.

The caller `decmpfs_file_read_compressed_attr()` (line 1252) then passes this
mismatched pointer+size to `tsk_fs_attr_set_str()`:

```cpp
if (tsk_fs_attr_set_str(fs_file, fs_attr_unc, "DECOMP",
                        TSK_FS_ATTR_TYPE_HFS_DATA,
                        TSK_FS_ATTR_ID_DEFAULT,
                        dstBuf,   // rawBuf+1 (tiny buffer)
                        dstSize)) // uncSize (65536 or larger!)
```

And `tsk_fs_attr_set_str()` (fs_attr.cpp line 247) does:
```c
memcpy(a_fs_attr->rd.buf, res_data, len);  // reads 'len=uncSize' bytes from tiny buffer
```

This causes a heap buffer over-read of up to `uncSize` bytes.

The same vulnerability is triggered via the `LZVN_ATTR` path (type=7) when
`rawBuf[0]=0x06` is the noncompressed marker.

## Proof of Concept

Two independent PoC images trigger this exact same bug:

### Primary PoC (issue 08)

```bash
docker run --rm --memory=2g \
  -v /scr2/yiwei/vul-agent/zero-day/sleuthkit/08-decmpfs-SF07-noncompressed-oob-read:/h \
  vulagent/sleuthkit:20260417 \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_hfs_fuzzer /h/decmpfs_sf07_noncompressed_oob.img"
```

### Secondary PoC (issue 12)

```bash
docker run --rm --memory=2g \
  -v /scr2/yiwei/vul-agent/zero-day/sleuthkit/12-hfs-decmpfs-noncompressed-oob-read:/h \
  vulagent/sleuthkit:20260417 \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_hfs_fuzzer /h/hfs_decmpfs_oob_read.img"
```

### Sanitizer Output

```
=================================================================
==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7b84e47e05f4
READ of size 65536 at 0x7b84e47e05f4 thread T0
    #0 0x... in __asan_memcpy asan_interceptors_memintrinsics.cpp:63
    #1 0x... in tsk_fs_attr_set_str /src/sleuthkit/tsk/fs/fs_attr.cpp:247
    #2 0x... in decmpfs_file_read_compressed_attr decmpfs.cpp:1252
    #3 0x... in decmpfs_file_read_zlib_attr decmpfs.cpp:1281
    #4 0x... in hfs_load_extended_attrs /src/sleuthkit/tsk/fs/hfs.cpp:4284
    #5 0x... in hfs_load_attrs /src/sleuthkit/tsk/fs/hfs.cpp:4774
    #6 0x... in hfs_inode_lookup /src/sleuthkit/tsk/fs/hfs.cpp:2536
    #7 0x... in tsk_fs_dir_get2 /src/sleuthkit/tsk/fs/fs_dir.cpp:488
    #8 0x... in tsk_fs_path2inum /src/sleuthkit/tsk/fs/ifind_lib.cpp:274
    #9 0x... in hfs_open /src/sleuthkit/tsk/fs/hfs.cpp:6761
    #10 0x... in tsk_fs_open_img_decrypt /src/sleuthkit/tsk/fs/fs_open.c:292
    #11 0x... in LLVMFuzzerTestOneInput /src/sleuthkit/ossfuzz/fls_fuzzer.cc:34

0x7b84e47e05f4 is located 0 bytes after 20-byte region [0x7b84e47e05e0, 0x7b84e47e05f4)
allocated by thread T0 here:
    #0 calloc (asan_malloc_linux.cpp)
    #1 tsk_malloc (mymalloc.c:32)
    #2 hfs_load_extended_attrs (hfs.cpp:4235)

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/sleuthkit/tsk/fs/fs_attr.cpp:247
```

## Impact

- **Denial of Service**: Crash in any application processing HFS+ images with
  compressed files using the noncompressed storage format.
- **Information Disclosure**: The OOB read can expose up to `uncSize` bytes of adjacent
  heap memory, potentially including sensitive data from other analysis operations.
- **Attack surface**: Any TSK tool processing HFS+ images: `fls`, `icat`, `istat`,
  `tsk_recover`, Autopsy, etc. Attacker has full control over `uncSize` (UINT64 from
  filesystem metadata).

## CWE

- CWE-125: Out-of-Bounds Read
- CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

## Suggested Fix

Remove `[[maybe_unused]]` from `rawSize` and add bounds checking:

```cpp
static int decmpfs_decompress_noncompressed_attr(
  char* rawBuf,
  uint32_t rawSize,    // parameter should NOT be [[maybe_unused]]
  uint64_t uncSize,
  char** dstBuf,
  uint64_t* dstSize)
{
    // Validate that uncSize is bounded by actual data size
    if (rawSize < 1 || uncSize > (uint64_t)(rawSize - 1)) {
        error_detected(TSK_ERR_FS_READ,
            "%s: uncSize (%llu) exceeds available data (%u bytes)",
            __func__, (unsigned long long)uncSize, rawSize > 0 ? rawSize - 1 : 0);
        return 0;
    }
    *dstBuf = rawBuf + 1;
    *dstSize = uncSize;
    return 1;
}
```
