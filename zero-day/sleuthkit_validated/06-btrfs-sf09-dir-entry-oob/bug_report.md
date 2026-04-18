# [HEAP-BUFFER-OVERFLOW] btrfs dir entry data_len OOB read - sleuthkit

## Summary

`btrfs_dir_entry_fromraw_single()` reads `data_len` from an untrusted directory entry
without validating it against the actual item buffer size. It then performs
`memcpy(de->data, a_raw + 0x1E + name_len, de->data_len)` which reads `data_len` bytes
from `a_raw`. Since `a_raw` points into a heap-allocated tree node data buffer of fixed
size (3995 bytes for a 4096-byte node), a crafted large `data_len` causes an
out-of-bounds read of 28672 bytes past the node buffer end.

- **Affected file**: `tsk/fs/btrfs.cpp` (lines 247, 259)
- **Confirmed on commit**: `01de034` (2026-04-15, sleuthkit main)
- **Sanitizer**: ASAN (crash confirmed)
- **Impact**: DoS / information disclosure

## Root Cause

In `btrfs_dir_entry_fromraw_single()`:
```cpp
de->data_len = tsk_getu16(BTRFS_ENDIAN, a_raw + 0x19);
uint16_t name_len = tsk_getu16(BTRFS_ENDIAN, a_raw + 0x1B);
// ...
de->data = new uint8_t[de->data_len];
memcpy(de->data, a_raw + 0x1E + name_len, de->data_len);  // OOB read!
```

`de->data_len` is read from untrusted input and used directly in `memcpy` without
verifying that `0x1E + name_len + data_len` does not exceed the caller's buffer bounds.
A crafted `data_len = 0x7000` causes a 28672-byte OOB read.

## Proof of Concept

### Reproduction

```bash
docker run --rm --memory=2g \
  -v /scr2/yiwei/vul-agent/zero-day/sleuthkit/06-btrfs-SF09-dir-entry-data-len-oob:/h \
  vulagent/sleuthkit:20260417 \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_btrfs_fuzzer /h/btrfs_sf09_dir_entry_oob_v2.img"
```

### Sanitizer Output

```
=================================================================
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7d244a7f8c9b at pc 0x55cc67f394db bp 0x7ffef1177060 sp 0x7ffef1176820
READ of size 28672 at 0x7d244a7f8c9b thread T0
    #0 0x55cc67f394da in __asan_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:63:3
    #1 0x55cc68074066 in btrfs_dir_entry_fromraw_single /src/sleuthkit/tsk/fs/btrfs.cpp:247:5
    #2 0x55cc68074066 in btrfs_dir_entry_fromraw(unsigned char const*, unsigned int) /src/sleuthkit/tsk/fs/btrfs.cpp:259:36
    #3 0x55cc6805d861 in btrfs_dir_open_meta(TSK_FS_INFO*, TSK_FS_DIR**, unsigned long, int) /src/sleuthkit/tsk/fs/btrfs.cpp:3173:14
    #4 0x55cc67f83de1 in tsk_fs_dir_open_meta_internal /src/sleuthkit/tsk/fs/fs_dir.cpp:310:14
    #5 0x55cc67f83de1 in tsk_fs_dir_walk_recursive /src/sleuthkit/tsk/fs/fs_dir.cpp:675:9
    #6 0x55cc67f83bac in tsk_fs_dir_walk_internal /src/sleuthkit/tsk/fs/fs_dir.cpp:1007:14
    #7 0x55cc67f7fe41 in tsk_fs_fls /src/sleuthkit/tsk/fs/fls_lib.cpp:246:12
    #8 0x55cc67f7fb2a in LLVMFuzzerTestOneInput /src/sleuthkit/ossfuzz/fls_fuzzer.cc:39:5

0x7d244a7f8c9b is located 0 bytes after 3995-byte region [0x7d244a7f7d00,0x7d244a7f8c9b)
allocated by thread T0 here:
    #0 0x55cc67f7e31d in operator new[](unsigned long) /src/llvm-project/compiler-rt/lib/asan/asan_new_delete.cpp:111:37
    #1 0x55cc680699ea in btrfs_treenode_push /src/sleuthkit/tsk/fs/btrfs.cpp:1418:18

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/sleuthkit/tsk/fs/btrfs.cpp:247:5 in btrfs_dir_entry_fromraw_single
```

## Impact

- **Denial of Service**: Triggered during directory listing of any directory containing
  a crafted `DIR_ITEM` or `DIR_INDEX` entry. The filesystem must mount successfully
  (valid superblock+chunk tree+root tree), but any directory's contents can be
  malicious.
- **Information Disclosure**: The 28672-byte OOB read into adjacent heap pages may
  disclose sensitive memory contents.
- **Attack surface**: Any tool using TSK to list files from an attacker-supplied btrfs
  image will crash.

## CWE

- CWE-125: Out-of-Bounds Read
- CWE-787: Out-of-Bounds Write (the `new uint8_t[de->data_len]` path could also fail)

## Suggested Fix

In `btrfs_dir_entry_fromraw_single()`, validate `data_len` against the remaining buffer:

```cpp
// Before memcpy for data, require a_len parameter from caller:
size_t data_start = 0x1E + name_len;
if (data_start + de->data_len > a_len) {
    // Error: data_len exceeds buffer
    delete[] de->name;
    delete de;
    return NULL;
}
```

The function signature should also accept a `size_t a_len` parameter to enable this
check. The callers in `btrfs_dir_entry_fromraw()` can compute the remaining bytes using
`btrfs_dir_entry_single_rawlen()`.
