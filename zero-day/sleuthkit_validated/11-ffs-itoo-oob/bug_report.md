# [HEAP-BUFFER-OVERFLOW] FFS itoo_lcl OOB read via anomalous fs_inopb - sleuthkit

## Summary

A heap buffer overflow exists in `ffs_dinode_load()` in `tsk/fs/ffs.cpp`. When a UFS1
filesystem image contains a superblock with an anomalous `fs_inopb` value (inodes per
block) that exceeds `bsize_b / sizeof(ffs_inode1)`, the `itoo_lcl()` macro can compute
an offset beyond the allocated inode-table buffer (`itbl_buf`), causing `memcpy()` to
read 128 bytes past the end of the heap allocation.

- **Affected file**: `tsk/fs/ffs.cpp` (lines ~228–231)
- **Confirmed on commit**: `01de034` (2026-04-15, sleuthkit main)
- **Sanitizer**: ASAN (crash confirmed)
- **Impact**: DoS / information disclosure

## Root Cause

In `ffs_dinode_load()` (UFS1 path):

```c
// Line 135: itbl_buf allocated with ffsbsize_b bytes
if ((ffs->itbl_buf = (char*) tsk_malloc(ffs->ffsbsize_b)) == NULL) { ... }

// Line 228-231: offset computed WITHOUT bounds check
offs = itoo_lcl(fs, ffs->fs.sb1, inum) * sizeof(ffs_inode1);
memcpy((char *) dino_buf, ffs->itbl_buf + offs,   // <-- OOB if offs >= ffsbsize_b
    sizeof(ffs_inode1));
```

Where the macro is:
```c
// tsk_ffs.h line 450:
#define itoo_lcl(fsi, fs, x)   ((x) % (uint32_t)tsk_getu32(fsi->endian, (fs)->fs_inopb))
```

The macro computes `inum % fs_inopb`. Normally `fs_inopb = bsize_b / sizeof(inode)`,
so the maximum offset is `(fs_inopb - 1) * sizeof(inode) = bsize_b - sizeof(inode)`,
which fits within the buffer.

**Attack:** Set `fs_inopb` in the superblock to a value larger than
`bsize_b / sizeof(ffs_inode1)`. For `bsize_b=1024` (so `itbl_buf = 1024 bytes`) with
`fs_inopb=64` (normal=8): for `inum=8`, `itoo = 8 % 64 = 8`,
`offs = 8 * 128 = 1024 = bsize_b` — `memcpy` reads 128 bytes starting at the exact
end of the 1024-byte buffer.

The superblock passes all existing validation (`bsize_b`, `fsize_b`, `bsize_frag`
ratio checks pass; `fs_inopb` has no direct validation against `bsize_b/sizeof(inode)`).

## Proof of Concept

### Reproduction

```bash
docker run --rm --memory=2g \
  -v /scr2/yiwei/vul-agent/zero-day/sleuthkit/11-ffs-SF18-itoo-oob-read:/h \
  vulagent/sleuthkit:20260417 \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_ffs_fuzzer /h/ffs_itoo_oob_write.img"
```

### Sanitizer Output

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... at pc 0x...
READ of size 128 at 0x7d05354e0e80 thread T0
    #0 0x... in __asan_memcpy
    #1 0x... in ffs_dinode_load(FFS_INFO*, unsigned long, ffs_inode*) /src/sleuthkit/tsk/fs/ffs.cpp
    #2 0x... in ffs_inode_walk(...) /src/sleuthkit/tsk/fs/ffs.cpp:971:13
    #3 0x... in tsk_fs_dir_find_orphans /src/sleuthkit/tsk/fs/fs_dir.cpp:1417:9

0x7d05354e0e80 is located 0 bytes after 1024-byte region [0x7d05354e0a80,0x7d05354e0e80)
allocated by thread T0 here:
    #0 ... in calloc
    #1 ... in tsk_malloc /src/sleuthkit/tsk/base/mymalloc.c:32:16
    #2 ... in ffs_dinode_load(FFS_INFO*, unsigned long, ffs_inode*) /src/sleuthkit/tsk/fs/ffs.cpp:135:38

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/sleuthkit/tsk/fs/ffs.cpp in ffs_dinode_load
```

## Impact

- **Denial of Service**: Crash when enumerating inodes in a UFS1/FFS filesystem with
  a crafted `fs_inopb` superblock value.
- **Information Disclosure**: 128-byte OOB read can expose adjacent heap memory
  contents.
- **Attack surface**: `tsk_fs_fls()`, `ffs_inode_walk()`, `ffs_dir_open_meta()` —
  any code that enumerates inodes in a UFS1 filesystem.

## CWE

- CWE-122: Heap-based Buffer Overflow
- CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
- CWE-20: Improper Input Validation

## Suggested Fix

Add a bounds check before the `memcpy` call in `ffs_dinode_load()`:

```c
// FFS1 path:
offs = itoo_lcl(fs, ffs->fs.sb1, inum) * sizeof(ffs_inode1);
// ADD: bounds check
if (offs + sizeof(ffs_inode1) > ffs->ffsbsize_b) {
    tsk_release_lock(&ffs->lock);
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
    tsk_error_set_errstr("ffs_dinode_load: inode offset out of bounds for inum %" PRIuINUM, inum);
    return 1;
}
memcpy((char *) dino_buf, ffs->itbl_buf + offs, sizeof(ffs_inode1));
```

Additionally, validate `fs_inopb` during superblock parsing in `ffs_open()`:
```c
if (ffs->ffsbsize_b / sizeof(ffs_inode1) != tsk_gets32(fs->endian, ffs->fs.sb1->fs_inopb)) {
    // reject as invalid
}
```
