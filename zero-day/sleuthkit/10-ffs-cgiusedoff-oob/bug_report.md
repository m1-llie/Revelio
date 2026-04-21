# [HEAP-BUFFER-OVERFLOW] FFS cg_iusedoff signed comparison bypass OOB read - sleuthkit

## Summary

A heap buffer overflow exists in `ffs_dinode_copy()` (called via `ffs_inode_lookup`)
when it accesses the inode-allocation bitmap via `cg_inosused_lcl()`. The
`ffs_group_load()` function validates cylinder group descriptor fields `cg_iusedoff`
and `cg_freeoff` using a **signed comparison**, which allows a malicious filesystem
image to bypass the check by setting these fields to negative values (e.g.,
`0xFFFFFFFF = -1`). The negative offset then produces a pointer before the
heap-allocated `grp_buf`, causing an out-of-bounds read.

- **Affected file**: `tsk/fs/ffs.cpp` (lines 88–89, 751–755)
- **Confirmed on commit**: `01de034` (2026-04-15, sleuthkit develop-4.14)
- **Re-confirmed on commit**: `d784e64db6` (2026-04-13, sleuthkit develop branch)
- **Sanitizer**: ASAN (crash confirmed on both commits)
- **Impact**: DoS / information disclosure

## Root Cause

### Validation (ffs_group_load, lines 88–89) — signed comparison bug:

```c
// grp_buf allocated as bsize_b bytes (e.g., 8192)
if (ffs->grp_buf == NULL) {
    if ((ffs->grp_buf = (char*) tsk_malloc(ffs->ffsbsize_b)) == NULL) { ... }
}
// SIGNED comparison - BUGGY!
if ((tsk_gets32(fs->endian, cg->cg_iusedoff) > (int)ffs->ffsbsize_b)
    || (tsk_gets32(fs->endian, cg->cg_freeoff) > (int)ffs->ffsbsize_b)) {
    // error
}
```

`tsk_gets32()` returns `int32_t` (signed). If `cg->cg_iusedoff = 0xFFFFFFFF`, then
as `int32_t` it is `-1`. The check `-1 > (int)8192` evaluates to `false` — the
validation is bypassed.

Also: if `cg_iusedoff = bsize_b = 8192`, the check `8192 > 8192` is also `false` —
passing validation despite being an exact-boundary overflow.

### Crash site (ffs_dinode_copy, lines 751–755):

```c
cg = (ffs_cgd *) ffs->grp_buf;
// Line 751: compute pointer using unvalidated (negative) offset
inosused = (unsigned char *) cg_inosused_lcl(fs, cg);
// cg_inosused_lcl = (uint8_t*)cg + tsk_gets32(endian, cg->cg_iusedoff)
//                 = grp_buf + 0xFFFFFFFF (wraps to grp_buf - 1)

// Line 755: bitmap access at OOB pointer
fs_meta->flags = (isset(inosused, dino_inum - ibase) ?   // <-- OOB READ!
    TSK_FS_META_FLAG_ALLOC : TSK_FS_META_FLAG_UNALLOC);
```

## Proof of Concept

### Reproduction

```bash
docker run --rm --memory=2g \
  -v /scr2/yiwei/vul-agent/zero-day/sleuthkit/10-ffs-SF03-cgiusedoff-signed-comparison-bypass:/h \
  vulagent/sleuthkit:20260417 \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_ffs_fuzzer /h/ffs_cgiusedoff_oob_read.img"
```

### Sanitizer Output

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... at pc 0x...
READ of size 1 at 0x7dcd19de28ff thread T0
    #0 0x... in ffs_dinode_copy(FFS_INFO*, TSK_FS_META*, unsigned long, ffs_inode const*) /src/sleuthkit/tsk/fs/ffs.cpp:755:23
    #1 0x... in ffs_inode_lookup(TSK_FS_INFO*, TSK_FS_FILE*, unsigned long) /src/sleuthkit/tsk/fs/ffs.cpp:815:9
    #2 0x... in tsk_fs_file_open_meta /src/sleuthkit/tsk/fs/fs_file.cpp:133:9
    #3 0x... in ffs_dir_open_meta /src/sleuthkit/tsk/fs/ffs_dent.cpp:286:13
    #4 0x... in tsk_fs_fls /src/sleuthkit/tsk/fs/fls_lib.cpp:246:12

0x7dcd19de28ff is located 1 bytes before 8192-byte region [0x7dcd19de2900,0x7dcd19de4900)
allocated by thread T0 here:
    #0 ... in calloc
    #1 ... in tsk_malloc /src/sleuthkit/tsk/base/mymalloc.c:32:16
    #2 ... in ffs_group_load(FFS_INFO*, unsigned int) /src/sleuthkit/tsk/fs/ffs.cpp:65:37
    #3 ... in ffs_dinode_copy(...) /src/sleuthkit/tsk/fs/ffs.cpp:744:9

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/sleuthkit/tsk/fs/ffs.cpp:755:23 in ffs_dinode_copy
```

## Impact

- **Denial of Service**: Crash when enumerating any file/inode in a UFS1 filesystem
  with a crafted cylinder group descriptor.
- **Information Disclosure**: OOB read of heap memory before `grp_buf`, potentially
  exposing sensitive analysis data.
- **Attack surface**: `tsk_fs_fls()`, `ffs_dir_open_meta()`, `ffs_inode_lookup()` —
  any code enumerating inodes in a UFS1 filesystem.

## CWE

- CWE-122: Heap-based Buffer Overflow
- CWE-125: Out-of-Bounds Read
- CWE-681: Incorrect Conversion between Numeric Types (signed/unsigned comparison)
- CWE-20: Improper Input Validation

## Suggested Fix

Change the signed comparison to unsigned, and use `>=` (not `>`) to also reject
boundary-equal offsets:

```c
// BEFORE (buggy - signed comparison):
if ((tsk_gets32(fs->endian, cg->cg_iusedoff) > (int)ffs->ffsbsize_b)
    || (tsk_gets32(fs->endian, cg->cg_freeoff) > (int)ffs->ffsbsize_b)) {

// AFTER (correct - unsigned comparison and strict boundary check):
uint32_t iusedoff = (uint32_t)tsk_gets32(fs->endian, cg->cg_iusedoff);
uint32_t freeoff  = (uint32_t)tsk_gets32(fs->endian, cg->cg_freeoff);
if ((iusedoff >= (uint32_t)ffs->ffsbsize_b)
    || (freeoff >= (uint32_t)ffs->ffsbsize_b)) {
```

Also add bitmap size validation to ensure the bitmap fits within the buffer:
```c
uint32_t bitmap_bytes = (cg_inode_num + 7) / 8;
if (iusedoff + bitmap_bytes > (uint32_t)ffs->ffsbsize_b) { /* error */ }
```
