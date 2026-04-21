Heap-buffer-overflow in ffs_dinode_copy via signed cg_iusedoff comparison bypass (FFS/UFS1)

### Summary
A signed-comparison bug in `ffs_group_load()` allows a crafted UFS1 filesystem image to set `cg_iusedoff` to a negative value (e.g., `0xFFFFFFFF = -1`), bypassing the bounds check. The negative offset causes `ffs_dinode_copy()` to compute a pointer one byte *before* the heap-allocated cylinder-group buffer, producing a heap-buffer-overflow (OOB read) that crashes any libtsk consumer processing the image.

### Details
Tested Version:
- SleuthKit 4.15.0 (tag `sleuthkit-4.15.0`, commit `01de034`, released 2026-04-15)

The bounds check in `tsk/fs/ffs.c` uses `tsk_gets32()`, which returns `int32_t` (signed):

```c
// ffs.c ~line 88-89 — BUGGY signed comparison
if ((tsk_gets32(fs->endian, cg->cg_iusedoff) > (int)ffs->ffsbsize_b)
    || (tsk_gets32(fs->endian, cg->cg_freeoff) > (int)ffs->ffsbsize_b)) {
    // error
}
```

When `cg_iusedoff = 0xFFFFFFFF`, the cast to `int32_t` yields `-1`. The check `-1 > (int)8192` is `false`, so validation is silently bypassed.

`ffs_dinode_copy()` then computes:

```c
// ffs.c ~line 751
inosused = (unsigned char *) cg_inosused_lcl(fs, cg);
// = grp_buf + (-1) = grp_buf - 1  → one byte before the allocation
fs_meta->flags = (isset(inosused, dino_inum - ibase) ? ...);  // OOB READ
```

The same boundary-equal case (`cg_iusedoff == bsize_b`) also bypasses validation since `>` (not `>=`) is used.

### PoC
Build SleuthKit 4.15.0 with AddressSanitizer, then run `fls` against the attached image:

```bash
./configure CC="clang -fsanitize=address" CXX="clang++ -fsanitize=address" \
            CFLAGS="-g -O1" CXXFLAGS="-g -O1"
make -j$(nproc)

ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  ./tools/fstools/fls ffs_cgiusedoff_oob_read.img
```

ASAN output:

```
=================================================================
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7dc966ee28ff at pc 0x... bp 0x... sp 0x...
READ of size 1 at 0x7dc966ee28ff thread T0
    #0 0x... in ffs_dinode_copy(FFS_INFO*, TSK_FS_META*, unsigned long, ffs_inode const*) /src/sleuthkit/tsk/fs/ffs.c:755:23
    #1 0x... in ffs_inode_lookup(TSK_FS_INFO*, TSK_FS_FILE*, unsigned long) /src/sleuthkit/tsk/fs/ffs.c:815:9
    #2 0x... in tsk_fs_file_open_meta /src/sleuthkit/tsk/fs/fs_file.c:128:9
    #3 0x... in ffs_dir_open_meta /src/sleuthkit/tsk/fs/ffs_dent.c:283:13
    #4 0x... in tsk_fs_dir_walk_recursive /src/sleuthkit/tsk/fs/fs_dir.c
    #5 0x... in tsk_fs_fls /src/sleuthkit/tsk/fs/fls_lib.c

0x7dc966ee28ff is located 1 bytes before 8192-byte region [0x7dc966ee2900,0x7dc966ee4900)
allocated by thread T0 here:
    #0 0x... in calloc
    #1 0x... in tsk_malloc /src/sleuthkit/tsk/base/mymalloc.c:32:16
    #2 0x... in ffs_group_load(FFS_INFO*, unsigned int) /src/sleuthkit/tsk/fs/ffs.c:65:29

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/sleuthkit/tsk/fs/ffs.c:755:23 in ffs_dinode_copy
```

### Impact
Any tool or library using libtsk to enumerate inodes or files in a UFS1/FFS filesystem (e.g., `fls`, `icat`, Autopsy, forensic pipelines) will crash when presented with a crafted image. An attacker who can supply a filesystem image for analysis can reliably trigger the crash. The 1-byte OOB read can also leak adjacent heap contents (information disclosure). If the update sequence matches rather than mismatches, a write variant of this path may be reachable.

### Remediation
Change the signed comparison to unsigned and use `>=` to also reject the boundary-equal case:

```c
// BEFORE (buggy — signed comparison, off-by-one boundary):
if ((tsk_gets32(fs->endian, cg->cg_iusedoff) > (int)ffs->ffsbsize_b)
    || (tsk_gets32(fs->endian, cg->cg_freeoff) > (int)ffs->ffsbsize_b))

// AFTER (correct — unsigned, strict boundary):
uint32_t iusedoff = (uint32_t)tsk_gets32(fs->endian, cg->cg_iusedoff);
uint32_t freeoff  = (uint32_t)tsk_gets32(fs->endian, cg->cg_freeoff);
if ((iusedoff >= (uint32_t)ffs->ffsbsize_b)
    || (freeoff >= (uint32_t)ffs->ffsbsize_b))
```

Additionally, validate that the bitmap referenced by `cg_iusedoff` fits within the buffer:

```c
uint32_t bitmap_bytes = (cg_inode_num + 7) / 8;
if (iusedoff + bitmap_bytes > (uint32_t)ffs->ffsbsize_b) { /* error */ }
```

- Severity: High
  - CWE:
    - CWE-195: Signed to Unsigned Conversion Error (root cause — tsk_gets32 result used in signed comparison)
    - CWE-125: Out-of-Bounds Read
    - CWE-20: Improper Input Validation
  - CVSS v3.1: AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H → 7.1 (High)
    - Local file input, no privileges needed, crash is reliable, 1-byte heap leak