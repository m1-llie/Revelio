Heap-buffer-overflow in ffs_dinode_load via anomalous fs_inopb in UFS1 superblock (itoo_lcl OOB)

### Summary
`ffs_dinode_load()` in SleuthKit's UFS1/FFS parser trusts the on-disk `fs_inopb` (inodes-per-block) field without validating it against the actual block size. A crafted superblock with an inflated `fs_inopb` causes the `itoo_lcl()` macro to compute an inode offset beyond the heap-allocated inode-table buffer, leading to a 128-byte heap-buffer-overflow (OOB read via `memcpy`).

### Details
Tested Version:
- SleuthKit 4.15.0 (tag `sleuthkit-4.15.0`, commit `01de034`, released 2026-04-15)

In `tsk/fs/ffs.c`, the inode table buffer is allocated with `ffsbsize_b` bytes (e.g., 1024 for a 1 KB block size):

```c
// ffs.c ~line 135
if ((ffs->itbl_buf = (char*) tsk_malloc(ffs->ffsbsize_b)) == NULL) { ... }
```

The inode offset within that buffer is computed by the `itoo_lcl` macro (defined in `tsk_ffs.h`):

```c
// tsk_ffs.h ~line 450
#define itoo_lcl(fsi, fs, x)   ((x) % (uint32_t)tsk_getu32(fsi->endian, (fs)->fs_inopb))
```

Normally `fs_inopb == bsize_b / sizeof(ffs_inode1)`, so the maximum result is `bsize_b - sizeof(inode)`, safely within the buffer. However, the field is never validated against this relationship. With a crafted `fs_inopb = 64` (normal value is 8 for a 1 KB block / 128-byte inode), for `inum = 8`:

```
itoo = 8 % 64 = 8
offs = 8 * sizeof(ffs_inode1) = 8 * 128 = 1024 == ffsbsize_b
```

The subsequent `memcpy` reads 128 bytes starting exactly at the end of the allocation:

```c
// ffs.c ~lines 228-231
offs = itoo_lcl(fs, ffs->fs.sb1, inum) * sizeof(ffs_inode1);
memcpy((char *) dino_buf, ffs->itbl_buf + offs, sizeof(ffs_inode1));  // OOB READ
```

### PoC
Build SleuthKit 4.15.0 with AddressSanitizer, then run `fls` against the attached image:

```bash
./configure CC="clang -fsanitize=address" CXX="clang++ -fsanitize=address" \
            CFLAGS="-g -O1" CXXFLAGS="-g -O1"
make -j$(nproc)

ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  ./tools/fstools/fls ffs_itoo_oob_write.img
```

ASAN output:

```
=================================================================
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7ce1e02e0480 at pc 0x... bp 0x... sp 0x...
READ of size 128 at 0x7ce1e02e0480 thread T0
    #0 0x... in __asan_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:63:3
    #1 0x... in ffs_dinode_load(FFS_INFO*, unsigned long, ffs_inode*) /src/sleuthkit/tsk/fs/ffs.c
    #2 0x... in ffs_inode_walk(TSK_FS_INFO*, unsigned long, unsigned long, TSK_FS_META_FLAG_ENUM, TSK_FS_META_WALK_CB, void*) /src/sleuthkit/tsk/fs/ffs.c:968:13
    #3 0x... in tsk_fs_dir_find_orphans /src/sleuthkit/tsk/fs/fs_dir.c:1407:9

0x7ce1e02e0480 is located 0 bytes after 1024-byte region [0x7ce1e02e0080,0x7ce1e02e0480)
allocated by thread T0 here:
    #0 0x... in calloc
    #1 0x... in tsk_malloc /src/sleuthkit/tsk/base/mymalloc.c:32:16
    #2 0x... in ffs_dinode_load(FFS_INFO*, unsigned long, ffs_inode*) /src/sleuthkit/tsk/fs/ffs.c:135:38

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/sleuthkit/tsk/fs/ffs.c in ffs_dinode_load
```

### Impact
Any tool or library using libtsk to walk inodes in a UFS1/FFS filesystem (e.g., `fls`, `ils`, orphan-file detection in Autopsy) will crash when processing a crafted image. The 128-byte OOB read can expose adjacent heap contents (information disclosure) including pointers and data from prior allocations.

### Remediation
Add a bounds check before the `memcpy` in `ffs_dinode_load()`:

```c
offs = itoo_lcl(fs, ffs->fs.sb1, inum) * sizeof(ffs_inode1);
if (offs + sizeof(ffs_inode1) > ffs->ffsbsize_b) {
    tsk_release_lock(&ffs->lock);
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
    tsk_error_set_errstr("ffs_dinode_load: inode offset out of bounds for inum %" PRIuINUM, inum);
    return 1;
}
memcpy((char *) dino_buf, ffs->itbl_buf + offs, sizeof(ffs_inode1));
```

Also validate `fs_inopb` during superblock parsing in `ffs_open()`:

```c
uint32_t inopb = tsk_getu32(fs->endian, ffs->fs.sb1->fs_inopb);
uint32_t expected = ffs->ffsbsize_b / sizeof(ffs_inode1);
if (inopb == 0 || inopb > expected) {
    tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
    tsk_error_set_errstr("ffs_open: fs_inopb %u exceeds bsize/inode_size %u", inopb, expected);
    return NULL;
}
```


- Severity: High
  - CWE:
    - CWE-125: Out-of-Bounds Read
    - CWE-20: Improper Input Validation (fs_inopb not validated against block size)
    - CWE-122: Heap-based Buffer Overflow
  - CVSS v3.1: AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H → 7.1 (High)
    - 128-byte OOB read is more significant for info disclosure than issue 10