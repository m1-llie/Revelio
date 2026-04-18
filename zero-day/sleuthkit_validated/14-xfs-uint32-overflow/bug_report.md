# [INTEGER OVERFLOW] XFS xfs_inode_get_offset uint32_t * uint32_t overflow - sleuthkit

## Summary

A confirmed integer overflow exists in `xfs_inode_get_offset()` in The Sleuth Kit's
XFS filesystem parser (`tsk/fs/tsk_xfs.h:1167`). The multiplication
`sb_agblocks * sb_blocksize` uses two `uint32_t` operands, allowing overflow to zero
when both fields are large (e.g., `sb_agblocks=1048576` and `sb_blocksize=4096`). This
causes `xfs_inode_get_offset()` to return incorrect filesystem byte offsets, directing
all inode reads to allocation group 0 regardless of the actual AG.

- **Affected file**: `tsk/fs/tsk_xfs.h` (line 1167)
- **Confirmed on commit**: `01de034` (2026-04-15, sleuthkit main)
- **Sanitizer**: UBSan with `-fsanitize=unsigned-integer-overflow` (standard UBSan
  misses unsigned overflow; requires this additional Clang flag)
- **Impact**: Wrong forensic results / information disclosure

## Root Cause

```c
// tsk/fs/tsk_xfs.h line ~1167
TSK_OFF_T ag_offset = ag_num * (tsk_getu32(fs->endian, xfs->fs->sb_agblocks) *
                                tsk_getu32(fs->endian, xfs->fs->sb_blocksize));
```

Both `tsk_getu32()` calls return `uint32_t`. The inner multiplication:
```
sb_agblocks * sb_blocksize = 1048576 * 4096 = 4,294,967,296
```
This exceeds `UINT32_MAX` (4,294,967,295), wrapping to `0` on overflow. As a result,
`ag_offset = 0` regardless of `ag_num`, and all allocation groups map to offset 0.
Every inode lookup returns data from AG 0 instead of the correct AG.

Real XFS filesystems commonly use `sb_agblocks` values in the millions. TSK does not
validate an upper bound on `sb_agblocks`.

## Proof of Concept

### Reproduction

```bash
docker run --rm --memory=2g \
  -v /scr2/yiwei/vul-agent/zero-day/sleuthkit/14-xfs-inode-get-offset-uint32-overflow:/h \
  vulagent/sleuthkit:20260417 \
  bash -c "UBSAN_OPTIONS='halt_on_error=0:print_stacktrace=1' \
  /out/ubsan/fls_xfs_fuzzer /h/xfs_agno_overflow.img" 2>&1 || true
```

> **Note**: Requires UBSan build compiled with `-fsanitize=unsigned-integer-overflow`
> (a Clang extension). The standard `undefined` sanitizer does not flag unsigned
> overflow by default since C/C++ unsigned wraparound is technically well-defined.

### Sanitizer Output

```
tsk/fs/tsk_xfs.h:1167:82: runtime error: unsigned integer overflow: 1048576 * 4096 cannot be represented in type 'uint32_t' (aka 'unsigned int')
    #0 in xfs_inode_get_offset(XFS_INFO*, unsigned long) /src/sleuthkit/tsk/fs/tsk_xfs.h:1167:82
    #1 in xfs_dinode_load(XFS_INFO*, unsigned long, xfs_dinode*) /src/sleuthkit/tsk/fs/xfs.cpp:180:12
    #2 in xfs_inode_lookup(TSK_FS_INFO*, TSK_FS_FILE*, unsigned long) /src/sleuthkit/tsk/fs/xfs.cpp:453:9
    #3 in tsk_fs_file_open_meta /src/sleuthkit/tsk/fs/fs_file.cpp:133:9
    #4 in xfs_dir_open_meta /src/sleuthkit/tsk/fs/xfs_dent.cpp:400:9
    #5 in tsk_fs_dir_open_meta_internal ...
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior tsk/fs/tsk_xfs.h:1167:82
```

## Impact

- **Wrong forensic results**: All inodes in non-zero AGs resolve to wrong offsets,
  causing TSK to read and parse filesystem data from incorrect locations. File metadata,
  timestamps, and content could be incorrectly attributed to wrong files.
- **Information disclosure**: A malicious XFS image can force the parser to read from
  arbitrary positions within the image by controlling `sb_agblocks` and `sb_blocksize`.
- **Attacker-controlled**: Both operands are fully controlled by the filesystem image.

## CWE

- CWE-190: Integer Overflow or Wraparound
- CWE-125: Out-of-Bounds Read

## Suggested Fix

Cast to `TSK_OFF_T` (64-bit) before the multiplication:

```c
// tsk/fs/tsk_xfs.h - xfs_inode_get_offset()
TSK_OFF_T ag_offset = (TSK_OFF_T)ag_num *
    ((TSK_OFF_T)tsk_getu32(fs->endian, xfs->fs->sb_agblocks) *
     (TSK_OFF_T)tsk_getu32(fs->endian, xfs->fs->sb_blocksize));
```

Also add validation in `xfs_open()` to reject parameter combinations that would cause
overflow:
```c
if ((uint64_t)sb_agblocks * fs->block_size > UINT64_MAX / 2) {
    // reject: filesystem parameters too large
}
```
