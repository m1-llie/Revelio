# [HEAP-BUFFER-OVERFLOW] ntfs_fix_idxrec upd_seq array OOB read - sleuthkit

## Summary

A heap buffer overflow (out-of-bounds READ) exists in `ntfs_fix_idxrec()` in
`tsk/fs/ntfs_dent.cpp` (line 737). An attacker can craft an NTFS filesystem image
with a malformed `$INDEX_ALLOCATION` attribute whose INDX record header contains a
`upd_off` value set near the end of the allocated buffer and a `upd_cnt` value that
causes reading past the end of the 4096-byte index record buffer.

- **Affected file**: `tsk/fs/ntfs_dent.cpp` (line 737)
- **Confirmed on commit**: `01de034` (2026-04-15, sleuthkit develop-4.14)
- **Re-confirmed on commit**: `d784e64db6` (2026-04-13, sleuthkit develop branch)
- **Sanitizer**: ASAN (crash confirmed on both commits)
- **Impact**: DoS / information disclosure / potential OOB write

## Root Cause

`ntfs_fix_idxrec()` applies the NTFS update sequence correction to an index record
buffer. The existing bounds check at lines 684–691 validates:

```c
uint16_t upd_off = tsk_getu16(fs->endian, idxrec->upd_off);
if (upd_off > len || sizeof(ntfs_upd) > (len - upd_off)) {
    // error: corrupt idx record
    return 1;
}
```

`sizeof(ntfs_upd)` = 4 bytes (the fixed portion). This validates that the struct
header fits, but **does NOT validate that the full variable-length `upd_seq` array
(2 * (upd_cnt - 1) bytes) fits within the buffer**.

Subsequently, the loop at line 700:
```c
for (i = 1; i < tsk_getu16(fs->endian, idxrec->upd_cnt); i++) {
    int offset = i * NTFS_UPDATE_SEQ_STRIDE - 2;
    uint16_t cur_seq = tsk_getu16(fs->endian, (uintptr_t) idxrec + offset);

    if (cur_seq != orig_seq) {
        uint16_t cur_repl =
            tsk_getu16(fs->endian, &upd->upd_seq + (i - 1) * 2);  // <-- OOB READ
```

**Trigger conditions:**
1. `upd_off = len - 4` (e.g., `upd_off = 4092` for a 4096-byte INDX record)
2. `upd_cnt = 3` (loop runs for `i = 1, 2`)
3. Sector-end byte at offset 510 matches `upd_val` (i=1 passes)
4. Sector-end byte at offset 1022 does NOT match `upd_val` (i=2 triggers mismatch)
5. Mismatch branch reads `tsk_getu16(&upd->upd_seq + 2)` = `buffer[4094..4096]`
   → reads 1 byte past the 4096-byte allocation

## Proof of Concept

### Reproduction

```bash
docker run --rm --memory=2g \
  -v /scr2/yiwei/revelio/zero-day/sleuthkit/13-ntfs-idxrec-heap-buffer-overflow:/h \
  revelio/sleuthkit:20260417 \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_ntfs_fuzzer /h/ntfs_idxrec_oob.img"
```

### Sanitizer Output

```
=================================================================
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7dcb4d0e4d00 at pc 0x...
READ of size 1 at 0x7dcb4d0e4d00 thread T0
    #0 0x... in ntfs_fix_idxrec(NTFS_INFO*, ntfs_idxrec*, unsigned int) /src/sleuthkit/tsk/fs/ntfs_dent.cpp:737:22
    #1 0x... in ntfs_dir_open_meta /src/sleuthkit/tsk/fs/ntfs_dent.cpp:1211:17
    #2 0x... in tsk_fs_dir_open_meta_internal /src/sleuthkit/tsk/fs/fs_dir.cpp:310:14
    #3 0x... in tsk_fs_dir_walk_recursive(...) /src/sleuthkit/tsk/fs/fs_dir.cpp:675:9
    #4 0x... in tsk_fs_dir_walk_internal /src/sleuthkit/tsk/fs/fs_dir.cpp:1007:14
    #5 0x... in tsk_fs_fls /src/sleuthkit/tsk/fs/fls_lib.cpp:246:12
    #6 0x... in LLVMFuzzerTestOneInput /src/sleuthkit/ossfuzz/fls_fuzzer.cc:39:5

0x7dcb4d0e4d00 is located 0 bytes after 4096-byte region [0x7dcb4d0e3d00,0x7dcb4d0e4d00)
allocated by thread T0 here:
    #0 0x... in calloc
    #1 0x... in tsk_malloc /src/sleuthkit/tsk/base/mymalloc.c:32:16
    #2 0x... in ntfs_dir_open_meta /src/sleuthkit/tsk/fs/ntfs_dent.cpp:1046:53

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/sleuthkit/tsk/fs/ntfs_dent.cpp:737:22 in ntfs_fix_idxrec
```

## Impact

- **Denial of Service**: Reliably crashes the sleuthkit NTFS parser when processing a
  crafted NTFS filesystem image.
- **Information Disclosure**: 1-byte OOB read from heap can leak adjacent heap contents
  in info-disclosure scenarios.
- **Potential OOB Write**: If the update sequence values match instead of mismatch, the
  write path at line 731 writes 2 bytes via `*old_val++ = *new_val++` pointers derived
  from the same OOB address — a heap-buffer-overflow WRITE (higher severity).
- **Attack surface**: Any tool using TSK to list NTFS directory contents (forensic
  analysis, incident response, file system scanning).

## CWE

- CWE-125: Out-of-Bounds Read
- CWE-787: Out-of-Bounds Write (write path variant)

## Suggested Fix

Add a bounds check for the full `upd_seq` array size before entering the loop:

```c
// After existing check for sizeof(ntfs_upd):
uint16_t upd_cnt = tsk_getu16(fs->endian, idxrec->upd_cnt);
size_t upd_seq_total_size = (upd_cnt > 0) ? (size_t)(upd_cnt - 1) * 2 : 0;
size_t upd_struct_total = 2 + upd_seq_total_size;  // upd_val[2] + upd_seq[...]
if (upd_struct_total > (len - upd_off)) {
    tsk_error_set_errstr("ntfs_fix_idxrec: upd_seq array extends past idx record end");
    return 1;
}
```

This ensures that all `(upd_cnt - 1)` replacement values fit within the buffer before
the loop starts accessing them.
