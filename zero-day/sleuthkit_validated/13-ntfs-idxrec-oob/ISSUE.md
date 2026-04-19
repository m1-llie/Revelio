Heap-buffer-overflow in ntfs_fix_idxrec via unvalidated upd_seq array length (NTFS index record)

### Summary
`ntfs_fix_idxrec()` in SleuthKit's NTFS parser validates that the fixed `ntfs_upd` struct header fits within an INDX record buffer, but does not validate that the variable-length `upd_seq` replacement array (2 × (`upd_cnt` − 1) bytes) also fits. A crafted NTFS `$INDEX_ALLOCATION` attribute with a large `upd_cnt` and an `upd_off` near the end of the buffer causes the loop to read the replacement values past the end of the 4096-byte allocation.

### Details
Tested Version:
- SleuthKit 4.15.0 (tag `sleuthkit-4.15.0`, commit `01de034`, released 2026-04-15)

In `tsk/fs/ntfs_dent.cpp`, the existing bounds check (line 684–691) only validates that `sizeof(ntfs_upd)` (4 bytes — the fixed header) fits:

```c
uint16_t upd_off = tsk_getu16(fs->endian, idxrec->upd_off);
if (upd_off > len || sizeof(ntfs_upd) > (len - upd_off)) {
    // error: corrupt idx record
    return 1;
}
```

The check does **not** verify that the full variable-length `upd_seq` array fits. The loop at line ~700 then reads replacement values from `&upd->upd_seq + (i - 1) * 2`:

```c
for (i = 1; i < tsk_getu16(fs->endian, idxrec->upd_cnt); i++) {
    int offset = i * NTFS_UPDATE_SEQ_STRIDE - 2;
    uint16_t cur_seq = tsk_getu16(fs->endian, (uintptr_t) idxrec + offset);
    if (cur_seq != orig_seq) {
        uint16_t cur_repl =
            tsk_getu16(fs->endian, &upd->upd_seq + (i - 1) * 2);  // OOB READ
```

Trigger conditions in PoC:
1. `upd_off = 4092` (4 bytes before end of a 4096-byte INDX record)
2. `upd_cnt = 3` (loop runs for `i = 1, 2`)
3. Sector-end byte at offset 510 matches `upd_val` → `i=1` passes, no OOB
4. Sector-end byte at offset 1022 does not match `upd_val` → `i=2` mismatch branch reads `&upd->upd_seq + 2 = buffer[4094..4096]` — 1 byte past end

### PoC
Build SleuthKit 4.15.0 with AddressSanitizer, then run `fls` against the attached image:

```bash
./configure CC="clang -fsanitize=address" CXX="clang++ -fsanitize=address" \
            CFLAGS="-g -O1" CXXFLAGS="-g -O1"
make -j$(nproc)

ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  ./tools/fstools/fls ntfs_idxrec_oob.img
```

ASAN output:

```
=================================================================
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7de7480e9d00 at pc 0x... bp 0x... sp 0x...
READ of size 1 at 0x7de7480e9d00 thread T0
    #0 0x... in ntfs_fix_idxrec(NTFS_INFO*, ntfs_idxrec*, unsigned int) /src/sleuthkit/tsk/fs/ntfs_dent.cpp:713:17
    #1 0x... in ntfs_dir_open_meta /src/sleuthkit/tsk/fs/ntfs_dent.cpp:1206:17
    #2 0x... in tsk_fs_dir_open_meta_internal /src/sleuthkit/tsk/fs/fs_dir.c:308:14
    #3 0x... in tsk_fs_dir_walk_recursive /src/sleuthkit/tsk/fs/fs_dir.c
    #4 0x... in tsk_fs_fls /src/sleuthkit/tsk/fs/fls_lib.c

0x7de7480e9d00 is located 0 bytes after 4096-byte region [0x7de7480e8d00,0x7de7480e9d00)
allocated by thread T0 here:
    #0 0x... in calloc
    #1 0x... in tsk_malloc /src/sleuthkit/tsk/base/mymalloc.c:32:16
    #2 0x... in ntfs_dir_open_meta /src/sleuthkit/tsk/fs/ntfs_dent.cpp:1046:53

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/sleuthkit/tsk/fs/ntfs_dent.cpp:713:17 in ntfs_fix_idxrec
```

### Impact
Any forensic tool using libtsk to list NTFS directory contents (`fls`, `icat`, Autopsy, incident-response pipelines) will crash when parsing a crafted NTFS image containing a malformed `$INDEX_ALLOCATION` INDX record. The 1-byte OOB read can leak adjacent heap contents. If the update-sequence value matches instead of mismatching, the write path at line ~731 (`*old_val++ = *new_val++`) derives pointers from the same OOB address; a heap-buffer-overflow **write** of higher severity is also possible.

### Remediation
Add a bounds check for the full `upd_seq` array before entering the loop:

```c
// After the existing sizeof(ntfs_upd) check:
uint16_t upd_cnt = tsk_getu16(fs->endian, idxrec->upd_cnt);
size_t upd_seq_bytes = (upd_cnt > 0) ? (size_t)(upd_cnt - 1) * 2 : 0;
size_t upd_total = 2 + upd_seq_bytes;  // upd_val (2 bytes) + upd_seq array
if (upd_total > (len - upd_off)) {
    tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
    tsk_error_set_errstr("ntfs_fix_idxrec: upd_seq array extends past idx record end");
    return 1;
}
```


- Severity: High (bordering Critical given the write path)
  - CWE:                                                    
    - CWE-125: Out-of-Bounds Read (confirmed)
    - CWE-787: Out-of-Bounds Write (write path reachable if cur_seq == orig_seq)
    - CWE-20: Improper Input Validation                                         
  - CVSS v3.1: AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H → 7.3 (High)
    - Elevated due to OOB write potential; if write path is exploitable, Integrity impact could be H → pushes toward 8.x