# [HEAP-BUFFER-OVERFLOW] btrfs chunk item stripe_count OOB read - sleuthkit

## Summary

`btrfs_chunk_item_fromraw()` reads `number_of_stripes` from an untrusted CHUNK_ITEM in
the superblock's embedded `system_chunks` without bounds validation. It then loops
through parsing each stripe from the raw buffer. When `number_of_stripes` is set to a
large value (e.g., 0xFFFF), the loop reads far past the end of the 4096-byte superblock
raw buffer, causing a heap-buffer-overflow.

- **Affected file**: `tsk/fs/btrfs.cpp` (lines 358, 396)
- **Confirmed on commit**: `01de034` (2026-04-15, sleuthkit develop-4.14)
- **Re-confirmed on commit**: `d784e64db6` (2026-04-13, sleuthkit develop branch)
- **Sanitizer**: ASAN (crash confirmed on both commits)
- **Impact**: DoS / information disclosure

## Root Cause

In `btrfs_chunk_item_fromraw()`:
```cpp
ci->number_of_stripes = tsk_getu16(BTRFS_ENDIAN, a_raw + 0x2C);
ci->stripes = new BTRFS_CHUNK_ITEM_STRIPE[ci->number_of_stripes];
for (uint16_t i = 0; i < ci->number_of_stripes; i++)
    btrfs_chunk_item_stripe_rawparse(a_raw + 0x30 + i * 0x20, &ci->stripes[i]);
```

`number_of_stripes` is read from attacker-controlled data without any upper-bound check.
The `a_raw` pointer points into the superblock's `system_chunks` buffer (at most 0x800
bytes from offset 0x32B within the 4096-byte superblock raw buffer). With
`number_of_stripes=0xFFFF`, the stripe loop attempts to read
`0xFFFF * 0x20 = 0x1FFFE0` bytes, reading far past the 4096-byte allocation.

## Proof of Concept

### Reproduction

```bash
docker run --rm --memory=2g \
  -v /scr2/yiwei/vul-agent/zero-day/sleuthkit/04-btrfs-SF06-stripe-count-oob:/h \
  vulagent/sleuthkit:20260417 \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_btrfs_fuzzer /h/btrfs_sf06_stripe_oob.img"
```

### Sanitizer Output

```
=================================================================
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7d6820fe38e8 at pc 0x55994a2284db bp 0x7fffaf4aa860 sp 0x7fffaf4aa020
READ of size 16 at 0x7d6820fe38e8 thread T0
    #0 0x55994a2284da in __asan_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:63:3
    #1 0x55994a367567 in btrfs_chunk_item_stripe_rawparse /src/sleuthkit/tsk/fs/btrfs.cpp:358:5
    #2 0x55994a367567 in btrfs_chunk_item_fromraw /src/sleuthkit/tsk/fs/btrfs.cpp:396:9
    #3 0x55994a367567 in btrfs_chunks_process_chunk_item(BTRFS_INFO*, BTRFS_CACHED_CHUNK_MAPPING*, unsigned long, unsigned char const*) /src/sleuthkit/tsk/fs/btrfs.cpp:970:28
    #4 0x55994a347c01 in btrfs_chunks_from_superblock /src/sleuthkit/tsk/fs/btrfs.cpp:1022:9
    #5 0x55994a347c01 in btrfs_open /src/sleuthkit/tsk/fs/btrfs.cpp:5016:21
    #6 0x55994a27f205 in tsk_fs_open_img_decrypt /src/sleuthkit/tsk/fs/fs_open.c:307:16
    #7 0x55994a26eae8 in LLVMFuzzerTestOneInput /src/sleuthkit/ossfuzz/fls_fuzzer.cc:34:5

0x7d6820fe38e8 is located 0 bytes after 4072-byte region [0x7d6820fe2900,0x7d6820fe38e8)
allocated by thread T0 here:
    #0 0x55994a26d20d in operator new(unsigned long) /src/llvm-project/compiler-rt/lib/asan/asan_new_delete.cpp:109:35
    #1 0x55994a3466e5 in btrfs_superblock_read /src/sleuthkit/tsk/fs/btrfs.cpp:882:28
    #2 0x55994a3466e5 in btrfs_superblock_search /src/sleuthkit/tsk/fs/btrfs.cpp:930:36
    #3 0x55994a3466e5 in btrfs_open /src/sleuthkit/tsk/fs/btrfs.cpp:4961:10

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/sleuthkit/tsk/fs/btrfs.cpp:358:5 in btrfs_chunk_item_stripe_rawparse
```

## Impact

- **Denial of Service**: Opening any btrfs filesystem image with a crafted
  `number_of_stripes` in `system_chunks` crashes TSK-based tools.
- **Information Disclosure**: 16-byte reads far past the superblock buffer can leak
  adjacent heap memory contents.
- **Attack surface**: Triggered during the earliest phase of filesystem parsing
  (superblock `system_chunks`), before any authentication or privilege check.

## CWE

- CWE-125: Out-of-Bounds Read
- CWE-20: Improper Input Validation

## Suggested Fix

Add bounds checking in `btrfs_chunk_item_fromraw()` to validate that
`number_of_stripes` fits within the buffer:

```cpp
// Before allocating stripes array:
uint32_t expected_len = 0x30 + (uint32_t)ci->number_of_stripes * 0x20;
if (expected_len > a_len) {
    // Error: num_stripes exceeds buffer
    delete ci;
    return NULL;
}
```

`btrfs_chunks_from_superblock` should also pass the remaining buffer length to
`btrfs_chunk_item_fromraw`.
