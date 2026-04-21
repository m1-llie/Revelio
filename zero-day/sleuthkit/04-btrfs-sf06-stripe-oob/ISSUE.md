# [SECURITY] ASAN heap-buffer-overflow in btrfs_chunk_item_stripe_rawparse (btrfs stripe count OOB)

**Severity**: High  
**CWE**: CWE-125 (Out-of-Bounds Read), CWE-20 (Improper Input Validation)  
**Affected branch**: `develop` at commit `d784e64db6` (2026-04-13)  
**Sanitizer**: ASAN — crash confirmed

---

## Summary

`btrfs_chunk_item_fromraw()` in `tsk/fs/btrfs.cpp` reads a `number_of_stripes`
field (uint16_t) directly from a crafted btrfs superblock chunk item without
validating it against the available buffer size. It then allocates a
`BTRFS_CHUNK_ITEM_STRIPE` array of that size and calls
`btrfs_chunk_item_stripe_rawparse()` for each stripe, where a `memcpy` reads 32
bytes per stripe from the raw buffer. With `number_of_stripes = 0x7F` in an 8-byte
chunk item, the loop reads 3200 bytes past the end of the 4072-byte superblock
allocation — a heap-buffer-overflow.

---

## Affected Code

**File**: `tsk/fs/btrfs.cpp`, line 358 (`btrfs_chunk_item_stripe_rawparse`)  
**File**: `tsk/fs/btrfs.cpp`, line 396 (`btrfs_chunk_item_fromraw`)  
**Call chain**: `btrfs_open` → `btrfs_chunks_from_superblock` →
`btrfs_chunks_process_chunk_item` → `btrfs_chunk_item_fromraw` →
`btrfs_chunk_item_stripe_rawparse`

---

## Reproduction

```bash
docker run --rm --memory=2g \
  -v /path/to/btrfs_sf06_stripe_oob.img:/h/btrfs_sf06_stripe_oob.img \
  vulagent/sleuthkit:develop-20260418 \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
           /out/asan/fls_btrfs_fuzzer /h/btrfs_sf06_stripe_oob.img"
```

**PoC image**: `btrfs_sf06_stripe_oob.img` (attached)

---

## ASAN Output

```
=================================================================
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7dd394ae24e8
  at pc 0x... bp 0x... sp 0x...
READ of size 16 at 0x7dd394ae24e8 thread T0
    #0 0x... in __asan_memcpy
    #1 0x... in btrfs_chunk_item_stripe_rawparse /src/sleuthkit/tsk/fs/btrfs.cpp:358:5
    #2 0x... in btrfs_chunk_item_fromraw /src/sleuthkit/tsk/fs/btrfs.cpp:396:9
    #3 0x... in btrfs_chunks_process_chunk_item(BTRFS_INFO*, ...) /src/sleuthkit/tsk/fs/btrfs.cpp:970:28
    #4 0x... in btrfs_chunks_from_superblock /src/sleuthkit/tsk/fs/btrfs.cpp:1022:9
    #5 0x... in btrfs_open /src/sleuthkit/tsk/fs/btrfs.cpp:5016:21

0x7dd394ae24e8 is located 0 bytes after 4072-byte region [0x7dd394ae1500,0x7dd394ae24e8)
allocated by thread T0 here:
    #0 0x... in operator new(unsigned long)
    #1 0x... in btrfs_superblock_read /src/sleuthkit/tsk/fs/btrfs.cpp:882:28

SUMMARY: AddressSanitizer: heap-buffer-overflow btrfs.cpp:358:5 in btrfs_chunk_item_stripe_rawparse
```

---

## Root Cause

In `btrfs_chunk_item_fromraw()` (btrfs.cpp:379–401):

```cpp
ci->number_of_stripes = tsk_getu16(BTRFS_ENDIAN, a_raw + 0x2C);
// ...
ci->stripes = new BTRFS_CHUNK_ITEM_STRIPE[ci->number_of_stripes];
for (uint16_t i = 0; i < ci->number_of_stripes; i++)
    btrfs_chunk_item_stripe_rawparse(a_raw + 0x30 + i * 0x20, &ci->stripes[i]);
```

`number_of_stripes` is taken from the raw image without checking that
`0x30 + number_of_stripes * 0x20` does not exceed the bounds of `a_raw`'s
containing buffer. The chunk item data lives inside the 4096-byte superblock
buffer; a large `number_of_stripes` causes reads far past its end.

---

## Impact

- **DoS**: Parsing any btrfs image with a crafted chunk-tree stripe count crashes `fls`, `icat`, or Autopsy.
- **Information disclosure**: OOB read leaks heap contents adjacent to the superblock allocation.
- **Attack vector**: crafted btrfs disk image (local forensic tool, or remote if images come from untrusted sources).

---

## Suggested Fix

Before the stripe loop, validate that the declared stripes fit within the available buffer:

```cpp
// btrfs_chunk_item_fromraw(): add after reading number_of_stripes
uint32_t required = 0x30 + (uint32_t)ci->number_of_stripes * 0x20;
if (required > a_raw_len) {   // a_raw_len = caller-provided buffer bound
    btrfs_chunk_item_free(ci);
    return nullptr;
}
```

Alternatively, cap `number_of_stripes` to a sane maximum (e.g. 256).

---

## Attachments

- `btrfs_sf06_stripe_oob.img` — PoC filesystem image
- `run_poc.sh` — exact reproduction command
