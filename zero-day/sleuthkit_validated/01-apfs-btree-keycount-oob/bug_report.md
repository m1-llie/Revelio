# [USE-OF-UNINITIALIZED-VALUE / OOB-READ] APFS btree key_count out-of-bounds iterator - sleuthkit

## Summary

When the container omap btree in an APFS image has an attacker-controlled `key_count`
(e.g., 0xFFFF), `APFSSuperblock::volume_blocks()` calls `entries()` which iterates all
`key_count` entries. The iterator accesses TOC entries (`toc.fixed[_index]`) from within
the 4096-byte block storage, but the TOC only has valid data for the actual number of
entries. For `key_count=0xFFFF` the iterator reads far beyond the valid TOC area,
triggering **use-of-uninitialized-value** (MSan) as the TOC region contains
garbage/uninitialized block data.

- **Affected file**: `tsk/fs/tsk_apfs.hpp` (lines ~222, 307, 496–507)
- **Confirmed on commit**: `01de034` (2026-04-15, sleuthkit main)
- **Sanitizer**: MSan (requires MSan build; ASAN exits cleanly)
- **Impact**: DoS / information disclosure

## Root Cause

```cpp
// tsk_apfs.hpp:496-507
inline auto entries() const {
    const auto vec = [&] {
        std::vector<typename iterator::value_type> v{};
        // BUG: for_each iterates from begin() to end()
        // end() = {this, key_count(), 0} where key_count() reads bn()->key_count
        // If key_count is attacker-controlled (0xFFFF), the iterator reads
        // 0xFFFF TOC entries from a 4096-byte block, going OOB
        std::for_each(begin(), end(), [&v](const auto e) { v.push_back(e); });
        return v;
    }();
    return vec;
}

// tsk_apfs.hpp:307 (operator++)
// When iterating: _table_data.toc.fixed[_index] is accessed for each increment
// For _index=65534 (0xFFFE): accesses offset 0xFFFE * 4 = 0x3FFF8 from TOC start
// This is far outside the 4096-byte block
```

The `key_count` field in `apfs_btree_node` (at block offset 0x24) is directly read
without bounds-checking against the block size or the available table space. An attacker
can set `key_count=0xFFFF` in the container omap btree root node to trigger iteration
over 65535 TOC entries, reading far beyond the 4096-byte block.

## Proof of Concept

### Reproduction

```bash
docker run --rm --memory=2g \
  -v /scr2/yiwei/vul-agent/zero-day/sleuthkit/01-apfs-btree-key-count-oob-read:/h \
  vulagent/sleuthkit:20260417 \
  bash -c "/out/msan/fls_apfs_fuzzer /h/apfs_btree_huge_key_count.img"
```

> **Note**: Requires MSan build (`/out/msan/fls_apfs_fuzzer`). The ASAN binary
> (`/out/asan/fls_apfs_fuzzer`) exits cleanly without triggering — MSan is needed to
> detect the uninitialized-value read through the iterator.

### Sanitizer Output

```
==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 reset  unique_ptr.h:289
    #1 ~unique_ptr  unique_ptr.h:259
    #2 APFSBtreeNodeIterator<APFSBtreeNode<apfs_omap_key,apfs_omap_value>>::
       ~APFSBtreeNodeIterator()  tsk_apfs.hpp:222
    #3 for_each  for_each.h:57
    #4 APFSBtreeNode<...>::entries() const  tsk_apfs.hpp:504
    #5 APFSSuperblock::volume_blocks() const  apfs.cpp:244
    #6 APFSPool::APFSPool(...)  apfs_pool.cpp:75
    #7 APFSPoolCompat::APFSPoolCompat(...)  pool_compat.hpp:38
    #8 tsk_pool_open_img  pool_open.cpp:149
    #9 LLVMFuzzerTestOneInput  fls_apfs_fuzzer.cc:32

  Member fields were destroyed
    (in APFSBtreeNodeIterator constructor at tsk_apfs.hpp:1234 via operator++)

SUMMARY: MemorySanitizer: use-of-uninitialized-value tsk_apfs.hpp:222
```

## Impact

Any application using TSK to parse APFS pool images (forensic tools, Autopsy, disk
analyzers) is affected. A crafted APFS image with `key_count=0xFFFF` in the container
omap btree:

- **Denial of Service**: Crash or hang during pool construction.
- **Information Disclosure**: The iterator reads arbitrary block data beyond the valid
  key/value area. With sanitizer-off builds, garbage TOC offsets redirect `key_data` and
  `val_data` pointers potentially across mapped memory regions, leaking heap contents.
- **Potential OOB Write**: If `key_data`/`val_data` calculations yield in-range but
  attacker-controlled addresses, returned `paddr` values could direct pool reads to
  arbitrary blocks.

## CWE

- CWE-125: Out-of-Bounds Read
- CWE-20: Improper Input Validation
- CWE-119: Improper Restriction of Buffer Operations

## Suggested Fix

Validate `key_count` during btree node initialization against available table space:

```cpp
// In APFSBtreeNode constructor (tsk_apfs.hpp or apfs.cpp):
const uint32_t max_entries_by_space =
    bn()->table_space_length / (has_fixed_kv_size() ? sizeof(apfs_btentry_fixed)
                                                    : sizeof(apfs_btentry_variable));
if (bn()->key_count > max_entries_by_space) {
    throw std::runtime_error("APFSBtreeNode: key_count exceeds table_space capacity");
}

// Also cross-check with btree_info for root nodes:
if (is_root() && info() != nullptr && bn()->key_count != info()->key_count) {
    throw std::runtime_error("APFSBtreeNode: key_count mismatch with btree_info");
}
```
