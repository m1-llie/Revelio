# [HEAP-BUFFER-OVERFLOW] btrfs tree node number_of_items=0 integer underflow - sleuthkit

## Summary

When a btrfs tree node has `number_of_items=0`, the code in `btrfs_treenode_push()`
computes `node->header.number_of_items - 1` as a `uint32_t`, which underflows to
`0xFFFFFFFF`. This huge index is then used in `btrfs_treenode_set_index()` to compute
a byte offset `0xFFFFFFFF * BTRFS_ITEM_RAWLEN` into the node data buffer, causing an
out-of-bounds read far past the heap allocation.

- **Affected file**: `tsk/fs/btrfs.cpp` (lines 452, 1285, 1559)
- **Confirmed on commit**: `01de034` (2026-04-15, sleuthkit main)
- **Sanitizer**: ASAN (crash confirmed)
- **Impact**: DoS / information disclosure

## Root Cause

In `btrfs_treenode_push()`:
```cpp
btrfs_treenode_set_index(node, true,
    a_initial_index == BTRFS_FIRST ? 0 : node->header.number_of_items - 1);
```

When `number_of_items = 0` and `a_initial_index = BTRFS_LAST`:
- `0 - 1 = 0xFFFFFFFF` (unsigned 32-bit underflow)
- `btrfs_treenode_set_index(node, true, 0xFFFFFFFF)` is called
- In `btrfs_treenode_set_index()`:
  ```cpp
  uint8_t *raw = a_node->data + a_node->index *
      (a_node->header.level ? BTRFS_KEY_POINTER_RAWLEN : BTRFS_ITEM_RAWLEN);
  ```
- `a_node->data + 0xFFFFFFFF * 25` points far past the 3995-byte node buffer

No check exists that `number_of_items > 0` before subtracting 1 in the `BTRFS_LAST`
path.

## Proof of Concept

### Reproduction

```bash
docker run --rm --memory=2g \
  -v /scr2/yiwei/vul-agent/zero-day/sleuthkit/03-btrfs-SF01-integer-underflow-zero-items:/h \
  vulagent/sleuthkit:20260417 \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_btrfs_fuzzer /h/btrfs_sf01_zero_items.img"
```

### Sanitizer Output

```
=================================================================
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7df6055e749b at pc 0x557c059d3a47 bp 0x7ffdfda395f0 sp 0x7ffdfda395e8
READ of size 1 at 0x7df6055e749b thread T0
    #0 0x557c059d3a46 in btrfs_item_rest_rawparse /src/sleuthkit/tsk/fs/btrfs.cpp:452:27
    #1 0x557c059d3a46 in btrfs_treenode_set_index(BTRFS_TREENODE*, bool, int) /src/sleuthkit/tsk/fs/btrfs.cpp:1285:9
    #2 0x557c059d2c6e in btrfs_treenode_single_step(BTRFS_INFO*, BTRFS_TREENODE**, BTRFS_DIRECTION) /src/sleuthkit/tsk/fs/btrfs.cpp:1559:5
    #3 0x557c059c404b in btrfs_treenode_step /src/sleuthkit/tsk/fs/btrfs.cpp:1613:40
    #4 0x557c059c404b in btrfs_chunks_from_chunktree /src/sleuthkit/tsk/fs/btrfs.cpp:1751:41
    #5 0x557c059c404b in btrfs_open /src/sleuthkit/tsk/fs/btrfs.cpp:5020:21
    #6 0x557c058fb205 in tsk_fs_open_img_decrypt /src/sleuthkit/tsk/fs/fs_open.c:307:16
    #7 0x557c058eaae8 in LLVMFuzzerTestOneInput /src/sleuthkit/ossfuzz/fls_fuzzer.cc:34:5

0x7df6055e749b is located 0 bytes after 3995-byte region [0x7df6055e6500,0x7df6055e749b)
allocated by thread T0 here:
    #0 0x557c058e931d in operator new[](unsigned long) /src/llvm-project/compiler-rt/lib/asan/asan_new_delete.cpp:111:37
    #1 0x557c059d49ea in btrfs_treenode_push(BTRFS_INFO*, BTRFS_TREENODE**, unsigned long, BTRFS_DIRECTION) /src/sleuthkit/tsk/fs/btrfs.cpp:1418:18
    #2 0x557c059c3e04 in btrfs_treenode_extremum /src/sleuthkit/tsk/fs/btrfs.cpp:1445:14
    #3 0x557c059c3e04 in btrfs_chunks_from_chunktree /src/sleuthkit/tsk/fs/btrfs.cpp:1742:28

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/sleuthkit/tsk/fs/btrfs.cpp:452:27 in btrfs_item_rest_rawparse
```

## Impact

- **Denial of Service**: Any btrfs tree node with `number_of_items=0` triggers the
  crash, affecting all tree types traversed during filesystem open.
- **Information Disclosure**: The OOB read reaches adjacent heap memory pages, leaking
  heap contents.
- **Exploitability**: Trivially crafted — setting a zero-item tree node in the chunk
  tree is sufficient.

## CWE

- CWE-191: Integer Underflow (Wraparound)
- CWE-125: Out-of-Bounds Read

## Suggested Fix

Validate `number_of_items` before use in `btrfs_treenode_push()`:

```cpp
if (node->header.number_of_items == 0) {
    btrfs_error(TSK_ERR_FS_INODE_COR, "btrfs_treenode_push: empty tree node");
    btrfs_treenode_pop(&node);
    delete[] raw;
    return false;
}
```

Also guard the `BTRFS_LAST` branch explicitly:
```cpp
uint32_t last_idx = (a_initial_index == BTRFS_FIRST) ? 0
    : (node->header.number_of_items - 1);
// number_of_items == 0 already rejected above
btrfs_treenode_set_index(node, true, last_idx);
```
