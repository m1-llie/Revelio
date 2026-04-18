# [HEAP-BUFFER-OVERFLOW] btrfs tree node large number_of_items OOB read - sleuthkit

## Summary

`btrfs_treenode_push()` reads `number_of_items` from an untrusted tree node header
without bounds validation against the actual node size. The value is then used in
`btrfs_treenode_set_index()` to compute a byte offset into the node's data buffer. When
`number_of_items` is set to a large value (e.g., 0x10000000), the item descriptor
access in `btrfs_item_rest_rawparse()` reads past the end of the allocated node data
buffer, causing a heap-buffer-overflow.

- **Affected file**: `tsk/fs/btrfs.cpp` (lines 452, 1285)
- **Confirmed on commit**: `01de034` (2026-04-15, sleuthkit main)
- **Sanitizer**: ASAN (crash confirmed)
- **Impact**: DoS / information disclosure

## Root Cause

In `btrfs_tree_header_rawparse()`:
```cpp
a_th->number_of_items = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x60);
```
No bounds check. In `btrfs_treenode_push()`:
```cpp
btrfs_treenode_set_index(node, true, a_initial_index == BTRFS_FIRST ? 0 : node->header.number_of_items - 1);
```
In `btrfs_treenode_set_index()`:
```cpp
uint8_t *raw = a_node->data + a_node->index *
        (a_node->header.level ? BTRFS_KEY_POINTER_RAWLEN : BTRFS_ITEM_RAWLEN);
btrfs_key_rawparse(raw, &a_node->key);
raw += BTRFS_KEY_RAWLEN;
btrfs_item_rest_rawparse(raw, &a_node->item);
```

The node data buffer is `nodesize - BTRFS_TREE_HEADER_RAWLEN = 4096 - 101 = 3995`
bytes. With `number_of_items = 0x10000000`, `a_node->index * BTRFS_ITEM_RAWLEN`
produces an offset far beyond the 3995-byte buffer.

## Proof of Concept

### Reproduction

```bash
docker run --rm --memory=2g \
  -v /scr2/yiwei/vul-agent/zero-day/sleuthkit/05-btrfs-SF07-large-num-items-oob:/h \
  vulagent/sleuthkit:20260417 \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_btrfs_fuzzer /h/btrfs_sf07_large_num_items.img"
```

### Sanitizer Output

```
=================================================================
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7df2210e749b at pc 0x5627b36fca47 bp 0x7ffc01e45450 sp 0x7ffc01e45448
READ of size 1 at 0x7df2210e749b thread T0
    #0 0x5627b36fca46 in btrfs_item_rest_rawparse /src/sleuthkit/tsk/fs/btrfs.cpp:452:27
    #1 0x5627b36fca46 in btrfs_treenode_set_index(BTRFS_TREENODE*, bool, int) /src/sleuthkit/tsk/fs/btrfs.cpp:1285:9
    #2 0x5627b36fbc6e in btrfs_treenode_single_step(BTRFS_INFO*, BTRFS_TREENODE**, BTRFS_DIRECTION) /src/sleuthkit/tsk/fs/btrfs.cpp:1559:5
    #3 0x5627b36ed04b in btrfs_treenode_step /src/sleuthkit/tsk/fs/btrfs.cpp:1613:40
    #4 0x5627b36ed04b in btrfs_chunks_from_chunktree /src/sleuthkit/tsk/fs/btrfs.cpp:1751:41
    #5 0x5627b36ed04b in btrfs_open /src/sleuthkit/tsk/fs/btrfs.cpp:5020:21
    #6 0x5627b3624205 in tsk_fs_open_img_decrypt /src/sleuthkit/tsk/fs/fs_open.c:307:16
    #7 0x5627b3613ae8 in LLVMFuzzerTestOneInput /src/sleuthkit/ossfuzz/fls_fuzzer.cc:34:5

0x7df2210e749b is located 0 bytes after 3995-byte region [0x7df2210e6500,0x7df2210e749b)
allocated by thread T0 here:
    #0 0x5627b361231d in operator new[](unsigned long) /src/llvm-project/compiler-rt/lib/asan/asan_new_delete.cpp:111:37
    #1 0x5627b36fd9ea in btrfs_treenode_push(BTRFS_INFO*, BTRFS_TREENODE**, unsigned long, BTRFS_DIRECTION) /src/sleuthkit/tsk/fs/btrfs.cpp:1418:18

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/sleuthkit/tsk/fs/btrfs.cpp:452:27 in btrfs_item_rest_rawparse
```

## Impact

- **Denial of Service**: Any btrfs tree node (chunk tree, root tree, FS tree, etc.)
  with a crafted `number_of_items` field causes a crash.
- **Information Disclosure**: OOB reads may expose adjacent heap memory contents.
- **Exploitability**: Affects all tree types, reachable through multiple code paths.

## CWE

- CWE-125: Out-of-Bounds Read
- CWE-20: Improper Input Validation

## Suggested Fix

In `btrfs_tree_header_rawparse()` or `btrfs_treenode_push()`, validate
`number_of_items` against the maximum possible items for the node size:

```cpp
uint32_t item_size = a_th->level ? BTRFS_KEY_POINTER_RAWLEN : BTRFS_ITEM_RAWLEN;
uint32_t max_items = (nodesize - BTRFS_TREE_HEADER_RAWLEN) / item_size;
if (a_th->number_of_items > max_items) {
    // Error: corrupted tree node
    return false;
}
```
