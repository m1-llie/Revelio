# [USE-AFTER-FREE] yaffs2_open() returns dangling pointer - sleuthkit

## Summary

`yaffs2_open()` in `tsk/fs/yaffs.cpp` returns a **dangling pointer** to freed heap
memory. The function allocates a `YAFFSFS_INFO` structure (which embeds `TSK_FS_INFO`)
via a `std::unique_ptr`. When the function successfully parses a YAFFS2 filesystem and
reaches the `return fs` statement (line ~3259), the `unique_ptr` destructor fires as
the local scope unwinds, calling `yaffsfs_close()` which frees the entire
`YAFFSFS_INFO` struct. The raw `fs` pointer (pointing inside the now-freed
`YAFFSFS_INFO`) is returned to the caller as a seemingly valid filesystem handle.

- **Affected file**: `tsk/fs/yaffs.cpp` (line ~3259)
- **Confirmed on commit**: `01de034` (2026-04-15, sleuthkit main)
- **Sanitizer**: ASAN confirmed via dedicated driver (the standalone fuzzer harness
  exits before reallocation occurs; a test driver calling `fs->inode_walk` after open
  triggers ASAN)
- **Impact**: Use-after-free / potential remote code execution

## Root Cause

```cpp
// yaffs2_open() in tsk/fs/yaffs.cpp

std::unique_ptr<YAFFSFS_INFO, decltype(deleter)> yaffsfs{
    (YAFFSFS_INFO *) tsk_fs_malloc(sizeof(YAFFSFS_INFO)),  // line ~3048
    deleter
};

TSK_FS_INFO* fs = &(yaffsfs->fs_info);  // raw pointer into unique_ptr-owned memory

// ... 200+ lines of initialization ...

return fs;  // line ~3259: DANGLING POINTER!
// ^ At this point, yaffsfs (unique_ptr) destructor fires,
//   calling yaffsfs_close(fs) which frees the YAFFSFS_INFO block.
//   `fs` now points to freed memory, but is returned to the caller!
```

The bug: `yaffsfs.release()` is never called before `return fs`. The `unique_ptr`
correctly owns the memory and frees it when the function returns — but the raw `fs`
pointer escapes into the caller, which then uses it as a valid handle.

The freed `YAFFSFS_INFO` contains function pointers (vtable-like callbacks:
`inode_walk`, `block_walk`, `dir_open_meta`, etc.) that could be overwritten before
the caller uses them, enabling controlled-function-pointer overwrite.

## Proof of Concept

### Reproduction with standalone fuzzer

```bash
docker run --rm --memory=2g \
  -v /scr2/yiwei/vul-agent/zero-day/sleuthkit/15-yaffs-uaf-yaffs2-open-unique-ptr:/h \
  vulagent/sleuthkit:20260417 \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_yaffs_fuzzer /h/yaffs_uaf_minimal.img" 2>&1 || true
```

> **Note**: The standalone fuzzer harness may exit before reallocation occurs.
> A dedicated driver that calls `tsk_fs_fls(fs, ...)` after `tsk_fs_open_img()` will
> reliably trigger ASAN `heap-use-after-free`.

### Sanitizer Output (from dedicated driver)

```
tsk_fs_open_img returned: 0x7d4efd5e0080   <-- non-NULL dangling pointer!
=================================================================
==8212==ERROR: AddressSanitizer: heap-use-after-free on address 0x7d4efd5e00a0 at pc 0x55e675102b2e
READ of size 8 at 0x7d4efd5e00a0 thread T0
    #0 0x55e675102b2d in main /yaffs_test2.cpp:23:26

0x7d4efd5e00a0 is located 32 bytes inside of 544-byte region [0x7d4efd5e0080,0x7d4efd5e02a0)
freed by thread T0 here:
    #0 0x55e6750be816 in free asan_malloc_linux.cpp:51:3
    #1 0x55e675133126 in yaffsfs_close(TSK_FS_INFO*) /src/sleuthkit/tsk/fs/yaffs.cpp:2563:9
    #2 0x55e675130a6c in operator() /src/sleuthkit/tsk/fs/yaffs.cpp:3044:9
    #3 0x55e675130a6c in reset unique_ptr.h:290:7
    #4 0x55e675130a6c in ~unique_ptr unique_ptr.h:259:71
    #5 0x55e675130a6c in yaffs2_open /src/sleuthkit/tsk/fs/yaffs.cpp:3260:1
    #6 0x55e675102a0f in main /yaffs_test2.cpp:13:21

previously allocated by thread T0 here:
    #0 0x55e6750bec79 in calloc asan_malloc_linux.cpp:74:3
    #1 0x55e675138633 in tsk_malloc /src/sleuthkit/tsk/base/mymalloc.c:32:16
    #2 0x55e6751086aa in tsk_fs_malloc /src/sleuthkit/tsk/fs/fs_open.c:344:36
    #3 0x55e67512efb2 in yaffs2_open /src/sleuthkit/tsk/fs/yaffs.cpp:3048:26

SUMMARY: AddressSanitizer: heap-use-after-free /yaffs_test2.cpp:23:26 in main
Shadow bytes: fd fd fd fd fd fd ...  (freed heap region pattern)
```

## Impact

- **Use-after-free / potential RCE**: The dangling `TSK_FS_INFO*` is returned to the
  caller and immediately used. The freed memory contains function pointers that could be
  overwritten before the caller uses them, enabling controlled-function-pointer
  overwrite.
- **Attack surface**: Any tool that parses a user-supplied YAFFS2 filesystem image
  (`fls`, `fsstat`, `istat`, custom drivers) is vulnerable.
- **Exploitability**: A crafted YAFFS2 disk image passed to a forensic tool triggers
  the UAF. In a forensic/investigation scenario, an adversary could craft a device
  image that crashes or compromises the investigator's analysis system.

## CWE

- CWE-416: Use After Free
- CWE-825: Expired Pointer Dereference

## Suggested Fix

Add `yaffsfs.release()` before `return fs` to transfer ownership out of the
`unique_ptr`:

```cpp
// In yaffs2_open(), before the final return:
yaffsfs.release();  // Transfer ownership - caller is responsible for cleanup via tsk_fs_close
return fs;
```

This is the minimal fix. The underlying design issue is that the `unique_ptr` was
introduced to handle early-exit cleanup, but the final success path forgot to release
ownership. Alternatively, restructure to use raw pointer management throughout (as was
the original design before the `unique_ptr` was added).
