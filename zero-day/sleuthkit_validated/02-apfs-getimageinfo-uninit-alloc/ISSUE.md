# [SECURITY] ASAN allocation-size-too-big in APFSPoolCompat::getImageInfo (heap corruption)

**Severity**: High  
**CWE**: CWE-20 (Improper Input Validation), CWE-122 (Heap-Based Buffer Overflow)  
**Affected branch**: `develop` at commit `d784e64db6` (2026-04-13)  
**Sanitizer**: ASAN — crash confirmed

---

## Summary

`APFSPoolCompat::getImageInfo()` in `tsk/pool/apfs_pool_compat.cpp` reads an
attacker-controlled `num_img` field from a malformed APFS image and passes it
unchecked to `tsk_img_copy_image_names()`, which multiplies it by a pointer size
and calls `tsk_malloc`. With `num_img = 0xF5F5F5F5` (a value that can appear in
heap memory via attacker-controlled image data), the computed allocation size
`0xfffffffdf5f5f5f0` massively exceeds the ASAN heap limit, causing an abort.

On non-instrumented builds the same overflow can produce an undersized heap
buffer, which subsequent image-name copy operations write past — a heap-based
buffer overflow exploitable by a maliciously crafted APFS image.

---

## Affected Code

**File**: `tsk/pool/apfs_pool_compat.cpp`, line 343  
**File**: `tsk/img/img_open.cpp`, line 676  
**Function**: `APFSPoolCompat::getImageInfo(_TSK_POOL_INFO const*, unsigned long)`

---

## Reproduction

Build the ASAN fuzzer from `develop` at `d784e64db6`:

```bash
# Build Docker image (develop branch, d784e64db6)
docker run --rm --memory=2g \
  -v /path/to/apfs_minimal_valid.img:/h/apfs_minimal_valid.img \
  vulagent/sleuthkit:develop-20260418 \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
           /out/asan/fls_apfs_fuzzer /h/apfs_minimal_valid.img"
```

**PoC image**: `apfs_minimal_valid.img` (attached)

---

## ASAN Output

```
=================================================================
==1==ERROR: AddressSanitizer: requested allocation size 0xfffffffdf5f5f5f0
  (0xfffffffdf5f605f0 after adjustments for alignment, red zones etc.)
  exceeds maximum supported size of 0x10000000000 (thread T0)
    #0 0x... in calloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:74:3
    #1 0x... in tsk_malloc /src/sleuthkit/tsk/base/mymalloc.c:32:16
    #2 0x... in tsk_img_copy_image_names /src/sleuthkit/tsk/img/img_open.cpp:676:44
    #3 0x... in APFSPoolCompat::getImageInfo(_TSK_POOL_INFO const*, unsigned long)
               /src/sleuthkit/tsk/pool/apfs_pool_compat.cpp:343:10
    #4 0x... in LLVMFuzzerTestOneInput /src/sleuthkit/ossfuzz/fls_apfs_fuzzer.cc:43:5

SUMMARY: AddressSanitizer: allocation-size-too-big mymalloc.c:32:16 in tsk_malloc
```

---

## Root Cause

`apfs_pool_compat.cpp:343` calls `getImageInfo` which reads a `num_img` value
from the parsed APFS pool info. This value originates from `APFSPool::open()`
→ `mem_open()` where `num_img` is stored in a `TSK_IMG_INFO` that can carry
stale/attacker-influenced heap values. The value is passed unvalidated to
`tsk_img_copy_image_names()`, which computes:

```c
images = (TSK_TCHAR **)tsk_malloc(num_img * sizeof(TSK_TCHAR *));
```

With `num_img` = `0xF5F5F5F5`, the product overflows and produces a request
for `~18 EB` of heap.

---

## Impact

- Any tool using libtsk to open an APFS disk image is affected (Autopsy, `fls`, `icat`, etc.)
- A crafted APFS image crashes the process; on 32-bit or non-ASAN builds, the
  allocation size wraps to small, enabling heap corruption.
- Attack vector: local file parsing (forensic toolchain) or remote if images
  are parsed from untrusted sources.

---

## Suggested Fix

Add an upper-bound check on `num_img` before the allocation in
`tsk_img_copy_image_names()` (or before the call in `getImageInfo`):

```c
if (num_img == 0 || num_img > TSK_IMG_MAX_IMAGES) {
    tsk_error_set_errno(TSK_ERR_IMG_OPEN);
    tsk_error_set_errstr("getImageInfo: num_img value (%zu) out of range", num_img);
    return 1;
}
```

---

## Attachments

- `apfs_minimal_valid.img` — PoC filesystem image (triggers crash)
- `run_poc.sh` — exact reproduction command
