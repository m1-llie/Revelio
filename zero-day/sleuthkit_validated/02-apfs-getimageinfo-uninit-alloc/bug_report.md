# [ALLOCATION-SIZE-TOO-BIG] APFSPoolCompat::getImageInfo unvalidated num_img - sleuthkit

## Summary

`APFSPoolCompat::getImageInfo()` in `tsk/pool/apfs_pool_compat.cpp` copies `num_img`
and `images` from the original `TSK_IMG_INFO` structure without validating them. When
the image info was created via `malloc()` (without zeroing), these fields are
uninitialized garbage values, causing an enormous allocation request that crashes with
ASAN's `allocation-size-too-big` or silently corrupts the heap on non-instrumented
builds.

- **Affected file**: `tsk/pool/apfs_pool_compat.cpp` (line 343)
- **Confirmed on commit**: `01de034` (2026-04-15, sleuthkit develop-4.14)
- **Re-confirmed on commit**: `d784e64db6` (2026-04-13, sleuthkit develop branch)
- **Sanitizer**: ASAN (crash confirmed on both commits)
- **Impact**: DoS / potential heap corruption

## Root Cause

```cpp
// apfs_pool_compat.cpp:335-343
const auto pool = static_cast<APFSPoolCompat*>(pool_info->impl);
TSK_IMG_INFO *origInfo = pool->_members[0].first;

img_info->size = origInfo->size;
img_info->sector_size = origInfo->sector_size;
img_info->page_size = origInfo->page_size;
img_info->spare_size = origInfo->spare_size;

// BUG: origInfo->num_img and origInfo->images are not validated.
// If origInfo was created via malloc() (as in the fuzzer harness), they
// are uninitialized and may contain arbitrary values.
if (!tsk_img_copy_image_names(img_info, origInfo->images, origInfo->num_img)) {
```

`tsk_img_copy_image_names` at `img_open.cpp:676` then calls:
```c
if (!(img_info->images = (TSK_TCHAR**) tsk_malloc(num * sizeof(TSK_TCHAR*)))) {
```

With `num = 0xfffffffdf5f5f5f5` (garbage from uninitialized heap), this tries to
allocate ~16 EiB, crashing with ASAN's `allocation-size-too-big` or wrapping to a
small allocation with subsequent heap corruption.

## Proof of Concept

### Reproduction

```bash
docker run --rm --memory=2g \
  -v /scr2/yiwei/vul-agent/zero-day/sleuthkit/02-apfs-getimageinfo-uninit-alloc:/h \
  vulagent/sleuthkit:20260417 \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_apfs_fuzzer /h/apfs_minimal_valid.img"
```

### Sanitizer Output

```
==ERROR: AddressSanitizer: requested allocation size 0xfffffffdf5f5f5f0
(0xfffffffdf5f605f0 after adjustments for alignment, red zones etc.)
exceeds maximum supported size of 0x10000000000 (thread T0)
    #0 calloc  asan_malloc_linux.cpp:74
    #1 tsk_malloc  mymalloc.c:32
    #2 tsk_img_copy_image_names  img_open.cpp:676
    #3 APFSPoolCompat::getImageInfo  apfs_pool_compat.cpp:343
    #4 LLVMFuzzerTestOneInput  fls_apfs_fuzzer.cc:43

SUMMARY: AddressSanitizer: allocation-size-too-big mymalloc.c:32 in tsk_malloc
```

## Impact

- **Denial of Service**: Crash in any application using TSK to parse APFS pool images
  when `getImageInfo` is called (which is mandatory for reading volumes).
- **Potential heap corruption**: On platforms where `calloc` wraps integer overflow,
  the huge `num_img` value wraps to a small allocation; subsequent `memset` and string
  copies in `tsk_img_copy_image_names` then overflow the heap buffer.
- **Attack surface**: Any APFS image open triggers this path unconditionally.

## CWE

- CWE-456: Missing Initialization of a Variable
- CWE-190: Integer Overflow or Wraparound
- CWE-122: Heap-based Buffer Overflow (downstream effect)

## Suggested Fix

Validate `num_img` before copying image names:

```cpp
// In APFSPoolCompat::getImageInfo():
if (origInfo->num_img > 0 && origInfo->images != nullptr) {
    if (!tsk_img_copy_image_names(img_info, origInfo->images, origInfo->num_img)) {
        return nullptr;
    }
} else {
    img_info->num_img = 0;
    img_info->images = nullptr;
}
```

Also fix the fuzzer harness `mem_img.h` to zero-initialize the `IMG_MEM_INFO` struct:
```c
IMG_MEM_INFO *inmemory_img = reinterpret_cast<IMG_MEM_INFO*>(calloc(1, sizeof(IMG_MEM_INFO)));
```
