# Integer Overflow in `nTiles_h()`/`nTiles_v()` Causes Empty Tile Offset Table and SIGSEGV

## Summary

A uint32_t integer overflow in `nTiles_h()` (and symmetrically `nTiles_v()`) causes the tiled image offset table to be initialized with zero entries. Any subsequent access to offset table entry 0 via `TiledHeader::is_tile_offset_known()` dereferences a null pointer in the empty `std::vector`, producing a SIGSEGV. The vulnerability is triggered by a maliciously crafted HEIF file containing a `tilC` (Tiled Image Configuration) property with `image_width=0xFFFFFFFE` and `tile_width=3`.

- **Affected file:** `libheif/image-items/tiled.cc`, `libheif/image-items/tiled.h`
- **Root-cause function:** `nTiles_h()` / `nTiles_v()`, `tiled.cc` lines 87–96
- **Crash function:** `TiledHeader::is_tile_offset_known()`, `tiled.h` line 118
- **Confirmed on version:** libheif 1.21.2
- **Impact:** Heap OOB (null-pointer read on empty std::vector internal buffer) → SIGSEGV; reachable via a malicious HEIF file

## Root Cause

`nTiles_h()` computes the number of horizontal tiles using a formula that performs intermediate arithmetic in `uint32_t`:

```cpp
// tiled.cc lines 87-90
uint32_t nTiles_h(const heif_tiled_image_parameters& params)
{
  return (params.image_width + params.tile_width - 1) / params.tile_width;
}
```

When `image_width = 0xFFFFFFFE` and `tile_width = 3`:

```
(0xFFFFFFFE + 3 - 1) = 0x100000000
```

But `params.image_width` and `params.tile_width` are both `uint32_t`, so the addition wraps:

```
0x100000000 & 0xFFFFFFFF = 0x00000000
```

Then `0 / 3 = 0`, so `nTiles_h()` returns **0**.

Consequently, in `TiledHeader::set_parameters()` (line 338):

```cpp
m_offsets.resize(*num_tiles_result);  // num_tiles_result = nTiles_h * nTiles_v = 0 * N = 0
```

`m_offsets` is resized to **zero entries** — an empty vector with a null internal data pointer.

## Crash Path

Any call that accesses `m_offsets[0]` after this initialization will crash. The directly exploitable path is via `heif_image_handle_get_luma_bits_per_pixel()`:

```
heif_image_handle_get_luma_bits_per_pixel()            [heif_image_handle.cc:105]
  -> ImageItem_Tiled::get_luma_bits_per_pixel()         [tiled.cc:1014]
     append_compressed_tile_data(m_raw, tx=0, ty=0)    [tiled.cc:1014]
       -> TiledHeader::is_tile_offset_known(idx=0)     [tiled.cc:888]
          -> m_offsets[idx]  <-- SIGSEGV               [tiled.h:118]
```

`ImageItem_Tiled::get_luma_bits_per_pixel()` calls `append_compressed_tile_data()` **directly without any bounds or error check**:

```cpp
// tiled.cc line 1013-1016
int ImageItem_Tiled::get_luma_bits_per_pixel() const
{
  DataExtent any_tile_extent;
  append_compressed_tile_data(any_tile_extent.m_raw, 0, 0); // TODO: use tile that is already loaded
```

And `is_tile_offset_known()` performs an unchecked vector element access:

```cpp
// tiled.h line 118
bool is_tile_offset_known(uint32_t idx) const { return m_offsets[idx].offset != TILD_OFFSET_NOT_LOADED; }
```

When `m_offsets` is empty, `m_offsets[0]` reads from the vector's null internal data pointer, producing SIGSEGV.

## Vulnerable Code

**Root-cause (nTiles_h overflow):**
```cpp
// libheif/image-items/tiled.cc, lines 87-90
uint32_t nTiles_h(const heif_tiled_image_parameters& params)
{
  return (params.image_width + params.tile_width - 1) / params.tile_width;
  //     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  //     uint32_t overflow when image_width + tile_width - 1 > 0xFFFFFFFF
}

// libheif/image-items/tiled.cc, lines 93-96
uint32_t nTiles_v(const heif_tiled_image_parameters& params)
{
  return (params.image_height + params.tile_height - 1) / params.tile_height;
  //     same overflow possible for height dimension
}
```

**Crash site (unchecked vector access):**
```cpp
// libheif/image-items/tiled.h, line 118
bool is_tile_offset_known(uint32_t idx) const { return m_offsets[idx].offset != TILD_OFFSET_NOT_LOADED; }
//                                                      ^^^^^^^^^^^^ no bounds check; crashes if m_offsets is empty
```

**Direct crash trigger (no guard before access):**
```cpp
// libheif/image-items/tiled.cc, lines 1013-1016
int ImageItem_Tiled::get_luma_bits_per_pixel() const
{
  DataExtent any_tile_extent;
  append_compressed_tile_data(any_tile_extent.m_raw, 0, 0); // calls is_tile_offset_known(0) directly
```

## Trigger

A 262-byte HEIF file with the following structure:

```
ftyp  brand='mif1'
meta
  hdlr  handler='pict'
  iinf
    infe  item_id=1, item_type='tili'
  iprp
    ipco
      ispe  image_width=0xFFFFFFFE (4294967294), image_height=4
      tilC  tile_width=3, tile_height=4, compression='hvc1'
            (version=0, flags=0x05: offset_field_length=40, size_field_length=24)
    ipma  item 1 -> properties 1 (ispe), 2 (tilC)
  pitm  item_id=1
  iloc  item 1 -> 16 bytes in mdat
mdat  <16 zero bytes>
```

Key trigger values:
- `image_width = 0xFFFFFFFE` (from `ispe` box, read by `initialize_decoder()`)
- `tile_width = 3` (from `tilC` box)
- `nTiles_h = (0xFFFFFFFE + 3 - 1) / 3 = 0x100000000 / 3` → uint32 wraps to `0 / 3 = 0`
- `m_offsets.resize(0)` — empty vector
- `compression = 'hvc1'` — needed so `initialize_decoder()` succeeds and the crash path is reached

**Note:** The item type must be `tili` (not `tild`), as `ImageItem::alloc_for_infe_box()` only allocates an `ImageItem_Tiled` for `item_type == fourcc("tili")`. The compression codec must be a known type (e.g., `hvc1`) so that `alloc_for_compression_format()` succeeds and `m_offsets.resize(0)` completes without error.

## ASAN Output

```
AddressSanitizer:DEADLYSIGNAL
=================================================================
==11==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7f4aa3d9c47f bp ... sp ...)
==11==The signal is caused by a READ memory access.
==11==Hint: address points to the zero page.
    #0 TiledHeader::is_tile_offset_known(unsigned int) const /src/libheif/libheif/image-items/tiled.h:118:80
    #1 ImageItem_Tiled::append_compressed_tile_data(...) /src/libheif/libheif/image-items/tiled.cc:888:22
    #2 ImageItem_Tiled::get_luma_bits_per_pixel() const /src/libheif/libheif/image-items/tiled.cc:1014:3
    #3 heif_image_handle_get_luma_bits_per_pixel /src/libheif/libheif/api/libheif/heif_image_handle.cc:105:25

SUMMARY: AddressSanitizer: SEGV .../tiled.h:118:80 in TiledHeader::is_tile_offset_known(unsigned int) const
```

## Additional Crash Paths

The same empty `m_offsets` vector can be triggered via multiple public API functions:

1. `heif_image_handle_get_luma_bits_per_pixel()` — **confirmed crash** (direct path, no guard)
2. `heif_image_handle_get_chroma_bits_per_pixel()` — same direct path via `get_chroma_bits_per_pixel()`
3. `heif_image_handle_decode_image_tile()` — reaches `append_compressed_tile_data()` when decoding a tile

## Impact

- **CWE:** CWE-190 (Integer Overflow or Wraparound), CWE-125 (Out-of-bounds Read)
- **Severity:** High — triggered by opening a maliciously crafted HEIF file, no user interaction beyond file open
- **Effect:** Denial of service (SIGSEGV / process crash); potential information disclosure (reading from address 0x0)
- **Attack surface:** Any application using libheif that queries image metadata (luma bits per pixel, chroma bits per pixel) or decodes tiles from a HEIF/AVIF file

## Suggested Fix

**Primary fix — add overflow check in `nTiles_h()` and `nTiles_v()`:**

```cpp
uint32_t nTiles_h(const heif_tiled_image_parameters& params)
{
  // Guard against uint32_t overflow in the addition
  if (params.tile_width == 0) return 0;  // defensive
  uint64_t sum = (uint64_t)params.image_width + params.tile_width - 1;
  if (sum > UINT32_MAX) {
    // Overflow: reject or clamp
    return 0;  // or return an error; tile count of 0 should be rejected upstream
  }
  return (uint32_t)(sum / params.tile_width);
}
```

**Secondary fix — reject zero tile count in `TiledHeader::set_parameters()`:**

```cpp
Error TiledHeader::set_parameters(const heif_tiled_image_parameters& params)
{
  m_parameters = params;
  Result<uint64_t> num_tiles_result = number_of_tiles(params, heif_get_global_security_limits());
  if (auto err = num_tiles_result.error()) { return err; }
  if (*num_tiles_result == 0) {
    return {heif_error_Invalid_input, heif_suberror_Unspecified,
            "Tiled image with zero tiles (possible integer overflow in image dimensions)"};
  }
  m_offsets.resize(*num_tiles_result);
  ...
```

**Tertiary fix — add bounds check in `is_tile_offset_known()` and `get_tile_size()`:**

```cpp
bool is_tile_offset_known(uint32_t idx) const {
  if (idx >= m_offsets.size()) return false;
  return m_offsets[idx].offset != TILD_OFFSET_NOT_LOADED;
}
```

## Reproduction

```bash
bash build.sh
```

Or manually:

```bash
# Generate the 262-byte POC
python3 gen_poc.py

# Confirm crash via ASAN harness (calls heif_image_handle_get_luma_bits_per_pixel)
docker run --rm \
  -v "$(pwd):/tmp/poc" \
  -v "/tmp/libheif-build:/tmp/libheif-build" \
  -e ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:symbolize=1" \
  vulagent/libheif:latest \
  bash -c "
    # compile crash harness, then run:
    # /tmp/crash_harness /tmp/poc/poc_input
  "
```
