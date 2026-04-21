# OOB Access in SampleAuxInfoReader Constructor via saiz/stco Sample Count Mismatch

- **CWE:** CWE-125 (Out-of-bounds Read), CWE-617 (Reachable Assertion)
- **CVSS 3.1:** 6.5 Medium (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)

## Summary

When parsing an ISOBMFF sequence file (moov/trak), libheif constructs a `SampleAuxInfoReader` object whose constructor iterates `nSamples` times (taken from the `saiz` box) while walking through a `chunks` vector whose size is determined by `stco`/`stsc`. If `saiz` declares more samples than the chunks actually cover, the loop increments `current_chunk` beyond `chunks.size()`, triggering an out-of-bounds assertion (debug builds) or heap OOB read (release/ASAN builds without assertions). In the ASAN fuzzer build, this fires as a fatal `SIGABRT` via `assert(current_chunk < chunks.size())` at `track.cc:141`.

- **Affected file:** `libheif/sequences/track.cc`
- **Crash function:** `SampleAuxInfoReader::SampleAuxInfoReader` — line 141
- **Root-cause function:** `Track::load` — line 447 (constructs the `SampleAuxInfoReader`)
- **Trigger:** `heif_context_read_from_memory()` with crafted HEIF file; crash happens during parsing, no further API calls needed
- **Confirmed on version:** libheif 1.21.2 (latest, 2026-04-17) and master commit `f20a88baec0f34825cc076b3dfb2578fb2d5728c` (2026-04-17)
- **POC:** `gen_poc.py` generates the crafted file; `poc_trigger.cc` is the minimal harness
- **Impact:** Denial of service (process abort / SIGABRT); potential heap OOB read in release builds lacking the assert, which could allow information disclosure.

## Root Cause

`SampleAuxInfoReader::SampleAuxInfoReader` (track.cc lines 117-151) takes:
- `saiz`: a `Box_saiz` whose `get_num_samples()` returns `nSamples`
- `saio`: a `Box_saio` with `get_num_chunks()` chunk offsets
- `chunks`: the track's chunk vector (size = `stco` chunk count)

When `oneChunk = false` (saio has multiple chunk entries), the constructor enters the loop:

```cpp
for (uint32_t i = 0; i < nSamples; i++) {
    if (!oneChunk && i > chunks[current_chunk]->last_sample_number()) {
        current_chunk++;
        assert(current_chunk < chunks.size());   // line 141
        offset = saio->get_chunk_offset(current_chunk);
    }
    ...
}
```

The loop walks `nSamples` iterations. Each time `i` exceeds the `last_sample_number()` of the current chunk, `current_chunk` is incremented. If `saiz` declares more samples than all chunks cover, `current_chunk` will reach `chunks.size()`, triggering the assert or an OOB access.

## Vulnerable Code

```cpp
// track.cc, lines 138-143
for (uint32_t i = 0; i < nSamples; i++) {   // nSamples from saiz (10 in PoC)
    if (!oneChunk && i > chunks[current_chunk]->last_sample_number()) {
        current_chunk++;
        assert(current_chunk < chunks.size()); // OOB when current_chunk == chunks.size()
        offset = saio->get_chunk_offset(current_chunk); // heap OOB in release builds
    }
    ...
}
```

The validation at track.cc:437-440 only checks that `saio.num_chunks == 1 OR saio.num_chunks == stco.num_chunks`. It does NOT verify that `saiz.num_samples <= total samples covered by stco/stsc`. This allows a crafted file to pass all guards and reach the unsafe loop.

## Trigger

Craft an ISOBMFF file with:
1. `ftyp` major brand `isom` (triggers sequence parsing path)
2. `moov/trak` with handler type `vide`
3. `stco`: 2 chunk offsets (2 chunks)
4. `stsc`: 2 entries, each mapping 1 chunk to 2 samples (4 total samples)
5. `stsz`: 4 samples (consistent with stsc/stts)
6. `stts`: 4 samples
7. `saio`: 2 offsets, aux_info_type=`suid` (matches stco, passes validation)
8. `saiz`: **10 samples**, aux_info_type=`suid`, non-constant per-sample sizes

Execution path:
- `SampleAuxInfoReader` constructor: `nSamples=10`, `chunks.size()=2`
- Chunk 0 covers samples 0-1 (`last_sample_number()=1`)
- Chunk 1 covers samples 2-3 (`last_sample_number()=3`)
- At `i=2`: `2 > 1` → `current_chunk=1` (OK)
- At `i=4`: `4 > 3` → `current_chunk=2` → `assert(2 < 2)` fires → SIGABRT

## Impact

- **CWE-125**: Out-of-Bounds Read (release build without assert)
- **CWE-617**: Reachable Assertion (debug/ASAN build)
- **Severity**: Medium-High. In release builds without the assert, reading
  `chunks[2]` (a `shared_ptr<Chunk>`) out-of-bounds accesses adjacent heap memory,
  potentially leaking pointer values or causing a segfault. Any application that
  parses untrusted HEIF/ISOBMFF sequence files is affected. The bug is reachable
  via the public `heif_context_read_from_memory` API.
- **Exploitability**: Reliable DoS; information disclosure requires additional heap layout control.

## Suggested Fix

Before constructing `SampleAuxInfoReader`, verify that `saiz.num_samples` does not exceed the total number of samples covered by the chunk vector. A simple guard in `Track::load` (track.cc, around line 447) would suffice:

```cpp
// Proposed check before constructing SampleAuxInfoReader
if (saiz->get_num_samples() > m_stsz->num_samples()) {
    return Error{heif_error_Invalid_input, heif_suberror_Unspecified,
                 "'saiz' declares more samples than 'stsz'"};
}
```

Alternatively, replace the bare `assert` in `SampleAuxInfoReader::SampleAuxInfoReader` with a proper bounds check that returns an error rather than aborting, making the library safe in both debug and release builds.

## Reproduction

### Files

| File | Purpose |
|------|---------|
| `gen_poc.py` | Generates the crafted HEIF file (`poc_input`) from scratch |
| `poc_input` | Pre-generated 694-byte HEIF file (output of `gen_poc.py`) |
| `poc_trigger.cc` | Minimal C++ harness using only public `heif_context_read_from_memory()` |
| `asan_output_validated.txt` | Captured crash output for reference |

### Step 1 — Generate the POC file

```bash
python3 gen_poc.py
# Writes poc_input (694 bytes)
# Structure: ftyp + moov/trak with stco(2 chunks), stsz(4 samples), saiz(10 samples)
```

The script constructs a valid-looking ISOBMFF file where `saiz` declares 10 samples but
`stco`/`stsc` only cover 4 samples across 2 chunks, creating the count mismatch.

### Step 2 — Build libheif with AddressSanitizer

```bash
git clone --depth=1 https://github.com/strukturag/libheif.git /tmp/libheif
mkdir /tmp/lhbuild && cd /tmp/lhbuild
cmake /tmp/libheif \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_INSTALL_PREFIX=/tmp/lhinstall \
    -DWITH_LIBDE265=OFF -DWITH_X265=OFF -DWITH_EXAMPLES=OFF
make -j$(nproc) install
```

### Step 3 — Compile and run the POC harness

```bash
clang++ -fsanitize=address -fno-omit-frame-pointer -g -O1 \
    poc_trigger.cc \
    -I/tmp/lhinstall/include \
    -L/tmp/lhinstall/lib -Wl,-rpath,/tmp/lhinstall/lib \
    -lheif -o poc_trigger

ASAN_OPTIONS="detect_leaks=0:print_stacktrace=1:symbolize=1" \
    ./poc_trigger poc_input
```

### Expected output

```
[+] Loaded 694 bytes from 'poc_input'
[+] Calling heif_context_read_from_memory() ...
[+] Crash expected in SampleAuxInfoReader::SampleAuxInfoReader()
    -> track.cc:141  assert(current_chunk < chunks.size())

libheif/sequences/track.cc:141: SampleAuxInfoReader::SampleAuxInfoReader(...):
    Assertion `current_chunk < chunks.size()' failed.

ERROR: AddressSanitizer: deadly signal
    #0  __sanitizer_print_stack_trace
    #1  SampleAuxInfoReader::SampleAuxInfoReader(...)
            /src/libheif/libheif/sequences/track.cc:141
    #2  Track::load(std::shared_ptr<Box_trak> const&)
            /src/libheif/libheif/sequences/track.cc:447
    #3  HeifContext::interpret_heif_file_sequences()
            /src/libheif/libheif/context.cc:1952
    #4  HeifContext::interpret_heif_file()
            /src/libheif/libheif/context.cc:512
    #5  HeifContext::read_from_memory(void const*, unsigned long, bool)
            /src/libheif/libheif/context.cc:225
    #6  heif_context_read_from_memory
            /src/libheif/libheif/api/libheif/heif_context.cc:67
    #7  main  poc_trigger.cc
```

Full captured output is in `asan_output_validated.txt`.

> **Note on release builds:** Without `assert()` (i.e., `-DNDEBUG` builds), the loop
> continues past `chunks.size()` and `chunks[current_chunk]` becomes a heap OOB READ
> on whatever memory follows the `m_chunks` vector allocation.
