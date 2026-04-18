# OOB Access in SampleAuxInfoReader Constructor via saiz/stco Sample Count Mismatch

## Summary

When parsing an ISOBMFF sequence file (moov/trak), libheif constructs a `SampleAuxInfoReader`
object whose constructor iterates `nSamples` times (taken from the `saiz` box) while walking
through a `chunks` vector whose size is determined by `stco`/`stsc`. If `saiz` declares more
samples than the chunks actually cover, the loop increments `current_chunk` beyond
`chunks.size()`, triggering an out-of-bounds assertion (debug builds) or heap OOB read
(release/ASAN builds without assertions). In the ASAN fuzzer build, this fires as a fatal
`SIGABRT` via `assert(current_chunk < chunks.size())` at `track.cc:141`.

- **Affected file:** `libheif/sequences/track.cc`
- **Crash function:** `SampleAuxInfoReader::SampleAuxInfoReader` — line 141
- **Root-cause function:** `Track::load` — line 447 (constructs the `SampleAuxInfoReader`)
- **Confirmed on version:** libheif 1.21.2 (latest, 2026-04-17)
- **Impact:** Denial of service (process abort / SIGABRT); potential heap OOB read in
  release builds lacking the assert, which could allow information disclosure.

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

The loop walks `nSamples` iterations. Each time `i` exceeds the `last_sample_number()` of the
current chunk, `current_chunk` is incremented. If `saiz` declares more samples than all chunks
cover, `current_chunk` will reach `chunks.size()`, triggering the assert or an OOB access.

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

The validation at track.cc:437-440 only checks that `saio.num_chunks == 1 OR
saio.num_chunks == stco.num_chunks`. It does NOT verify that `saiz.num_samples <=
total samples covered by stco/stsc`. This allows a crafted file to pass all guards and
reach the unsafe loop.

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
- **Exploitability**: Reliable DoS; information disclosure requires additional
  heap layout control.

## Suggested Fix

Before constructing `SampleAuxInfoReader`, verify that `saiz.num_samples` does not
exceed the total number of samples covered by the chunk vector. A simple guard in
`Track::load` (track.cc, around line 447) would suffice:

```cpp
// Proposed check before constructing SampleAuxInfoReader
if (saiz->get_num_samples() > m_stsz->num_samples()) {
    return Error{heif_error_Invalid_input, heif_suberror_Unspecified,
                 "'saiz' declares more samples than 'stsz'"};
}
```

Alternatively, replace the bare `assert` in `SampleAuxInfoReader::SampleAuxInfoReader`
with a proper bounds check that returns an error rather than aborting, making the
library safe in both debug and release builds.

## Reproduction

```bash
bash build.sh
```

Expected output: libFuzzer reports `deadly signal` with `SIGABRT` at
`SampleAuxInfoReader::SampleAuxInfoReader` (track.cc:141), confirming the assertion
`current_chunk < chunks.size()` fires.
