# Heap Buffer Overflow in `Track::get_next_sample_raw_data()` — OOB Chunk Vector Access

## Summary

`Track::init_sample_timing_table()` in `libheif/sequences/track.cc` stores an out-of-bounds chunk index (`m_chunks.size()`) into `m_presentation_timeline` when the number of chunks defined in the `stco` box is less than the number of samples in `stsz`. A subsequent call to `heif_track_get_next_raw_sequence_sample()` reads `m_chunks[chunk_idx]` with that OOB index, causing a **heap-buffer-overflow**.

- **Affected file:** `libheif/sequences/track.cc`
- **Crash function:** `Track::get_next_sample_raw_data()`, line 1087
- **Root-cause function:** `Track::init_sample_timing_table()`, line ~1018
- **Confirmed on version:** libheif 1.21.2 (latest release, 2025-01-16) and master commit `f20a88baec0f34825cc076b3dfb2578fb2d5728c` (2026-04-17)
- **CWE:** CWE-125 (Out-of-bounds Read)
- **CVSS 3.1:** 6.5 Medium (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **Impact:** Denial of service (crash); potential read of heap memory adjacent to the chunk vector


## Root Cause

`Track::load()` builds `m_chunks` by iterating over `stco` chunk offsets. It validates that each individual chunk's sample count does not exceed `stsz`, but never checks that the total samples assigned to chunks equals `stsz->num_samples()`.
If `stco` has fewer entries than needed, the remaining samples are left without a valid chunk.

`init_sample_timing_table()` then iterates over *all* `m_num_samples` and increments `current_chunk` whenever `i > m_chunks[current_chunk]->last_sample_number()`:

```cpp
// track.cc ~1010–1025
uint32_t current_chunk = 0;
for (uint32_t i = 0; i < m_num_samples; i++) {
    ...
    while (current_chunk < m_chunks.size() &&
           i > m_chunks[current_chunk]->last_sample_number()) {
        current_chunk++;           // ← can reach m_chunks.size()
        current_sample_in_chunk_idx = 0;

        if (current_chunk > m_chunks.size()) {   // ← BUG: should be >=
            timing.chunkIdx = 0;  // dead branch when current_chunk == size
        }
    }
    timing.chunkIdx = current_chunk;  // ← stores OOB index when current_chunk == size
    media_timeline.push_back(timing);
}
```

When `current_chunk` reaches `m_chunks.size()`, the `while` guard exits (because `current_chunk < m_chunks.size()` becomes false), the `>` vs `>=` error in the inner check leaves `timing.chunkIdx = m_chunks.size()` unhandled, and the OOB index is written to `m_presentation_timeline`.

Later, `get_next_sample_raw_data()` at line 1087 dereferences:

```cpp
const std::shared_ptr<Chunk>& chunk = m_chunks[chunk_idx];  // chunk_idx OOB
```

## Vulnerable Code

**`libheif/sequences/track.cc`, line 1015–1022:**
```cpp
while (current_chunk < m_chunks.size() &&
       i > m_chunks[current_chunk]->last_sample_number()) {
    current_chunk++;
    current_sample_in_chunk_idx = 0;

    if (current_chunk > m_chunks.size()) {   // ← should be >=
        timing.chunkIdx = 0;  // TODO: error
    }
}
timing.chunkIdx = current_chunk;             // ← OOB stored here
```

**`libheif/sequences/track.cc`, line 1087:**
```cpp
const std::shared_ptr<Chunk>& chunk = m_chunks[chunk_idx];  // heap-buffer-overflow
```


## Proof of Concept

Attached file `poc_input` is a minimal 625-byte ISO BMFF HEIC sequence with:
- `stsz`: 5 fixed-size samples
- `stts`: 5 samples at δ=100
- `stsc`: 1 sample per chunk (for all chunks)
- `stco`: only **2** chunk offsets → only 2 `Chunk` objects are created

Samples 2–4 have `chunkIdx = 2 = m_chunks.size()`. The OOB read fires on the third call to `heif_track_get_next_raw_sequence_sample()`.

### Build and run

```bash
# 1. Build libheif 1.21.2 with ASAN
cd libheif && git checkout v1.21.2
mkdir build && cd build
CC=clang CXX=clang++ cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" \
    -DWITH_LIBDE265=OFF -DWITH_X265=OFF -DWITH_EXAMPLES=OFF
make -j$(nproc) install DESTDIR=/tmp/heif_inst

# 2. Compile the driver
clang -fsanitize=address -fno-omit-frame-pointer -g -O1 \
    -I/tmp/heif_inst/usr/local/include \
    build.c \
    -L/tmp/heif_inst/usr/local/lib -Wl,-rpath,/tmp/heif_inst/usr/local/lib \
    -lheif -o seq_driver

# 3. Run
ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" \
    ./seq_driver poc_input
```

### Observed output of ASAN

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... at pc 0x...
READ of size 8 at 0x... thread T0
    #0 ... std::__shared_ptr<Chunk...>::get() const
    #1 ... Track::get_next_sample_raw_data(...)
           /src/libheif/libheif/sequences/track.cc:1087:23
    #2 ... heif_track_get_next_raw_sequence_sample
           /src/libheif/libheif/api/libheif/heif_sequences.cc:266:32
    ...
0x... is located 0 bytes after 32-byte region [0x..., 0x...)
allocated by thread T0 here:
    #0 ... Track::load(...) /src/libheif/libheif/sequences/track.cc:402:14
    ...
SUMMARY: AddressSanitizer: heap-buffer-overflow
    /src/libheif/libheif/sequences/track.cc:1087:23
    in Track::get_next_sample_raw_data(heif_decoding_options const*)
```

## Impact

- **CWE:** CWE-125 (Out-of-bounds Read)
- **CVSS 3.1:** 6.5 Medium (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)

Any application that:
1. Opens an attacker-controlled HEIC sequence file via `heif_context_read_from_memory` or `heif_context_read_from_file`, and
2. Calls `heif_track_get_next_raw_sequence_sample()` to iterate frames

is vulnerable. The OOB read crashes the process (DoS) and may allow reading heap memory adjacent to the chunk vector, depending on heap layout.


## Suggested Fix

Two changes are needed:

**Fix 1 — `Track::load()`:** After the stco loop, verify that all samples have been
assigned to chunks:
```cpp
if (current_sample_idx < m_stsz->num_samples()) {
    return {heif_error_Invalid_input, heif_suberror_Unspecified,
            "Not all samples in 'stsz' are covered by 'stco' and 'stsc' entries."};
}
```

**Fix 2 — `init_sample_timing_table()`:** Change `>` to `>=` in the guard, and
return an error instead of silently storing OOB:
```cpp
if (current_chunk >= m_chunks.size()) {
    return {heif_error_Invalid_input, heif_suberror_Unspecified,
            "Chunk index out of range during sample timing table construction."};
}
```
