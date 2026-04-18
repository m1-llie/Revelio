# Reporting Guide: libheif Validated Vulnerabilities

This guide covers how to responsibly disclose the 12 confirmed libheif bugs
to the project maintainers.

---

## Current Status of All Validated Bugs

Verified against: libheif **1.21.2** (latest release) and master commit
`f20a88baec0f34825cc076b3dfb2578fb2d5728c` (2026-04-17).

| # | Directory | Location | Type | Trigger | Status |
|---|-----------|----------|------|---------|--------|
| 01 | `01-track-oob-chunk-access` | `sequences/track.cc:1087` | Heap OOB read | Malicious HEIF file | **PRESENT** |
| 02 | `02-unci-empty-null-parameters` | `image-items/unc_image.cc:113` | NULL deref | API: `parameters=NULL` | **PRESENT** |
| 03 | `03-gimi-component-id-overflow` | `api/libheif/heif_uncompressed.cc:784` | Int overflow → heap OOB write | API: `component_idx=UINT32_MAX` | **PRESENT** |
| 04 | `04-saiz-sampleauxinfo-oob` | `sequences/track.cc:141` | Heap OOB read | Malicious HEIF file | **PRESENT** |
| 05 | `05-tild-ntiles-overflow` | `image-items/tiled.cc:87-96` | Int overflow → SIGSEGV | Malicious HEIF file | **PRESENT** |
| 06 | `06-track-null-iloc-deref` | `sequences/track.cc:478` | NULL deref | Malicious HEIF file | **PRESENT** |
| 07 | `07-track-api-oob-no-size` | `api/libheif/heif_sequences.cc:73,760` | Heap buffer overflow | API: undersized buffer | **PRESENT** |
| 08 | `08-track-release-double-free` | `api/libheif/heif_sequences.cc:57` | Double-free / UAF | API: double release | **PRESENT** |
| 09 | `09-context-api-null-data` | `bitstream.cc:83`, `context.cc:1796` | NULL deref | API: `data=NULL, size>0` | **PRESENT** |
| 10 | `10-context-api-negative-size` | `context.cc:~1790` | Signed→size_t wrap | API: `size=-1` | **PRESENT** |
| 11 | `11-metadata-invalid-compression-enum` | `context.cc:1728,1762,1767,1774,1783` | UB + type confusion | API: invalid enum | **PRESENT** |
| 12 | `12-snuc-memory-exhaustion` | `codecs/uncompressed/unc_boxes.cc:1323` | OOM bypass | Malicious HEIF file | **PRESENT** |

---

## Bug Summaries

### Group A — File-Parsing Bugs (highest severity; no user interaction beyond opening file)

#### Bug 01: OOB chunk vector access in `Track::get_next_sample_raw_data()`
**Folder:** `01-track-oob-chunk-access/`
- `init_sample_timing_table()` stores `chunkIdx = m_chunks.size()` (OOB) when `stco`
  has fewer chunks than `stsz` samples (`>` vs `>=` off-by-one). `get_next_sample_raw_data()`
  then reads `m_chunks[chunk_idx]` at that OOB index.
- **ASAN:** `heap-buffer-overflow READ` at `track.cc:1087`
- **Fix:** Change `if (current_chunk > m_chunks.size())` to `>=` at `track.cc:~1018`

#### Bug 04: OOB in `SampleAuxInfoReader` constructor via saiz/stco mismatch
**Folder:** `04-saiz-sampleauxinfo-oob/`
- `saiz` box declares more samples than `stco` chunks cover. Constructor iterates all
  `saiz` samples, incrementing `current_chunk` past `chunks.size()`. The `assert()` guard
  is debug-only; release builds access `chunks[current_chunk]` OOB.
- **ASAN:** assertion abort / OOB heap read at `track.cc:141`
- **Fix:** Replace `assert(current_chunk < chunks.size())` with a proper bounds check and error return

#### Bug 05: Integer overflow in `nTiles_h()`/`nTiles_v()` → empty tile offset table
**Folder:** `05-tild-ntiles-overflow/`
- `(image_width + tile_width - 1)` computed in `uint32_t`. With `image_width=0xFFFFFFFE,
  tile_width=3`, the sum wraps to 0 → `nTiles_h()` returns 0 → `m_offsets.resize(0)` →
  `is_tile_offset_known(0)` accesses `m_offsets[0]` on empty vector → SIGSEGV.
- **ASAN:** SEGV in `TiledHeader::is_tile_offset_known()` at `tiled.cc`
- **Fix:** Check `image_width + tile_width - 1` for overflow; reject zero tile count

#### Bug 06: NULL `iloc` pointer dereference in `Track::load()`
**Folder:** `06-track-null-iloc-deref/`
- When a `trak > meta` box contains an `infe` item of type `uri ` but no `iloc` child box,
  `get_child_box<Box_iloc>()` returns `nullptr`. This is not null-checked before
  `iloc->read_data(...)` at `track.cc:478`.
- **ASAN:** SEGV in `Box_iloc::read_data()`, called from `track.cc:478`
- **Fix:** Add `if (!iloc) { return Error{...}; }` after `get_child_box<Box_iloc>()`

#### Bug 12: Memory exhaustion in `Box_snuc::parse()` bypassing security limits
**Folder:** `12-snuc-memory-exhaustion/`
- `image_width=2, image_height=117,966,856` → 235M pixels, under the 1G-pixel limit.
  But `nuc_gains.resize(num_pixels)` and `nuc_offsets.resize(num_pixels)` each allocate
  ~944 MB via `std::vector`, bypassing `MemoryHandle` tracking. Total: ~1.88 GB from a
  61-byte input.
- **Fuzzer:** `libFuzzer: out-of-memory (malloc(943734848))`
- **Fix:** Register each resize through `MemoryHandle` before calling `resize()`; or cap
  `num_pixels` at a lower limit that accounts for double allocation

---

### Group B — C API Bugs (API contract violations; medium severity)

#### Bug 02: NULL `parameters` deref in `heif_context_add_empty_unci_image()`
**Folder:** `02-unci-empty-null-parameters/`
- Function validates `prototype` and `out_handle` but not `parameters`. Passed unguarded
  to `add_unci_item()` which dereferences `parameters->image_width` at `unc_image.cc:113`.
- **ASAN/UBSan:** `member access within null pointer` + SEGV at `unc_image.cc:113`
- **Fix:** Add `parameters == nullptr` to the existing null guard
- **Requirement:** `WITH_UNCOMPRESSED_CODEC=ON`

#### Bug 03: Integer overflow → heap OOB write in `heif_image_set_gimi_component_content_id()`
**Folder:** `03-gimi-component-id-overflow/`
- `component_idx + 1` overflows `uint32_t` to 0 when `component_idx = UINT32_MAX`.
  `ids.resize(0)` empties the vector; `ids[UINT32_MAX]` writes ~136 GiB past its base.
- **UBSan:** non-zero offset to null pointer; **ASAN:** SEGV at `heif_uncompressed.cc:784`
- **Fix:** Guard with `if (component_idx == UINT32_MAX) return;` or use 64-bit arithmetic
- **Requirement:** `WITH_UNCOMPRESSED_CODEC=ON`

#### Bug 07: Heap buffer overflow in track ID / reference type APIs (missing size param)
**Folder:** `07-track-api-oob-no-size/`
- `heif_context_get_track_ids()` and `heif_track_get_track_reference_types()` write all
  entries to the caller's array with no capacity/max_count parameter, overflowing if the
  buffer is smaller than the actual count.
- **ASAN:** `heap-buffer-overflow WRITE` in each function
- **Fix:** Add a `size_t max_count` parameter; truncate or return error if exceeded

#### Bug 08: Double-free / UAF in `heif_track_release()`
**Folder:** `08-track-release-double-free/`
- `heif_track_release()` is a bare `delete track` with no null guard. A second call
  destructs the already-freed object, causing the `shared_ptr<HeifContext>` destructor
  to read freed memory.
- **ASAN:** `heap-use-after-free READ size 8` in `shared_ptr` destructor
- **Fix:** Add `if (!track) return;` guard; document that callers must null their pointer

#### Bug 09: NULL data pointer not checked in metadata/read APIs
**Folder:** `09-context-api-null-data/`
- `heif_context_read_from_memory(ctx, NULL, size, ...)` and
  `heif_context_add_generic_metadata(ctx, item, NULL, size, ...)` pass the data pointer
  directly to `memcpy()` without null-checking, causing SEGV at address 0x0.
- **ASAN:** SEGV at `bitstream.cc:83` and `context.cc:1796`
- **Fix:** Add null check: `if (!data && size > 0) return heif_error_null_pointer_argument;`

#### Bug 10: Signed-to-`size_t` wrap in metadata size parameter
**Folder:** `10-context-api-negative-size/`
- `size` parameter is typed `int` in `heif_context_add_generic_metadata()`,
  `heif_context_add_XMP_metadata()`, and `heif_context_add_exif_metadata()`. Passing `-1`
  causes `data_array.resize((size_t)-1)` → `std::length_error` abort.
- **Runtime:** `std::length_error: vector::_M_default_append` → SIGABRT
- **Fix:** Validate `size >= 0` at API entry; or change parameter type to `size_t`

#### Bug 11: Undefined behavior via unvalidated `heif_metadata_compression` enum
**Folder:** `11-metadata-invalid-compression-enum/`
- `heif_context_add_XMP_metadata2()` accepts any integer cast to `heif_metadata_compression`
  with no range check. Out-of-range values (e.g., 99) trigger 8 UBSan errors across
  `context.cc` and cause type confusion: data is stored without a `content_encoding` header
  while the function returns `heif_error_Ok`.
- **UBSan:** `load of value 99, which is not a valid value for type 'heif_metadata_compression'`
- **Fix:** Validate the enum value against known constants before use

---

## Who Maintains libheif

**Dirk Farin** is the primary maintainer.

- **Email:** dirk.farin@gmail.com
- **GitHub:** https://github.com/strukturag/libheif

No `SECURITY.md` or dedicated security alias exists.

---

## Disclosure Channel

**Use GitHub Private Vulnerability Reporting (strongly preferred):**

> https://github.com/strukturag/libheif/security/advisories/new

This is the channel used for all past libheif CVEs. Dirk typically responds promptly.

**Alternative:** Email dirk.farin@gmail.com directly with the same content.

---

## Recommended Reporting Strategy

Report in **two batches** to keep issues focused:

### Batch 1 — File-parsing bugs (bugs 01, 04, 05, 06, 12)
These are exploitable by opening a malicious HEIF file with no other user interaction.
Higher CVSS scores; file attachments are compact binary files.

### Batch 2 — C API contract bugs (bugs 02, 03, 07, 08, 09, 10, 11)
Require direct API misuse. Include `build.sh` and `.cc` POCs for each.
Can be reported together in one advisory or as individual issues depending on maintainer preference.

---

## Advisory Template — Batch 1 (File-Parsing Bugs)

```
Title: Five memory-safety bugs in libheif triggered by malicious HEIF files

Hi Dirk,

I'm reporting five confirmed bugs in libheif 1.21.2 (also present on master
f20a88b, 2026-04-17) that can be triggered by opening a crafted HEIF file.
All are confirmed with AddressSanitizer and/or libFuzzer.

---

Bug 1: Heap OOB read in Track::get_next_sample_raw_data() [track.cc:1087]
  File:    libheif/sequences/track.cc, lines ~1018 (root cause) and 1087 (crash)
  Fix:     change `current_chunk > m_chunks.size()` to `>=`
  Trigger: HEIF sequence with stco chunk count < stsz sample count; read 3+ frames
  ASAN:    heap-buffer-overflow READ
  Folder:  01-track-oob-chunk-access/

Bug 2: OOB in SampleAuxInfoReader constructor via saiz/stco mismatch [track.cc:141]
  File:    libheif/sequences/track.cc, line 141
  Fix:     replace assert() with proper bounds check and error return
  Trigger: saiz sample_count > samples covered by stco chunks
  ASAN:    assertion/OOB heap read at track.cc:141
  Folder:  04-saiz-sampleauxinfo-oob/

Bug 3: Integer overflow in nTiles_h()/nTiles_v() → empty offset table [tiled.cc:87]
  File:    libheif/image-items/tiled.cc, lines 87-96
  Fix:     check overflow in nTiles_h/nTiles_v; reject zero tile count
  Trigger: tilC/tili item with image_width=0xFFFFFFFE, tile_width=3
  ASAN:    SEGV in TiledHeader::is_tile_offset_known() on empty m_offsets
  Folder:  05-tild-ntiles-overflow/

Bug 4: NULL iloc dereference in Track::load() [track.cc:478]
  File:    libheif/sequences/track.cc, line 478
  Fix:     add null check on iloc before use
  Trigger: trak > meta with infe(uri) item but no iloc child box
  ASAN:    SEGV in Box_iloc::read_data() called from track.cc:478
  Folder:  06-track-null-iloc-deref/

Bug 5: Memory exhaustion in Box_snuc::parse() bypassing security limits [unc_boxes.cc:1323]
  File:    libheif/codecs/uncompressed/unc_boxes.cc, lines 1323 and 1328
  Fix:     track both resize() calls through MemoryHandle; or lower per-field pixel limit
  Trigger: snuc box with image_width=2, image_height=117966856 (235M pixels, under 1G limit)
           but two vector::resize() calls together allocate ~1.88 GB
  Fuzzer:  libFuzzer: out-of-memory (malloc(943734848))
  Folder:  12-snuc-memory-exhaustion/

---

Attachments: per-bug report (.md), POC file, ASAN output, and build.sh for each.

Coordinated disclosure — please advise your preferred timeline.

[Your name / handle]
```

---

## Advisory Template — Batch 2 (C API Bugs)

```
Title: Seven C API memory-safety bugs in libheif (null checks, overflow, double-free)

Hi Dirk,

I'm reporting seven C API bugs in libheif 1.21.2 where functions crash or produce
undefined behavior when called with unexpected but plausible parameters. All confirmed
with ASAN/UBSan on master f20a88b (2026-04-17).

Bug 1: heif_context_add_empty_unci_image() — NULL parameters deref [unc_image.cc:113]
  Fix: add `parameters == nullptr` to existing null guard
  ASAN/UBSan: member access within null pointer
  Folder: 02-unci-empty-null-parameters/

Bug 2: heif_image_set_gimi_component_content_id() — uint32 overflow [heif_uncompressed.cc:784]
  Fix: guard component_idx == UINT32_MAX or use 64-bit arithmetic
  UBSan + ASAN: non-zero offset to null pointer + SEGV
  Folder: 03-gimi-component-id-overflow/

Bug 3: heif_context_get_track_ids() / heif_track_get_track_reference_types() — missing size param
  Fix: add max_count capacity parameter; truncate or error on overflow
  ASAN: heap-buffer-overflow WRITE in both functions
  Folder: 07-track-api-oob-no-size/

Bug 4: heif_track_release() — double-free / UAF
  Fix: add `if (!track) return;` guard
  ASAN: heap-use-after-free READ in shared_ptr destructor
  Folder: 08-track-release-double-free/

Bug 5: heif_context_read_from_memory() / heif_context_add_generic_metadata() — NULL data
  Fix: reject data=NULL when size>0 with heif_error_null_pointer_argument
  ASAN: SEGV on address 0x0 in memcpy path
  Folder: 09-context-api-null-data/

Bug 6: heif_context_add_generic_metadata() / add_XMP_metadata() — negative size wrap
  Fix: validate size >= 0 at entry or change type to size_t
  Runtime: std::length_error abort (size_t wraps to SIZE_MAX)
  Folder: 10-context-api-negative-size/

Bug 7: heif_context_add_XMP_metadata2() — unvalidated compression enum
  Fix: validate enum value against known constants before switch/branch
  UBSan: load of value N not valid for type 'heif_metadata_compression' (8 sites)
  Folder: 11-metadata-invalid-compression-enum/

---

Attachments: report (.md), poc_trigger.cc, sanitizer output, and build.sh for each.

[Your name / handle]
```

---

## CVSS 3.1 Estimates

| # | Bug | AV | AC | PR | UI | S | C | I | A | Score |
|---|-----|----|----|----|----|---|---|---|---|-------|
| 01 | Track OOB chunk access | N | L | N | R | U | L | N | H | **6.5 Medium** |
| 04 | SampleAuxInfoReader OOB | N | L | N | R | U | L | N | H | **6.5 Medium** |
| 05 | tild nTiles overflow | N | L | N | R | U | N | N | H | **6.5 Medium** |
| 06 | Track NULL iloc deref | N | L | N | R | U | N | N | H | **6.5 Medium** |
| 12 | snuc memory exhaustion | N | L | N | R | U | N | N | H | **6.5 Medium** |
| 02 | unci null parameters | L | L | N | N | U | N | N | H | **5.5 Medium** |
| 03 | GIMI component overflow | L | L | N | N | U | N | L | H | **6.1 Medium** |
| 07 | Track API OOB no size | L | L | N | N | U | N | L | H | **6.1 Medium** |
| 08 | Track release double-free | L | L | N | N | U | N | L | H | **6.1 Medium** |
| 09 | Context API null data | L | L | N | N | U | N | N | H | **5.5 Medium** |
| 10 | Context API negative size | L | L | N | N | U | N | N | H | **5.5 Medium** |
| 11 | Metadata invalid enum | L | L | N | N | U | N | L | L | **4.4 Medium** |

---

## CVE Assignment

After Dirk confirms and ships patches, request CVEs via the GitHub advisory
interface (GitHub is a CNA). Do **not** request before notification.

---

## Follow-Up Timeline

- No response after **7 days** → follow-up email to dirk.farin@gmail.com
- No response after **21 days** → oss-security post with 90-day disclosure notice
- Standard embargo: **90 days** from initial report date

---

## Do NOT Do

- Do **not** open a public GitHub issue — use the private advisory link.
- Do **not** request a CVE before the maintainer confirms.
- Do **not** post publicly before a fix is released.

---

## Directory Structure

```
libheif_validated/
├── REPORTING_GUIDE.md                           ← this file
├── gen_pocs.py                                  ← master POC generator/runner
│
│   ── File-parsing bugs (Group A) ──────────────────────────────────────────
├── 01-track-oob-chunk-access/                   ← report this
│   ├── 01-track-oob-chunk-access.md
│   ├── poc_input                                ← 683-byte HEIF sequence
│   ├── asan_output_validated.txt
│   └── build.sh
│
├── 04-saiz-sampleauxinfo-oob/                   ← report this
│   ├── 04-saiz-sampleauxinfo-oob.md
│   ├── poc_input                                ← 694-byte HEIF sequence
│   ├── gen_poc.py
│   ├── asan_output_validated.txt
│   └── build.sh
│
├── 05-tild-ntiles-overflow/                     ← report this
│   ├── 05-tild-ntiles-overflow.md
│   ├── poc_input                                ← 262-byte HEIF (tili item)
│   ├── gen_poc.py
│   ├── asan_output_validated.txt
│   └── build.sh
│
├── 06-track-null-iloc-deref/                    ← report this
│   ├── 06-track-null-iloc-deref.md
│   ├── poc_input                                ← 637-byte HEIF sequence
│   ├── gen_poc.py
│   ├── asan_output_validated.txt
│   └── build.sh
│
├── 12-snuc-memory-exhaustion/                   ← report this
│   ├── 12-snuc-memory-exhaustion.md
│   ├── poc_input                                ← 61-byte snuc box
│   ├── gen_poc.py
│   ├── fuzzer_output_validated.txt
│   └── build.sh
│
│   ── C API bugs (Group B) ──────────────────────────────────────────────────
├── 02-unci-empty-null-parameters/               ← report this
│   ├── 02-unci-empty-null-parameters.md
│   ├── poc_trigger.cc
│   ├── asan_output_validated.txt
│   └── build.sh
│
├── 03-gimi-component-id-overflow/               ← report this
│   ├── 03-gimi-component-id-overflow.md
│   ├── poc_trigger.cc
│   ├── asan_ubsan_output_validated.txt
│   └── build.sh
│
├── 07-track-api-oob-no-size/                    ← report this
│   ├── 07-track-api-oob-no-size.md
│   ├── poc_07_get_track_ids.cc
│   ├── poc_08_get_reference_types.cc
│   ├── poc07_10tracks.heif
│   ├── poc08_10reftypes.heif
│   ├── gen_heif.py
│   ├── asan_output_validated.txt
│   └── build.sh
│
├── 08-track-release-double-free/                ← report this
│   ├── 08-track-release-double-free.md
│   ├── poc_trigger.cc
│   ├── gen_heif.py
│   ├── asan_output_validated.txt
│   └── build.sh
│
├── 09-context-api-null-data/                    ← report this
│   ├── 09-context-api-null-data.md
│   ├── poc_read_from_memory.cc
│   ├── poc_add_metadata_null.cc
│   ├── asan_output_validated.txt
│   └── build.sh
│
├── 10-context-api-negative-size/                ← report this
│   ├── 10-context-api-negative-size.md
│   ├── poc_trigger.cc
│   ├── asan_output_validated.txt
│   └── build.sh
│
└── 11-metadata-invalid-compression-enum/        ← report this
    ├── 11-metadata-invalid-compression-enum.md
    ├── poc_trigger.cc
    ├── ubsan_output_validated.txt
    └── build.sh
```
