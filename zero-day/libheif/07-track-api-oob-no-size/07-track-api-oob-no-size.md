# Heap Buffer Overflow in Track ID/Reference APIs Due to Missing Size Parameter

> **Security Assessment: VALID** — ASAN `heap-buffer-overflow WRITE`; triggered via documented public APIs `heif_context_get_track_ids()` and `heif_track_get_track_reference_types()` with an attacker-controlled HEIF file. Recommend reporting.

## Summary

Two related functions in the libheif C API write unbounded arrays into caller-provided
buffers without any size/capacity parameter, allowing heap buffer overflow when the
caller's buffer is smaller than the actual data.

- **Affected functions:** `heif_context_get_track_ids()`, `heif_track_get_track_reference_types()`
- **Affected file:** `libheif/api/libheif/heif_sequences.cc`
- **CWE:** CWE-120 (Buffer Copy without Checking Size of Input), CWE-122 (Heap-Based Buffer Overflow)
- **CVSS 3.1:** 6.1 Medium (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H)
- **Confirmed on version:** libheif 1.21.2 (latest, 2026-04-17) and master commit `f20a88baec0f34825cc076b3dfb2578fb2d5728c` (2026-04-17)

Both bugs share the same root pattern: the API contract documents that the caller must
pre-allocate a buffer of the "correct" size using a separate query function, but the
write function enforces no such limit — making it trivially exploitable when a HEIF file
under attacker control contains more tracks or reference types than the caller anticipated.

## Root Cause

Neither function accepts a `max_count` / `capacity` parameter. They write every item in
the internal collection unconditionally, trusting that the caller's buffer is large enough.
An attacker who supplies a HEIF file with N > caller_buffer_size entries causes a linear
out-of-bounds write past the heap allocation.

**Bug 07 — `heif_context_get_track_ids()`** (`heif_sequences.cc:67`):

```
The passed array must have heif_context_number_of_sequence_tracks() entries.
```

The documentation advises calling `heif_context_number_of_sequence_tracks()` first and
sizing the buffer accordingly. Nothing stops a concurrent or logic bug from making those
two values disagree, and — more critically — there is no API-level enforcement.

**Bug 08 — `heif_track_get_track_reference_types()`** (`heif_sequences.cc:751`):

```
The passed array must have heif_track_get_number_of_track_reference_types() entries.
```

Same pattern.

## Vulnerable Code

### Bug 07 — `heif_context_get_track_ids()` (heif_sequences.cc:67-79)

```c
void heif_context_get_track_ids(const heif_context* ctx,
                                 uint32_t out_track_id_array[])
{
  std::vector<uint32_t> IDs;
  IDs = ctx->context->get_track_IDs();

  for (uint32_t id : IDs) {         // iterates ALL track IDs (no limit)
    *out_track_id_array++ = id;      // writes unconditionally — no bounds check
  }
}
```

Public API declaration (`heif_sequences.h:88`):
```c
LIBHEIF_API
void heif_context_get_track_ids(const heif_context* ctx,
                                 uint32_t out_track_id_array[]);
// No size/capacity parameter.
```

### Bug 08 — `heif_track_get_track_reference_types()` (heif_sequences.cc:751-762)

```c
void heif_track_get_track_reference_types(const heif_track* track,
                                          uint32_t out_reference_types[])
{
  auto tref = track->track->get_tref_box();
  if (!tref) {
    return;
  }

  auto refTypes = tref->get_reference_types();
  for (size_t i = 0; i < refTypes.size(); i++) {  // iterates ALL types (no limit)
    out_reference_types[i] = refTypes[i];           // writes unconditionally — no bounds check
  }
}
```

Public API declaration (`heif_sequences.h:616`):
```c
LIBHEIF_API
void heif_track_get_track_reference_types(const heif_track*,
                                          uint32_t out_reference_types[]);
// No size/capacity parameter.
```

## Trigger

### Bug 07: 10 tracks, 2-slot buffer

```c
// HEIF file has 10 tracks; caller allocates only 2 slots.
int real_count = heif_context_number_of_sequence_tracks(ctx);  // returns 10
uint32_t* small_buf = malloc(2 * sizeof(uint32_t));             // 8 bytes

// The loop inside runs 10 times, overwriting 8 uint32_t words past the end.
heif_context_get_track_ids(ctx, small_buf);   // OOB write at heif_sequences.cc:73
```

### Bug 08: 10 reference types, 1-slot buffer

```c
// HEIF track has 10 distinct tref types; caller allocates only 1 slot.
int n = heif_track_get_number_of_track_reference_types(src_track);  // returns 10
uint32_t* small_buf = malloc(1 * sizeof(uint32_t));                  // 4 bytes

// The loop inside runs 10 times, overwriting 9 uint32_t words past the end.
heif_track_get_track_reference_types(src_track, small_buf);  // OOB write at heif_sequences.cc:760
```

## ASAN Confirmation

Both bugs confirmed with AddressSanitizer on libheif 1.21.2 (clang 12, `-fsanitize=address,undefined`):

### Bug 07

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7b77778e11d8
WRITE of size 4 at 0x7b77778e11d8 thread T0
    #0 heif_context_get_track_ids
           /src/libheif/libheif/api/libheif/heif_sequences.cc:73:27
    #1 main /tmp/poc07.cc:83:5

0x7b77778e11d8 is located 0 bytes after 8-byte region [0x7b77778e11d0,0x7b77778e11d8)
allocated by thread T0 here:
    #0 malloc ...
    #1 main /tmp/poc07.cc:72:38
```

### Bug 08

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7b5c7c0e1654
WRITE of size 4 at 0x7b5c7c0e1654 thread T0
    #0 heif_track_get_track_reference_types
           /src/libheif/libheif/api/libheif/heif_sequences.cc:760:28
    #1 main /tmp/poc08.cc:117:5

0x7b5c7c0e1654 is located 0 bytes after 4-byte region [0x7b5c7c0e1650,0x7b5c7c0e1654)
allocated by thread T0 here:
    #0 malloc ...
    #1 main /tmp/poc08.cc:107:38
```

## Impact

- **CWE:** CWE-120 (Buffer Copy without Checking Size of Input), CWE-122 (Heap-Based Buffer Overflow)
- **CVSS 3.1:** 6.1 Medium (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H)
- **Severity:** Medium — API-level bug; exploitable when the library is used with untrusted
  HEIF files that control track count or tref reference type count
- **Effect:** Heap corruption past the caller's buffer on every write past the boundary.
  At minimum this causes a crash (denial of service). In optimistic attacker conditions
  (controlled file parsing, adjacent heap metadata), this is a potential arbitrary code
  execution primitive.
- **Attack vector:** Remote — a maliciously crafted `.heif` file delivered to any
  application that calls these APIs with a pre-sized buffer.

## Suggested Fix

Add a `size_t max_count` (or `size_t capacity`) parameter to both functions and truncate
writing at that limit, returning the actual count so callers can detect truncation:

```c
// Bug 07 fix proposal
LIBHEIF_API
size_t heif_context_get_track_ids(const heif_context* ctx,
                                   uint32_t out_track_id_array[],
                                   size_t max_ids);  // NEW parameter

// Bug 08 fix proposal
LIBHEIF_API
size_t heif_track_get_track_reference_types(const heif_track*,
                                             uint32_t out_reference_types[],
                                             size_t max_types);  // NEW parameter
```

Or, alternatively, change the return type to an error code and add an output-length
parameter so callers detect buffer-too-small conditions at the API boundary.

For backwards compatibility the existing functions could be deprecated in favour of new
`_n` variants (analogous to `strncpy` vs `strcpy`).

## Reproduction

```bash
# From this directory:
bash build.sh
```

`build.sh`:
1. Generates two minimal crafted HEIF files using `gen_heif.py` (pure Python, no dependencies).
2. Builds libheif 1.21.2 as a static library with `-fsanitize=address,undefined` inside
   the `vulagent/libheif:latest` Docker image.
3. Compiles `poc_07_get_track_ids.cc` and `poc_08_get_reference_types.cc` against it.
4. Runs both POCs; ASAN reports `heap-buffer-overflow` for each.

Full ASAN output is saved to `asan_output_validated.txt`.

## Files

| File | Description |
|------|-------------|
| `poc_07_get_track_ids.cc` | POC for Bug 07: reads 10-track HEIF, calls API with 2-slot buffer |
| `poc_08_get_reference_types.cc` | POC for Bug 08: reads 11-track HEIF (1 with 10 tref types), calls API with 1-slot buffer |
| `poc07_10tracks.heif` | Crafted HEIF: 10 metadata tracks (generated by gen_heif.py) |
| `poc08_10reftypes.heif` | Crafted HEIF: 11 tracks, source track has 10 distinct tref types |
| `gen_heif.py` | Python script that generates both HEIF test files from scratch |
| `build.sh` | End-to-end build and run script (Docker) |
| `asan_output_validated.txt` | Full ASAN output from confirmed run |
