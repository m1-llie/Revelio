# [Security] UBSan: OOB Access via Empty Mapping Vector in `IDManifest::init` (Off-by-One in Bounds Check)

## Summary

In `IDManifest::init()`, a `mapping` vector is allocated with `stringList.size()`
elements. When `stringList` is empty (0 strings), `mapping` is also empty. A
manifest table entry with `tableSize ≥ 1` and `stringIndex = 0` passes the
off-by-one bounds check `size_t(stringIndex) > stringList.size()` (evaluates to
`0 > 0 = false`), but then accesses `mapping[0]` on an empty vector — a null
pointer dereference caught by UBSan.

```
stl_vector.h:1043: runtime error: reference binding to null pointer of type 'int'
```

- **Affected file:** `src/lib/OpenEXR/ImfIDManifest.cpp`
- **Affected function:** `IDManifest::init(const char*, const char*)`
- **Root cause:** `>` should be `>=` in the string index bounds check (line ~521)
- **Confirmed on commit:** `c13e0e1` (2026-04-16, OpenEXR main)
- **CWE:** CWE-125 (Out-of-Bounds Read), CWE-129 (Improper Validation of Array Index)

---

## Vulnerable Code

```cpp
// ImfIDManifest.cpp
vector<int> mapping (stringList.size ());   // size = 0 when stringList is empty
// ...
int stringIndex = readVariableLengthInteger (data, endOfData);
if (size_t (stringIndex) > stringList.size () ||   // ← BUG: should be >=
    stringIndex < 0)
{
    throw IEX_NAMESPACE::InputExc ("Bad string index in IDManifest");
}
// stringList is empty (size=0), stringIndex=0 passes the check:
// size_t(0) > 0 == false   → no throw
// mapping is also empty    → mapping[0] = null ptr deref!
(insertion.first)->second[i] = stringList[mapping[stringIndex]];
```

When `stringList.size() == 0`:
- `mapping` has 0 elements, its internal data pointer is `nullptr`.
- `stringIndex = 0` satisfies `0 > 0 → false`, so no exception is thrown.
- `mapping[0]` dereferences a null pointer → UBSan reports null-ptr deref.

---

## Proof of Concept

The attached `poc.bin` (68 bytes) is a minimal raw IDManifest payload containing:

- `numberOfStrings = 0` (empty string list)
- `rleLength = 0` (no mapping entries populated)
- One manifest entry with `tableSize = 1` and `stringIndex = 0`

### Build and Reproduce

```bash
# See build.sh for full details
bash build.sh
```

**Output:**

```
Parsing IDManifest binary: poc.bin (68 bytes)
/usr/lib/gcc/x86_64-linux-gnu/9/bits/stl_vector.h:1043:9: runtime error: \
    reference binding to null pointer of type 'int'
    #0 in std::vector<int>::operator[](unsigned long)  stl_vector.h:1043:2
    #1 in Imf_4_0::IDManifest::init(char const*, char const*)  ImfIDManifest.cpp
    #2 in Imf_4_0::IDManifest::IDManifest(char const*, char const*)  ImfIDManifest.cpp:306:5
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior stl_vector.h:1043:9
```

---

## Impact

In production builds (no UBSan):

- `mapping[0]` reads from address `nullptr + 0 * sizeof(int)` = address 0.
- On most platforms this is an immediate **SIGSEGV** (null page not mapped).
- An attacker triggering this via a malicious EXR file causes a **reliable crash**
  (denial of service).

Any EXR file with an `idmanifest` attribute having zero strings but a non-empty
table triggers this crash.

---

## Suggested Fix

Change `>` to `>=` in the string index bounds check:

```diff
-if (size_t (stringIndex) > stringList.size () ||
+if (size_t (stringIndex) >= stringList.size () ||
     stringIndex < 0)
 {
     throw IEX_NAMESPACE::InputExc ("Bad string index in IDManifest");
 }
```

This is the standard off-by-one fix: valid indices are `[0, size-1]`, so the
rejection condition should be `>= size`, not `> size`.

---

## Attachments

- `poc.bin` — 68-byte PoC raw IDManifest payload
- `harness.cpp` — minimal test harness calling `IDManifest(data, data+size)`
- `build.sh` — one-step build + run (Docker, clang + UBSan)
- `crash_output.txt` — UBSan output validated on commit c13e0e1
