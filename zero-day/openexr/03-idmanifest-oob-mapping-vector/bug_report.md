# Crash: null pointer dereference in `IDManifest::init` via empty string list (off-by-one in bounds check)

## Summary

`IDManifest::init()` allocates `mapping` with `stringList.size()` elements. When `stringList` is empty, `mapping` is also empty (internal data pointer is `nullptr`). The bounds check uses `>` instead of `>=`, so `stringIndex = 0` passes the check (`0 > 0 == false`) and then dereferences `mapping[0]` — a null pointer.

Any EXR file with an `idmanifest` attribute carrying zero strings but a non-empty table triggers a reliable SIGSEGV in production builds.

- **File:** `src/lib/OpenEXR/ImfIDManifest.cpp`
- **Function:** `IDManifest::init(const char*, const char*)`
- **Confirmed on:** commit `c13e0e1` (2026-04-16, main), and latest release v3.4.10

## Root Cause

```cpp
vector<int> mapping (stringList.size ());        // size = 0 → data() == nullptr

int stringIndex = readVariableLengthInteger (data, endOfData);
if (size_t (stringIndex) > stringList.size () || // BUG: > should be >=
    stringIndex < 0)
    throw IEX_NAMESPACE::InputExc ("Bad string index in IDManifest");

// stringIndex=0, stringList.size()=0 → 0 > 0 is false → no throw
// mapping[0] dereferences nullptr → SIGSEGV
(insertion.first)->second[i] = stringList[mapping[stringIndex]];
```

## Reproducer

`poc.bin` (68 bytes): `numberOfStrings = 0`, `rleLength = 0`, one table entry with `tableSize = 1` and `stringIndex = 0`.

```cpp
IDManifest manifest(data.data(), data.data() + size);  // crashes here
```

**UBSan output:**

```
stl_vector.h:1043:9: runtime error: reference binding to null pointer of type 'int'
    #0  std::vector<int>::operator[](unsigned long)        stl_vector.h:1043
    #1  Imf_4_0::IDManifest::init(char const*, char const*)  ImfIDManifest.cpp
    #2  Imf_4_0::IDManifest::IDManifest(char const*, char const*)  ImfIDManifest.cpp:306
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior stl_vector.h:1043:9
```

## Fix

```diff
-if (size_t (stringIndex) > stringList.size () ||
+if (size_t (stringIndex) >= stringList.size () ||
     stringIndex < 0)
```

Valid indices are `[0, size-1]`; the rejection condition must be `>= size`.