# [Security] UBSan: Shift Exponent Overflow in `readVariableLengthInteger` (ImfIDManifest)

## Summary

`readVariableLengthInteger()` in `src/lib/OpenEXR/ImfIDManifest.cpp` decodes
variable-length integers from untrusted EXR input with no upper bound on the
shift counter. After 10 continuation bytes (0x80), `shift` reaches 70 and the
expression `(uint64_t(byte & 127)) << shift` invokes **undefined behavior** —
left-shift of a 64-bit value by ≥ 64 bits (C++14 §5.8/2).

UndefinedBehaviorSanitizer stops with:

```
ImfIDManifest.cpp:122:42: runtime error: shift exponent 70 is too large for 64-bit type 'uint64_t'
```

- **Affected file:** `src/lib/OpenEXR/ImfIDManifest.cpp`
- **Affected function:** `readVariableLengthInteger(const char*&, const char*)`
- **Confirmed on commit:** `c13e0e1` (2026-04-16, OpenEXR main)
- **CWE:** CWE-190 (Integer Overflow or Wraparound)

---

## Vulnerable Code

```cpp
// ImfIDManifest.cpp, line 104–127
uint64_t
readVariableLengthInteger (const char*& readPtr, const char* endPtr)
{
    int           shift = 0;
    unsigned char byte  = 0;
    uint64_t      value = 0;
    do
    {
        if (readPtr >= endPtr)
            throw IEX_NAMESPACE::InputExc ("IDManifest too small for variable length integer");

        byte = *(unsigned char*) readPtr++;
        value |= (uint64_t (byte & 127)) << shift;   // ← UB when shift >= 64
        shift += 7;
    } while (byte & 128);
    return value;
}
```

A valid `uint64_t` varint needs at most 10 bytes (9 × 7 = 63 bits; the 10th byte
contributes 1 bit). An attacker supplies ≥ 10 continuation bytes (`0x80`), driving
`shift` to 70. The left-shift by 70 on a 64-bit type is undefined behavior per the
C++ standard.

---

## Proof of Concept

The attached `poc.bin` (24 bytes) is a minimal raw IDManifest payload containing a
varint with 10 continuation bytes (0x80) followed by a final byte. Feed it to the
`IDManifest(const char*, const char*)` constructor.

### Build and Reproduce

```bash
# Requires Docker image with clang+UBSan and OpenEXR source at /src/openexr
# See build.sh for full setup
bash build.sh
```

**Output:**

```
Parsing IDManifest binary: poc.bin (24 bytes)
/src/openexr/src/lib/OpenEXR/ImfIDManifest.cpp:122:42: runtime error: \
    shift exponent 70 is too large for 64-bit type 'uint64_t' (aka 'unsigned long')
    #0 in readVariableLengthInteger(char const*&, char const*)  ImfIDManifest.cpp:122:42
    #1 in readStringList<...>(...)                              ImfIDManifest.cpp:177:22
    #2 in Imf_4_0::IDManifest::init(char const*, char const*)  ImfIDManifest.cpp:324:5
    #3 in Imf_4_0::IDManifest::IDManifest(char const*, char const*) ImfIDManifest.cpp:306:5
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ImfIDManifest.cpp:122:42
```

---

## Impact

In production builds (no UBSan), the undefined behavior is compiler-dependent:

- GCC / Clang at `-O0`: shift wraps silently, returning a corrupted `value`.
- At higher optimization levels the compiler may assume the shift is always valid
  and eliminate checks — potentially turning this into silent data corruption or
  memory misallocation downstream.

Any EXR file carrying an `idmanifest` attribute can trigger this path via the
`IDManifest` constructor, which is called during image reading.

---

## Suggested Fix

Add a shift-bound check inside the varint decode loop:

```diff
         byte = *(unsigned char*) readPtr++;
+        if (shift >= 64)
+            throw IEX_NAMESPACE::InputExc (
+                "IDManifest variable length integer too large");
         value |= (uint64_t (byte & 127)) << shift;
         shift += 7;
```

A valid `uint64_t` varint never exceeds 10 bytes; the check is reached only for
malformed input.

---

## Attachments

- `poc.bin` — 24-byte PoC raw IDManifest payload
- `harness.cpp` — minimal test harness calling `IDManifest(data, data+size)`
- `build.sh` — one-step build + run (Docker, clang + UBSan)
- `crash_output.txt` — UBSan output validated on commit c13e0e1
