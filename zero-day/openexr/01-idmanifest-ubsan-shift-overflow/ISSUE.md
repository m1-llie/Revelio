# Shift exponent overflow in `readVariableLengthInteger()` (`ImfIDManifest.cpp`)

CWE-190: Integer Overflow or Wraparound

Severity: high

## Summary

`readVariableLengthInteger()` decodes a variable-length integer from untrusted EXR input without bounding the shift count. After enough continuation bytes, the code executes a left shift by 70 on a 64-bit value, which is undefined behavior.

I validated this on OpenEXR commit `c13e0e1320a6652e02c5c90c6dbd984d532efe44`, and latest release v3.4.10.

## Affected code path

- **File:** `src/lib/OpenEXR/ImfIDManifest.cpp`
- **Function:** `readVariableLengthInteger(const char*&, const char*)`
- **Crash line:** `ImfIDManifest.cpp:122`

## Root cause

The vulnerable expression is:

```cpp
value |= (uint64_t(byte & 127)) << shift;
```

`shift` is increased by 7 for every continuation byte, but the code never rejects values `>= 64`.


## Environment

- OS: Linux x86_64
- Compiler: `clang++`
- Sanitizer: UndefinedBehaviorSanitizer
- Reproduction setting: build current source with UBSan enabled, then compile `harness.cpp` in the attached zip file

## Reproduction

The attached `poc.bin` in the attached zip file triggers the parsing path, and `harness.cpp` constructs an `IDManifest` directly from the supplied bytes.

Build current OpenEXR source with `clang++` and UBSan enabled, then compile the attached `harness.cpp` together with `ImfIDManifest.cpp`, `IexBaseExc.cpp`, and
`IexThrowErrnoExc.cpp`:

```bash
clang++ -fsanitize=undefined -fno-sanitize-recover=all \
  -fno-omit-frame-pointer -g -O1 -std=c++14 \
  -I<generated-config-headers> \
  -I<src>/src/lib/OpenEXR -I<src>/src/lib/Iex -I<src>/src/lib/IlmThread \
  -I<src>/src/lib/OpenEXRCore \
  harness.cpp \
  <src>/src/lib/OpenEXR/ImfIDManifest.cpp \
  <src>/src/lib/Iex/IexBaseExc.cpp \
  <src>/src/lib/Iex/IexThrowErrnoExc.cpp \
  -o /tmp/idmanifest_harness

UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:print_stacktrace=1" \
  /tmp/idmanifest_harness poc.bin
```

## Observed output

```text
runtime error: shift exponent 70 is too large for 64-bit type 'uint64_t'
```

## Impact

- CWE-190: Integer Overflow or Wraparound
- A crafted EXR file containing an `idmanifest` attribute triggers undefined behavior in
  `readVariableLengthInteger()`.  The corrupted return value is immediately used as a
  **string-list length** (`numberOfStrings`) in `readStringList()`.  Depending on the
  compiler optimization level, UB on the left-shift can produce any value, including
  extremely large counts, causing `readStringList` to attempt reading far beyond the end
  of the supplied buffer — a potential **out-of-bounds read** in the parsing loop that
  follows.

## Suggested fix

Reject overlong encodings before shifting:

```cpp
if (shift >= 64)
    throw IEX_NAMESPACE::InputExc("Invalid variable-length integer");
```
