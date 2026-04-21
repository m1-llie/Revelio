# Out-of-bounds read in `IDManifest::init()` during prefix expansion

CWE-125: Out-of-Bounds Read

Severity: High

## Summary

`IDManifest::init()` reconstructs strings from a prefix-compressed representation. If the previous string is longer than 255 bytes, the next string is expected to begin with a 2-byte prefix length. The code reads `stringList[i][0]` and `stringList[i][1]` without checking that the current string has at least two bytes.

I validated this on OpenEXR commit `c13e0e1320a6652e02c5c90c6dbd984d532efe44`, and latest release v3.4.10.

## Affected code path

- **File:** `src/lib/OpenEXR/ImfIDManifest.cpp`
- **Function:** `IDManifest::init(const char*, const char*)`
- **Affected lines:** `342-343` and `346-347`

## Root cause

The vulnerable logic is:

```cpp
common = size_t(((unsigned char)(stringList[i][0])) << 8) +
         size_t((unsigned char)(stringList[i][1]));
```

If `stringList[i]` is empty, both subscripts are out of bounds.

## Environment

- OS: Linux x86_64
- Compiler: `clang++`
- Sanitizers: AddressSanitizer + UndefinedBehaviorSanitizer
- Reproduction setting: build current source with ASan/UBSan enabled, then compile `harness.cpp` in the attached zip file

## Reproduction

`poc.bin` in the attached zip file contains two strings:

1. a first string longer than 255 bytes, forcing the 2-byte prefix path, and
2. an empty second string.

The attached `harness.cpp` constructs an `IDManifest` from the supplied bytes.

Build the latest OpenEXR source with `clang++` and ASan/UBSan enabled, then compile the attached `harness.cpp` together with `ImfIDManifest.cpp`, `IexBaseExc.cpp`, and `IexThrowErrnoExc.cpp`:

```bash
clang++ -fsanitize=address,undefined -fno-sanitize-recover=all \
  -fno-omit-frame-pointer -g -O1 -std=c++14 \
  -I<generated-config-headers> \
  -I<src>/src/lib/OpenEXR -I<src>/src/lib/Iex -I<src>/src/lib/IlmThread \
  -I<src>/src/lib/OpenEXRCore \
  harness.cpp \
  <src>/src/lib/OpenEXR/ImfIDManifest.cpp \
  <src>/src/lib/Iex/IexBaseExc.cpp \
  <src>/src/lib/Iex/IexThrowErrnoExc.cpp \
  -o /tmp/idmanifest_harness

ASAN_OPTIONS="detect_leaks=0:print_stacktrace=1" \
UBSAN_OPTIONS="print_stacktrace=1" \
  /tmp/idmanifest_harness poc.bin
```

## Observed output

Without `_GLIBCXX_DEBUG`:

```text
Exception: basic_string::substr: __pos (which is 2) > this->size() (which is 0)
```

With `_GLIBCXX_DEBUG`:

```text
Assertion '__pos <= size()' failed
```

## Impact

- CWE-125: Out-of-Bounds Read

**In debug / instrumented builds** the C++ standard library intercepts the access and raises an exception or assertion before the byte is actually read.

**In production builds** (no ASan, no `_GLIBCXX_DEBUG`, optimized): `std::string::operator[]` performs no bounds check.  An empty `std::string` allocates exactly 1 byte for the NUL terminator. The access `stringList[i][1]` therefore reads **1 byte past the end of the heap-allocated string buffer** — a real, hardware-level out-of-bounds heap read.

The byte read from `stringList[i][1]` is then used directly as the low byte of the `common` prefix length, which controls a subsequent `substr` call and string reconstruction loop.  An attacker who controls adjacent heap layout can influence this value to:

1. **Leak heap memory** — the derived `common` length directs the string reconstruction to copy bytes from a neighboring heap object into the parsed `IDManifest`.
2. **Crash the process** — if the derived length exceeds the previous string's length, the downstream `substr` call throws `std::out_of_range` (reliable denial of service when opening a malicious `.exr` file).

## Suggested fix

Validate the string length before reading the 1-byte or 2-byte prefix.


[poc-2.zip](https://drive.google.com/file/d/1VT6elUVa253Lq9Bis4Ah38wETVouhOgW/view?usp=drive_link)