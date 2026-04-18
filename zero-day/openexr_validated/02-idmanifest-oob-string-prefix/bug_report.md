# [Security] OOB Read: Missing Bounds Check Before 2-Byte Prefix Access in `IDManifest::init`

## Summary

In `IDManifest::init()`, the string list decompression phase reads either one or
two bytes from `stringList[i]` to determine a common prefix length. When the
previous string is longer than 255 characters, two bytes are read (`[0]` and `[1]`)
with **no check that `stringList[i]` is at least 2 bytes long**. If the current
string is empty (0 bytes), both accesses are out-of-bounds.

With `_GLIBCXX_DEBUG`, this immediately triggers:

```
basic_string::operator[]: Assertion '__pos <= size()' failed.
```

Without debug mode, the OOB read returns garbage from the SSO buffer, which is
then used as the prefix length — causing downstream heap misuse.

- **Affected file:** `src/lib/OpenEXR/ImfIDManifest.cpp`
- **Affected function:** `IDManifest::init(const char*, const char*)`
- **Lines:** 342–343 (two-byte read) and 347 (one-byte read; also missing empty check)
- **Confirmed on commit:** `c13e0e1` (2026-04-16, OpenEXR main)
- **CWE:** CWE-125 (Out-of-Bounds Read), CWE-119 (Buffer Mishandling)

---

## Vulnerable Code

```cpp
// ImfIDManifest.cpp, line 336–355
for (size_t i = 1; i < stringList.size (); ++i)
{
    size_t common;
    int    stringStart = 1;
    if (stringList[i - 1].size () > 255)
    {
        // BUG: no check that stringList[i].size() >= 2
        common = size_t (((unsigned char) (stringList[i][0])) << 8) +
                 size_t ((unsigned char) (stringList[i][1]));   // ← OOB when size < 2
        stringStart = 2;
    }
    else
    {
        // BUG: no check that stringList[i].size() >= 1
        common = (unsigned char) stringList[i][0];              // ← OOB when size == 0
    }
    ...
    stringList[i] = stringList[i - 1].substr (0, common) +
                    stringList[i].substr (stringStart);         // ← throws / corrupts with bad 'common'
}
```

An attacker supplies:
1. String 0 with 256+ bytes → triggers the 2-byte branch for string 1.
2. String 1 with 0 bytes → `stringList[1][0]` and `stringList[1][1]` are OOB.

---

## Proof of Concept

The attached `poc.bin` (267 bytes) is a minimal raw IDManifest payload with:

- `numberOfStrings = 2`
- String 0: 256 bytes (all `'A'`) — triggers 2-byte prefix path
- String 1: 0 bytes (empty) — causes OOB read

### Build and Reproduce

```bash
# See build.sh for full details
bash build.sh
```

**Mode 1 output (ASAN+UBSan, no GLIBCXX_DEBUG):**

```
Parsing IDManifest binary: poc.bin (267 bytes)
Exception: basic_string::substr: __pos (which is 2) > this->size() (which is 0)
```

The garbage value read from the empty string's SSO buffer was 2, which then caused
`stringList[1].substr(2)` to throw — proof that out-of-bounds bytes were used as
the prefix and `stringStart` values.

**Mode 2 output (_GLIBCXX_DEBUG assertion):**

```
Parsing IDManifest binary: poc.bin (267 bytes)
/usr/include/c++/9/bits/basic_string.h:1071:
    reference std::basic_string<char>::operator[](size_type):
    Assertion '__pos <= size()' failed.
Aborted (core dumped)
```

---

## Impact

- **Without debug mode:** garbage bytes from the SSO buffer are silently used as
  the common prefix length; `substr()` then either throws or returns garbled data,
  and the reconstructed string table becomes attacker-controlled garbage.
- **With `_GLIBCXX_DEBUG`:** immediate abort.
- **On non-SSO strings (long strings):** the OOB read goes into heap memory beyond
  the string allocation — potential information disclosure or segfault.

Any EXR file with an `idmanifest` attribute can trigger this via the `IDManifest`
constructor path during image reading.

---

## Suggested Fix

Add explicit size checks before each prefix read:

```diff
     if (stringList[i - 1].size () > 255)
     {
+        if (stringList[i].size () < 2)
+            throw IEX_NAMESPACE::InputExc (
+                "IDManifest string too short for 2-byte prefix");
         common = size_t (((unsigned char) (stringList[i][0])) << 8) +
                  size_t ((unsigned char) (stringList[i][1]));
         stringStart = 2;
     }
     else
     {
+        if (stringList[i].empty ())
+            throw IEX_NAMESPACE::InputExc (
+                "IDManifest string too short for 1-byte prefix");
         common = (unsigned char) stringList[i][0];
     }
```

---

## Attachments

- `poc.bin` — 267-byte PoC raw IDManifest payload (2 strings; second is empty)
- `harness.cpp` — minimal test harness calling `IDManifest(data, data+size)`
- `build.sh` — one-step build + run (Docker, clang + ASAN/UBSan + `_GLIBCXX_DEBUG`)
- `crash_output.txt` — both-mode crash output validated on commit c13e0e1
