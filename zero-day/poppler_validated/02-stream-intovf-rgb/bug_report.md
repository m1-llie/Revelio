# Signed Integer Overflow in `ImageStream::ImageStream()` for RGB Images (CWE-190)

## Summary

`ImageStream::ImageStream()` in `poppler/Stream.cc` computes `nVals = width * nComps`
at line 596 before the bounds check `width > INT_MAX / nComps` at line 598. For a PDF
image XObject with `/ColorSpace /DeviceRGB` (3 components) and `/Width 715827883`,
the multiplication `715827883 * 3` overflows `int` before the guard executes,
making the check permanently ineffective.

This is the same defect as `01-stream-intovf-cmyk`, triggered via RGB (3 components)
rather than CMYK (4 components). The fix is identical.

- **Affected file:** `poppler/Stream.cc`
- **Confirmed on commit:** `e3d56a0` (2026-04-04, poppler 26.04.90)
- **Crash site:** `Stream.cc:596` — `nVals = width * nComps`
- **Sanitizer:** UBSan
- **CWE:** CWE-190 (Integer Overflow or Wraparound)
- **CVSS:** 5.5 (Medium) — AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H

---

## Vulnerable Code

```cpp
// poppler/Stream.cc  (commit e3d56a0, line 594–600)
ImageStream::ImageStream(Stream *strA, int widthA, int nCompsA, int nBitsA)
{
    int nVals;

    nVals = width * nComps;           // line 596 — overflow HERE for RGB + large width

    if (width > INT_MAX / nComps) {   // line 598 — guard arrives TOO LATE; nVals already overflowed
        error(errSyntaxError, -1, "ImageStream: width * nComps >= INT_MAX");
        return;
    }
    ...
}
```

The bounds check at line 598 is never reached with a correct result because the
overflow already corrupts `nVals` at line 596.

---

## Proof of Concept

PoC file: `poc.pdf` (located in this directory).

The PDF contains an image XObject with:
- `/ColorSpace /DeviceRGB` (nComps = 3)
- `/Width 715827883`

`715827883 * 3 = 2147483649`, which exceeds `INT_MAX` (2147483647).

### Reproduction

```bash
docker run --rm \
  -v /scr2/yiwei/vul-agent/zero-day/poppler_validated/02-stream-intovf-rgb:/work \
  vulagent/poppler:latest \
  /out/ubsan/qt_pdf_fuzzer /work/poc.pdf
```

### Observed Output

```
poppler/Stream.cc:596:12: runtime error: signed integer overflow: 715827883 * 3 cannot be represented in type 'int'
```

### Call Stack

```
#0  ImageStream::ImageStream (Stream.cc:596)
#1  SplashOutputDev::drawImage (SplashOutputDev.cc:3207)
#2  Gfx::doImage (Gfx.cc:4664)
```

---

## Impact

Same as `01-stream-intovf-cmyk`. Signed integer overflow on the `nVals` computation
produces a negative or incorrectly small value. Downstream code uses `nVals` to size
buffer allocations and loop bounds, which can lead to:

- Under-allocation followed by out-of-bounds writes (heap corruption).
- Out-of-bounds reads when iterating pixel data.

Any PDF containing an RGB image XObject with `/Width` >= `ceil(INT_MAX / 3)` = 715827883
can trigger this path. The vulnerability is reachable without authentication whenever
poppler is used to render untrusted PDF files.

---

## Suggested Fix

Move the bounds check to before the multiplication (same fix resolves both this bug
and `01-stream-intovf-cmyk`):

```diff
 ImageStream::ImageStream(Stream *strA, int widthA, int nCompsA, int nBitsA)
 {
     int nVals;

+    if (widthA > INT_MAX / nCompsA) {
+        error(errSyntaxError, -1, "ImageStream: width * nComps >= INT_MAX");
+        return;
+    }
     nVals = widthA * nCompsA;
-
-    if (width > INT_MAX / nComps) {
-        error(errSyntaxError, -1, "ImageStream: width * nComps >= INT_MAX");
-        return;
-    }
     ...
 }
```
