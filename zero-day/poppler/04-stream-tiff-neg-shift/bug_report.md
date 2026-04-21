# Negative Shift Exponent in TIFF Predictor Final Byte Flush

## Summary

`StreamPredictor::getNextLine()` in `poppler/Stream.cc` contains a final flush block at line 905–907 that writes the remaining bits in `outBuf` after the main per-pixel loop. When the `if (outBits >= 8)` guard at line 899 is used instead of `while`, `outBits` can accumulate to a value greater than 8 by the time the final flush executes. The expression `(8 - outBits)` at line 906 then becomes negative, and using a negative value as a shift exponent is undefined behavior.

This bug shares the same root cause as `03-stream-tiff-shift-ub` and is fixed by the same one-line change.

- **Affected file:** `poppler/Stream.cc`
- **Confirmed on commit:** `e3d56a0` (2026-04-04, poppler 26.04.90 dev; also affects stable 26.04.0)
- **Crash site:** `Stream.cc:906` — `outBuf << (8 - outBits)` and `(1 << (8 - outBits))`
- **Sanitizer:** UBSan
- **CWE:** CWE-682 (Incorrect Calculation)
- **CVSS:** 5.5 (Medium) — AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H

## Vulnerable Code

```cpp
// poppler/Stream.cc  (commit e3d56a0, lines 895–910, simplified)
// Inside StreamPredictor::getNextLine(), TIFF predictor path:

for (int i = 0; i < pixBytes; ++i) {
    outBuf = (outBuf << nBits) | sampleVal;
    outBits += nBits;

    if (outBits >= 8) {          // line 899 — 'if' instead of 'while' allows outBits > 8
        predLine[k++] = static_cast<unsigned char>(outBuf >> (outBits - 8));
        outBits -= 8;
    }
}

// Final flush — assumes outBits <= 8, but that invariant is broken by the 'if' above
if (outBits > 0) {                                              // line 905
    predLine[k++] = static_cast<unsigned char>(
        (outBuf << (8 - outBits)) +                            // line 906 — UB: negative shift when outBits > 8
        (inBuf & ((1 << (8 - outBits)) - 1)));                 // line 906 — UB: negative shift when outBits > 8
}
```

When `nBits = 9` and enough pixels are processed, `outBits` can be 22 (for example) when the final flush is reached. `8 - 22 = -14` is then used as a shift exponent, which is undefined behavior in C++.


## Proof of Concept

PoC file: `poc.pdf`.

The PDF contains a stream with:
```
/Filter /FlateDecode
/DecodeParms << /Predictor 2 /Colors 3 /BitsPerComponent 9 /Columns 10 >>
```

### Reproduction

**Standard CLI:**
```bash
pdftoppm poc.pdf /dev/null
```

**With UBSan (definitive confirmation):**
I reused the fuzz target from oss-fuzz as a program entry point.

```bash
  /out/ubsan/pdf_draw_fuzzer /work/poc.pdf
```

### Observed Output

```
poppler/Stream.cc:906:68: runtime error: shift exponent -22 is negative
```


## Impact

A negative shift exponent is undefined behavior. Compilers may generate code that produces arbitrary results, crashes, or silently corrupts the `predLine` buffer. Corrupted predictor output feeds directly into image rendering, potentially enabling further memory safety issues downstream.

Any PDF using `/Predictor 2` with `/BitsPerComponent 9` (or higher, combined with multi-channel `/Colors`) and enough `/Columns` to trigger the accumulation can reach this path.

## Suggested Fix

The fix is identical to `03-stream-tiff-shift-ub`. Replace `if (outBits >= 8)` with `while (outBits >= 8)` at line 899:

```diff
-    if (outBits >= 8) {
+    while (outBits >= 8) {
         predLine[k++] = static_cast<unsigned char>(outBuf >> (outBits - 8));
         outBits -= 8;
     }
```

After this change, `outBits` is always < 8 when the final flush block is reached, making `(8 - outBits)` always a non-negative value in [0, 7].