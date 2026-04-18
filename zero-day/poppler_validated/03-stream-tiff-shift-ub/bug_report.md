# Shift Exponent Overflow in TIFF Predictor Bit Accumulation (CWE-682)

## Summary

`StreamPredictor::getNextLine()` in `poppler/Stream.cc` uses `if (outBits >= 8)`
at line 899 to drain accumulated bits into the output buffer. Because `if` only
drains once per outer loop iteration, `outBits` can accumulate across iterations
when `BitsPerComponent` (nBits) >= 9. When `outBits` reaches or exceeds 64,
the shift expression `outBuf >> (outBits - 8)` at line 900 becomes a shift of
a 64-bit type by an exponent >= 64, which is undefined behavior in C++.

- **Affected file:** `poppler/Stream.cc`
- **Confirmed on commit:** `e3d56a0` (2026-04-04, poppler 26.04.90)
- **Crash site:** `Stream.cc:900` — `outBuf >> (outBits - 8)`
- **Sanitizer:** UBSan
- **CWE:** CWE-682 (Incorrect Calculation)
- **CVSS:** 5.5 (Medium) — AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H
- **Related bug:** `04-stream-tiff-neg-shift` (same root cause, same fix)

---

## Vulnerable Code

```cpp
// poppler/Stream.cc  (commit e3d56a0, line 895–910, simplified)
// Inside StreamPredictor::getNextLine(), TIFF predictor path:

for (int i = 0; i < pixBytes; ++i) {
    // Accumulate bits from inBuf into outBuf
    outBuf = (outBuf << nBits) | sampleVal;
    outBits += nBits;

    if (outBits >= 8) {                                          // line 899 — should be 'while'
        predLine[k++] = static_cast<unsigned char>(
            outBuf >> (outBits - 8));                            // line 900 — UB when outBits >= 64
        outBits -= 8;
    }

    ...

    if (outBits > 0) {                                           // line 905
        predLine[k++] = static_cast<unsigned char>(
            (outBuf << (8 - outBits)) +                         // line 906
            (inBuf & ((1 << (8 - outBits)) - 1)));
    }
}
```

Using `if` instead of `while` at line 899 means that when `nBits >= 9`, a single
loop iteration adds more than 8 bits to `outBits`, but only 8 are removed. Over
multiple iterations `outBits` grows unboundedly. When `outBits - 8 >= 64`, the
right-shift at line 900 is undefined behavior.

---

## Proof of Concept

Three PoC files are included in this directory, each exercising a different
`BitsPerComponent` value:

| File             | /BitsPerComponent | UBSan shift exponent |
|------------------|:-----------------:|:--------------------:|
| `poc_nBits12.pdf`| 12                | 64                   |
| `poc_nBits11.pdf`| 11                | 66                   |
| `poc_nBits9.pdf` | 9                 | (negative, see bug 4)|

Each PDF contains a stream with:
```
/Filter /FlateDecode
/DecodeParms << /Predictor 2 /BitsPerComponent N /Colors 1 /Columns 10 >>
```

### Reproduction

```bash
# nBits = 12 (shift exponent 64)
docker run --rm \
  -v /scr2/yiwei/vul-agent/zero-day/poppler_validated/03-stream-tiff-shift-ub:/work \
  vulagent/poppler:latest \
  /out/ubsan/pdf_draw_fuzzer /work/poc_nBits12.pdf

# nBits = 11 (shift exponent 66)
docker run --rm \
  -v /scr2/yiwei/vul-agent/zero-day/poppler_validated/03-stream-tiff-shift-ub:/work \
  vulagent/poppler:latest \
  /out/ubsan/pdf_draw_fuzzer /work/poc_nBits11.pdf
```

### Observed Output

**nBits = 12:**
```
poppler/Stream.cc:900:75: runtime error: shift exponent 64 is too large for 64-bit type 'unsigned long'
```

**nBits = 11:**
```
poppler/Stream.cc:900:75: runtime error: shift exponent 66 is too large for 64-bit type 'unsigned long'
```

---

## Impact

The undefined behavior from an out-of-range shift produces unpredictable results
that vary by compiler and optimization level. Observed effects include:

- Incorrect pixel data written to `predLine`, causing downstream heap operations
  to work on corrupted data.
- Potential crash or memory corruption when `predLine` bounds are exceeded.

Any PDF using `/Predictor 2` (TIFF predictor) with `/BitsPerComponent` in the
range 9–15 can trigger this path.

---

## Suggested Fix

Replace `if (outBits >= 8)` with `while (outBits >= 8)` to fully drain all
accumulated bits each iteration before proceeding:

```diff
-    if (outBits >= 8) {
+    while (outBits >= 8) {
         predLine[k++] = static_cast<unsigned char>(outBuf >> (outBits - 8));
         outBits -= 8;
     }
```

This ensures `outBits` never exceeds `nBits - 1` after the drain loop, making
the shift exponent always well-defined. The same change also fixes the negative
shift described in `04-stream-tiff-neg-shift`.
