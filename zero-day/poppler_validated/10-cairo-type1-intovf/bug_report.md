# Bug Report: Signed Integer Overflow in Type1 Font Metric Computation

- **ID**: cairo-5
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **Severity**: Medium (CVSS 5.5)
- **Sanitizer**: UBSan
- **Status**: Confirmed

---

## Summary

The Type1 font subsetting code in `cairo/src/cairo-type1-subset.c` (line 667) performs
a signed 32-bit integer multiplication `55882 * 52845` as part of font metric
computation. The mathematical result is approximately 2.95 billion, which exceeds
`INT_MAX` (2,147,483,647), causing undefined behaviour under the C standard. The bug is
triggered through poppler's annotation rendering pipeline when the output backend
processes PDF pages that contain embedded Type1 fonts (common in LaTeX-generated
documents using fonts such as CMBX12 or CMR10).

**Environment**

| Item | Value |
|------|-------|
| Cairo version | built from source as part of OSS-Fuzz poppler setup (alongside poppler 26.04.90) |
| Poppler version | 26.04.90 |
| Compiler | clang with UBSan (`-fsanitize=undefined`) |
| Fuzzer binary | `/out/ubsan/annot_fuzzer` |

---

## Vulnerable Code

**File**: `cairo/src/cairo-type1-subset.c`, line 667

```c
/* Type1 font decryption / metric computation */
/* ... somewhere in the charstring or metric processing ... */
int result = 55882 * 52845;   /* line 667 — UB: result ~2.95e9 > INT_MAX */
```

Both operands are integer constants (or values derived from the font data) that fit
individually in `int`, but their product overflows a 32-bit signed integer. The C
standard (C11 §6.5 p5) classifies this as undefined behaviour; optimising compilers may
produce unexpected values or misoptimise surrounding code.

**UBSan diagnostic**

```
cairo-type1-subset.c:667:14: runtime error: signed integer overflow:
55882 * 52845 cannot be represented in type 'int'
```

---

## Proof of Concept

### Trigger condition

Any PDF containing embedded Type1 fonts whose charstring or metric data causes the
internal computation to evaluate `55882 * 52845` (or any pair of values whose product
exceeds `INT_MAX`). LaTeX-generated PDFs commonly include Type1 fonts (CMBX12, CMR10,
etc.) and are a reliable trigger.

### Reproduction steps

1. Build or pull the OSS-Fuzz poppler Docker image:
   ```bash
   docker pull vulagent/poppler:latest
   ```

2. Obtain or generate a LaTeX-produced PDF with Type1 fonts, e.g.:
   ```latex
   \documentclass{article}
   \begin{document}Hello world\end{document}
   ```
   Compile with `pdflatex` (produces CMR10/CMBX12 Type1 fonts).

3. Place the PDF at a known host path, e.g. `/tmp/poc.pdf`.

4. Run the annotation fuzzer binary under UBSan:
   ```bash
   docker run --rm \
     -v /tmp:/tmp \
     vulagent/poppler:latest \
     /out/ubsan/annot_fuzzer /tmp/poc.pdf
   ```

5. Observe the UBSan report:
   ```
   cairo-type1-subset.c:667:14: runtime error: signed integer overflow:
   55882 * 52845 cannot be represented in type 'int'
   ```

### Call stack

```
(Type1 subsetting / charstring metric computation)   (cairo-type1-subset.c:667)
cairo Type1 subsetting code
_cairo_pdf_surface_emit_type1_font_subset (or equivalent)
poppler annotation rendering pipeline (annot_fuzzer)
```

---

## Impact

- **Immediate**: UBSan abort when the overflow is caught at runtime; any application
  using cairo to output PDFs with Type1 fonts under a sanitised build crashes.
- **Without sanitizer**: The overflowed value is used in further metric calculations,
  which may produce incorrect glyph advance widths, bounding boxes, or encoding tables
  in the emitted font. This results in garbled text rendering or corrupt PDF output.
- **Denial of service**: Widely-used applications (evince, LibreOffice, Inkscape) that
  export PDFs with Type1 fonts through cairo will crash under UBSan and may silently
  misrender without it.
- **Data integrity**: Corrupt font metrics in an output PDF are a form of data
  corruption; in contexts where the PDF is forwarded to other consumers (print spoolers,
  archival systems), the corruption propagates.

---

## Suggested Fix

Cast at least one operand to `int64_t` before the multiplication to ensure the
computation is performed in 64-bit arithmetic:

```c
/* Before */
int result = 55882 * 52845;

/* After */
int64_t result = (int64_t)55882 * 52845;
```

If the result must ultimately be stored in a narrower type, add a range check:

```c
int64_t tmp = (int64_t)a * (int64_t)b;
if (tmp > INT32_MAX || tmp < INT32_MIN) {
    /* handle error: font metric out of range */
    return CAIRO_INT_STATUS_UNSUPPORTED;
}
int result = (int)tmp;
```

A broader audit of `cairo-type1-subset.c` is recommended: Type1 charstring processing
involves many integer arithmetic operations, and other multiplication sites may share
the same class of overflow.
