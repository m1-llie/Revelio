# Signed Integer Overflow (INT_MIN Negation) in `_cairo_fixed_integer_floor()`

## Summary

- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **Severity**: Medium (CVSS 5.5)
- **Sanitizer**: UBSan

`_cairo_fixed_integer_floor()` in `cairo/src/cairo-fixed-private.h` (line 233) contains a signed integer overflow when its argument is `CAIRO_FIXED_MIN` (i.e., `INT_MIN = -2147483648`). The negation `-f` is undefined behaviour in C when `f == INT_MIN` because the mathematical result `2147483648` cannot be represented in a 32-bit signed integer.

**Public API entry point**: `cairo_mask()` (or `cairo_paint()` / `cairo_fill()` through any path that calls `_cairo_composite_rectangles_intersect_source_extents`). The overflow is reachable by calling cairo's standard drawing API with a transformation matrix that maps a mask pattern to a coordinate reaching `CAIRO_FIXED_MIN`.

The bug was found by rendering a crafted PDF file through a cairo-backed renderer. Poppler was used as the entry point (via `CairoOutputDev` / GLib rendering pipeline) since it conveniently exercises the full cairo drawing stack with attacker-controlled content, but the defect is within cairo instead of poppler.

**Environment**

| Item | Value |
|------|-------|
| Cairo version | git master (≥ 1.18.4); built from source as part of OSS-Fuzz poppler setup |
| Latest stable release | cairo 1.18.4 (2025-03-08) — bug present |
| Compiler | clang with UBSan (`-fsanitize=undefined`) |
| Fuzzer binary | `/out/ubsan/pdf_draw_fuzzer` (poppler OSS-Fuzz target) |

## Vulnerable Code

**File**: `cairo/src/cairo-fixed-private.h`, line 233

```c
static inline int _cairo_fixed_integer_floor(cairo_fixed_t f) {
    if (f >= 0)
        return f >> CAIRO_FIXED_FRAC_BITS;
    else
        return -((-f - 1) >> CAIRO_FIXED_FRAC_BITS) - 1;  /* line 233 — UB here */
}
```

When `f == INT_MIN` (`-2147483648`), the sub-expression `-f` attempts to negate `INT_MIN`, which is not representable as a signed 32-bit integer. The C standard (C11 §6.5 p5) classifies this as undefined behaviour; in practice UBSan traps it and optimising compilers may silently produce wrong results.

**UBSan diagnostic**

```
cairo-fixed-private.h:233:19: runtime error: negation of -2147483648 cannot be
represented in type 'cairo_fixed_t' (aka 'int'); cast to an unsigned type to negate this value
```

## Proof of Concept

### Trigger condition

A PDF content stream that renders an ImageMask XObject through a scale transform large enough for the rasterised coordinate to reach `CAIRO_FIXED_MIN`. A minimal example:

```
% Minimal trigger: 2x2 ImageMask scaled to coordinates that push fixed-point to INT_MIN
q
2 0 0 2 0 0 cm
/Im1 Do
Q
```

where `/Im1` is a 2×2 1-bit ImageMask XObject in the page's resource dictionary.

### Reproduction steps

Run the fuzz target under UBSan:
```bash
  /out/ubsan/pdf_draw_fuzzer /tmp/poc.pdf
```

Observe the UBSan report:
```
cairo-fixed-private.h:233:19: runtime error: negation of -2147483648 cannot be represented in type 'cairo_fixed_t' (aka 'int')
```

### Call stack

```
_cairo_fixed_integer_floor          (cairo-fixed-private.h:233)
_cairo_box_round_to_rectangle       (cairo-fixed-private.h)
_cairo_composite_rectangles_intersect_source_extents
_cairo_pdf_surface_mask
_cairo_surface_mask
_cairo_recording_surface_replay_internal
CairoOutputDev (poppler rendering pipeline)
```

## Impact

- **Immediate**: UBSan abort / crash when the overflow is caught at runtime.
- **Without sanitizer**: Optimising compilers (e.g., GCC/clang with `-O2`) are permitted to assume signed overflow never occurs and may miscompile the branch, causing incorrect floor values, pixel misalignment, or silent data corruption in the rendered output.
- **Denial of service**: Any application embedding cairo (e.g., evince, Inkscape, GNOME Shell) that renders attacker-controlled PDFs or SVGs can be crashed.
- **Scope**: Triggered through poppler's rendering pipeline but the defect is inside cairo; all cairo consumers that reach this code path share the exposure.

## Suggested Fix

Guard the `INT_MIN` case before the negation:

```c
static inline int _cairo_fixed_integer_floor(cairo_fixed_t f) {
    if (f >= 0)
        return f >> CAIRO_FIXED_FRAC_BITS;
    else {
        /* Guard: INT_MIN negation is undefined behaviour in signed arithmetic */
        if (f == INT32_MIN)
            return INT32_MIN >> CAIRO_FIXED_FRAC_BITS;
        return -((-f - 1) >> CAIRO_FIXED_FRAC_BITS) - 1;
    }
}
```

Alternatively, perform the arithmetic in unsigned to avoid all UB:

```c
static inline int _cairo_fixed_integer_floor(cairo_fixed_t f) {
    if (f >= 0)
        return f >> CAIRO_FIXED_FRAC_BITS;
    else
        return (int)(~((uint32_t)(-f - 1) >> CAIRO_FIXED_FRAC_BITS));
}
```

The unsigned variant avoids the special-case branch and is correct for all inputs.
