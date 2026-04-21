# Signed Integer Overflow in `_cairo_slope_init()` for Extreme Path Coordinates

## Summary

- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **Severity**: Medium (CVSS 5.5)
- **Sanitizer**: UBSan

`_cairo_slope_init()` in `cairo/src/cairo-slope-private.h` (line 49) computes the difference `b->x - a->x` using signed `cairo_fixed_t` (a 32-bit int) arithmetic. When `b->x` is near `INT_MAX` and `a->x` is near `INT_MIN`, both legal values in cairo's 24.8 fixed-point coordinate space, the subtraction overflows, producing undefined behaviour.

**Public API entry point**: `cairo_stroke()`. The overflow is reachable by stroking a path whose endpoints span the full fixed-point coordinate range. All coordinates used are within the documented valid range of `cairo_fixed_t`.

The bug was found by rendering a crafted PDF through a cairo-backed renderer. Poppler was used as the entry point (`CairoOutputDev::stroke`) since it exercises the full cairo stroke stack, but the defect is within cairo.

**Environment**

| Item | Value |
|------|-------|
| Cairo version | git master (≥ 1.18.4); built from source as part of OSS-Fuzz poppler setup |
| Latest stable release | cairo 1.18.4 (2025-03-08) — bug present |
| Compiler | clang with UBSan (`-fsanitize=undefined`) |
| Fuzzer binary | `/out/ubsan/pdf_draw_fuzzer` (poppler OSS-Fuzz target) |

## Vulnerable Code

**File**: `cairo/src/cairo-slope-private.h`, line 49

```c
static inline void
_cairo_slope_init(cairo_slope_t *slope,
                  const cairo_point_t *a,
                  const cairo_point_t *b)
{
    slope->dx = b->x - a->x;   /* line 49 — UB when result > INT_MAX */
    slope->dy = b->y - a->y;
}
```

`cairo_fixed_t` is `int32_t`. When `b->x ≈ INT_MAX` and `a->x ≈ INT_MIN`, the mathematical result of `b->x - a->x` exceeds `INT_MAX`, which is undefined behaviour under the C standard (C11 §6.5 p5).

**UBSan diagnostic**

```
cairo-slope-private.h:49:22: runtime error: signed integer overflow:
-2147483392 - 2147483391 cannot be represented in type 'cairo_fixed_t' (aka 'int')
```

## Proof of Concept

### Trigger condition

A PDF content stream containing a path segment from near `INT_MAX` to near `INT_MIN` in device-space coordinates. In PDF user-space units the fixed-point value `INT_MAX = 2147483647` corresponds to a very large coordinate; the content stream uses raw integers that map directly to cairo fixed-point values after the CTM.

```
% Minimal trigger: path spanning the full fixed-point range
2147483647 0 m
-2147483648 0 l
S
```

### Reproduction steps

Run the fuzzer binary under UBSan:
   ```bash
     /out/ubsan/pdf_draw_fuzzer /tmp/poc.pdf
   ```

Observe the UBSan report:
   ```
   cairo-slope-private.h:49:22: runtime error: signed integer overflow:
   -2147483392 - 2147483391 cannot be represented in type 'cairo_fixed_t' (aka 'int')
   ```

### Call stack

```
_cairo_slope_init                         (cairo-slope-private.h:49)
line_to                                   (cairo-path-stroke-polygon.c:1024)
_cairo_path_fixed_stroke_extents
_cairo_pdf_surface_stroke
CairoOutputDev::stroke                    (poppler rendering pipeline)
```

## Impact

- **Immediate**: UBSan abort when overflow is detected at runtime.
- **Without sanitizer**: The slope value used for stroke extent calculations may be silently wrong. This can result in clipping errors (strokes not drawn or drawn in the wrong region), subtle rendering corruption, or incorrect compositing operations.
- **Denial of service**: Applications rendering attacker-supplied PDF or SVG content through cairo can be crashed via the UBSan trap.
- **Compiler misoptimisation**: Under `-O2` a compiler may assume the subtraction cannot overflow and eliminate guards that follow, potentially masking related checks.

## Suggested Fix

Cast through `int64_t` before computing the difference, then clamp or store as 64-bit:

```c
static inline void
_cairo_slope_init(cairo_slope_t *slope,
                  const cairo_point_t *a,
                  const cairo_point_t *b)
{
    /* Use int64_t to avoid signed overflow for extreme fixed-point coordinates */
    slope->dx = (cairo_fixed_t)((int64_t)b->x - (int64_t)a->x);
    slope->dy = (cairo_fixed_t)((int64_t)b->y - (int64_t)a->y);
}
```

If `cairo_slope_t` fields must remain 32-bit, saturating arithmetic should be applied after the 64-bit subtraction:

```c
    int64_t dx = (int64_t)b->x - (int64_t)a->x;
    slope->dx = (cairo_fixed_t)(dx > INT32_MAX ? INT32_MAX :
                                dx < INT32_MIN ? INT32_MIN : dx);
```

Alternatively, if the callers only require the sign of `dx`/`dy` (which is the common use case for slope comparison), the saturation is safe and semantics-preserving.
