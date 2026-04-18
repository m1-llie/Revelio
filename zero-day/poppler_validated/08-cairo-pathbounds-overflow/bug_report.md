# Bug Report: Signed Integer Overflow in `_cairo_path_fixed_approximate_stroke_extents()` for Extreme Bezier Coordinates

- **ID**: cairo-3
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **Severity**: Medium (CVSS 5.5)
- **Sanitizer**: UBSan
- **Status**: Confirmed

---

## Summary

`_cairo_path_fixed_approximate_stroke_extents()` in `cairo/src/cairo-path-bounds.c`
(line 180) expands a path bounding box by the stroke width using signed `cairo_fixed_t`
arithmetic. When path coordinates are already near `INT_MAX` in cairo's 24.8
fixed-point representation and the stroke width adds a further increment, the addition
overflows a 32-bit signed integer, producing undefined behaviour. The bug is triggered
through poppler's `CairoOutputDev::stroke` when rendering a PDF Bezier curve with
extreme control-point coordinates.

**Environment**

| Item | Value |
|------|-------|
| Cairo version | built from source as part of OSS-Fuzz poppler setup (alongside poppler 26.04.90) |
| Poppler version | 26.04.90 |
| Compiler | clang with UBSan (`-fsanitize=undefined`) |
| Fuzzer binary | `/out/ubsan/pdf_draw_fuzzer` |

---

## Vulnerable Code

**File**: `cairo/src/cairo-path-bounds.c`, line 180

```c
/* approximate stroke extents — expand bounding box by stroke width */
box_extents.p2.x += _cairo_fixed_from_double(dx);   /* line 180 — UB here */
```

`box_extents.p2.x` is a `cairo_fixed_t` (`int32_t`). When the path bounding box already
has `p2.x` near `INT_MAX` (due to extreme Bezier control-point coordinates) and
`_cairo_fixed_from_double(dx)` produces a positive fixed-point value for the stroke
half-width, the in-place addition overflows.

**UBSan diagnostic**

```
cairo-path-bounds.c:180:19: runtime error: signed integer overflow:
2147483391 + 3620 cannot be represented in type 'cairo_fixed_t' (aka 'int')
```

---

## Proof of Concept

### Trigger condition

A PDF content stream with a cubic Bezier curve whose control points push the bounding
box to near `INT_MAX` in fixed-point. Any non-zero line width then causes the overflow
when expanding the bounding box.

```
% Minimal trigger: cubic Bezier with extreme coordinates
2147483647 0 m
0 0 -2147483648 0 0 0 c
S
```

The default line width (1 user-space unit) is sufficient; the stroke-width expansion
adds a few fixed-point units that overflow `INT_MAX`.

### Reproduction steps

1. Build or pull the OSS-Fuzz poppler Docker image:
   ```bash
   docker pull vulagent/poppler:latest
   ```

2. Place the proof-of-concept PDF at a known host path, e.g. `/tmp/poc.pdf`.

3. Run the fuzzer binary under UBSan:
   ```bash
   docker run --rm \
     -v /tmp:/tmp \
     vulagent/poppler:latest \
     /out/ubsan/pdf_draw_fuzzer /tmp/poc.pdf
   ```

4. Observe the UBSan report:
   ```
   cairo-path-bounds.c:180:19: runtime error: signed integer overflow:
   2147483391 + 3620 cannot be represented in type 'cairo_fixed_t' (aka 'int')
   ```

### Call stack

```
_cairo_path_fixed_approximate_stroke_extents   (cairo-path-bounds.c:180)
_cairo_composite_rectangles_init_for_stroke
_cairo_recording_surface_stroke
CairoOutputDev::stroke                         (poppler rendering pipeline)
```

---

## Impact

- **Immediate**: UBSan abort when the overflow is caught at runtime.
- **Without sanitizer**: The computed stroke bounding box becomes incorrectly small
  (wraps to a large negative value), causing strokes to be incorrectly culled as
  entirely outside the clip region. Visible rendering artefacts (missing strokes) result.
- **Denial of service**: Applications rendering attacker-controlled PDFs through cairo
  crash due to the UBSan trap.
- **Silent misrendering**: Without UBSan the bug silently produces wrong output rather
  than a crash, making it harder to detect and potentially security-relevant in
  applications that rely on rendering fidelity (e.g., PDF signature validation displays).

---

## Suggested Fix

Use saturating arithmetic when expanding the bounding box by the stroke width. A small
helper or inline clamp is sufficient:

```c
/* Saturating add for cairo_fixed_t */
static inline cairo_fixed_t
_cairo_fixed_add_saturate(cairo_fixed_t a, cairo_fixed_t b)
{
    int64_t result = (int64_t)a + (int64_t)b;
    if (result > INT32_MAX) return INT32_MAX;
    if (result < INT32_MIN) return INT32_MIN;
    return (cairo_fixed_t)result;
}
```

Apply it at the affected sites in `_cairo_path_fixed_approximate_stroke_extents()`:

```c
box_extents.p2.x = _cairo_fixed_add_saturate(box_extents.p2.x,
                                              _cairo_fixed_from_double(dx));
box_extents.p2.y = _cairo_fixed_add_saturate(box_extents.p2.y,
                                              _cairo_fixed_from_double(dy));
box_extents.p1.x = _cairo_fixed_add_saturate(box_extents.p1.x,
                                             -_cairo_fixed_from_double(dx));
box_extents.p1.y = _cairo_fixed_add_saturate(box_extents.p1.y,
                                             -_cairo_fixed_from_double(dy));
```

Saturating at `INT_MAX`/`INT_MIN` is semantically correct: a bounding box coordinate
clamped at the extreme means "extends to the edge of the fixed-point space", which is
conservative and safe for culling decisions.
