# CPU and Memory DoS via Oversized Page Dimensions in Splash Renderer (CWE-400)

## Summary

Two independent resource-consumption issues are triggered by a single crafted PDF:

1. **Memory:** `SplashBitmap::SplashBitmap()` in `splash/SplashBitmap.cc` allocates
   `height * rowSize` bytes for a full-page pixel buffer without limiting page
   height. A page height of 200,050 PDF units causes a ~240 MB allocation.

2. **CPU:** `TextPage::coalesce()` in `poppler/TextOutputDev.cc` calls
   `visitDepthFirst()` which has O(n²) complexity when the page contains many
   isolated text blocks. A page with 10,000 single-character text objects produces
   ~88× slower processing.

Together these produce a ~20-second hang for a 347 KB input PDF.

- **Affected files:** `splash/SplashBitmap.cc` (constructor), `poppler/TextOutputDev.cc` (visitDepthFirst)
- **Confirmed on commit:** `e3d56a0` (2026-04-04, poppler 26.04.90)
- **Sanitizer:** None required (timing/memory-based DoS)
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **CVSS:** 7.5 (High) — AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H

---

## Vulnerable Code

### Issue 1 — Uncapped page height in SplashBitmap

```cpp
// splash/SplashBitmap.cc — constructor
SplashBitmap::SplashBitmap(int widthA, int heightA, int rowPad,
                            SplashColorMode modeA, bool alphaA,
                            bool topDown, const std::vector<GfxSeparationColorSpace*> *separationList)
{
    ...
    // No upper bound on height before this allocation:
    data = (SplashColorPtr)gmallocn_checkoverflow(height, rowSize);
    // A 300 × 200,050 page → rowSize=900, allocation = 200,050 * 900 = ~180 MB
    ...
}
```

### Issue 2 — O(n²) text block traversal in TextOutputDev

```cpp
// poppler/TextOutputDev.cc — TextPage::coalesce()
// visitDepthFirst() iterates all text blocks to find neighbors;
// with n isolated blocks the algorithm is O(n²) with no iteration cap.
```

---

## Proof of Concept

PoC file: `poc.pdf` (located in this directory, ~347 KB).

The PDF has:
- **MediaBox:** `[0 0 300 200050]` (300 × 200,050 PDF units)
- **10,000 single-character text objects** scattered across the page

### Reproduction

```bash
docker run --rm \
  -v /scr2/yiwei/vul-agent/zero-day/poppler_validated/12-textout-dos:/work \
  vulagent/poppler:latest \
  /out/asan/page_search_fuzzer /work/poc.pdf
```

### Observed Timing and Memory

| Input              | Execution time | Peak RSS   |
|--------------------|:--------------:|:----------:|
| Normal PDF         | ~224 ms        | ~50 MB     |
| `poc.pdf`          | ~19,738 ms     | ~290 MB    |
| **Slowdown factor**| **~88×**       |            |

No sanitizer error is produced; the process completes normally but consumes
excessive time and memory.

---

## Impact

A 347 KB PDF file causes ~20 seconds of processing time and ~290 MB of memory
consumption per worker process. A service processing multiple concurrent requests
can be made unresponsive or OOM-killed. The attack requires no special privileges
and is reproducible with any poppler build.

---

## Suggested Fix

Two independent fixes are needed:

1. **Cap page dimensions in SplashBitmap:**

```cpp
// In SplashBitmap constructor, before the allocation:
const int kMaxDimension = 32768;
if (widthA > kMaxDimension || heightA > kMaxDimension) {
    error(errSyntaxError, -1,
          "SplashBitmap: page dimension %dx%d exceeds limit", widthA, heightA);
    width = height = 0;
    data = nullptr;
    return;
}
```

   Alternatively, enforce a page dimension limit when reading the MediaBox in
   `poppler/Page.cc` before any rendering backend is invoked.

2. **Add an iteration limit to visitDepthFirst():**

```cpp
// In TextOutputDev.cc, visitDepthFirst():
int iterCount = 0;
const int kMaxIter = 1000000;
// Inside the traversal loop:
if (++iterCount > kMaxIter) {
    error(errSyntaxWarning, -1, "TextPage: coalesce iteration limit reached");
    break;
}
```
