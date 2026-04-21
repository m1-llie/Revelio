# CPU and memory denial of service via oversized page and many text blocks

## Summary

The attached PDF combines two costly behaviors:

1. `SplashBitmap` allocates a full-page bitmap from oversized page dimensions.
2. `TextPage::coalesce()` performs expensive traversal over many isolated text blocks.

Together they produce a small-input denial of service with both high CPU time and high memory usage.

I reproduced this through poppler commit `e3d56a0e4b4a243ac9f4ab100325c95386f87521` and stable 26.04.0.

## Affected code path

- **Files:** `splash/SplashBitmap.cc`, `poppler/TextOutputDev.cc`

## Root cause

An oversized page causes disproportionate rendering allocation cost, while a large number of isolated text blocks amplifies the cost of text coalescing.

## Environment

- OS: Linux x86_64
- Source version: poppler commit `e3d56a0e4b4a243ac9f4ab100325c95386f87521`
- Reproduction target: `page_search_fuzzer` from a current poppler build

## Reproduction

The attached `poc.pdf` is about 347 KB and combines:

- a very tall page
- many isolated text objects

**Standard CLI:**
```bash
pdftotext poc.pdf /dev/null
```
Observe the wall-clock time (>20 s) for the ~347 KB input.

**With fuzzer target:**
```bash
page_search_fuzzer poc.pdf
```

## Observed output

Representative observed run:

```text
Executed /work/poc.pdf in 19867 ms
```

## Impact

- CWE-400: Uncontrolled Resource Consumption
- CVSS: 7.5 (High)
- A crafted PDF can keep a worker busy for roughly 20 seconds in the tested build.

## Suggested fix

Cap page dimensions before allocating large splash buffers, and add traversal or work limits to the text coalescing path so maliciously fragmented pages cannot induce quadratic behavior.
