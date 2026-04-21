# CPU denial of service via oversized inline image dimensions

## Summary

The inline-image parser accepts `/W` and `/H` values without bounding them against the actual inline image payload. A tiny PDF can therefore claim extremely large dimensions and force poppler to spend tens of seconds processing a non-existent image.

I reproduced this through poppler commit `e3d56a0e4b4a243ac9f4ab100325c95386f87521` (2026-04-04, dev post-26.04.0) and stable 26.04.0 (2026-04-01).

## Affected code path

- **Area:** `poppler/Gfx.cc` inline image handling (`BI` / `ID` / `EI`)

## Root cause

The parser trusts declared inline image dimensions and performs work proportional to those values even when the image payload is much smaller.

## Environment

- OS: Linux x86_64
- Source version: poppler commit `e3d56a0e4b4a243ac9f4ab100325c95386f87521`
- Reproduction target: `pdf_draw_fuzzer` from a current poppler build

## Reproduction

The attached `poc.pdf` is 485 bytes and declares:

```text
/W 32767
/H 32767
```

**Standard CLI:**
```bash
pdftoppm -r 1 poc.pdf /dev/null
# or: pdftocairo -png -r 1 poc.pdf /tmp/out
```
Observe the wall-clock time (>20 s) for a 485-byte input.

**With fuzzer target from oss-fuzz:**
```bash
pdf_draw_fuzzer poc.pdf
```

## Observed output

Representative observed run:

```text
Executed /work/poc.pdf in 21156 ms
```

## Impact

- CWE-400: Uncontrolled Resource Consumption
- CVSS: 7.5 (High)
- A very small PDF can keep a worker busy for roughly 20 seconds in the tested build.

## Suggested fix

Clamp inline image dimensions and reject obviously inconsistent combinations of declared dimensions and available image bytes before decoding begins.
