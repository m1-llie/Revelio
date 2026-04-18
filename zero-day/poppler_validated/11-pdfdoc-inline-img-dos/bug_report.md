# CPU Denial of Service via Unbounded Inline Image Dimensions (CWE-400)

## Summary

The inline image operator (BI/ID/EI) in `poppler/Gfx.cc` does not validate the
claimed `/W` (width) and `/H` (height) dictionary values against the actual
amount of image data present in the stream. A PDF claiming `/W 32767 /H 32767`
with only 10 bytes of image data causes poppler to spend approximately 60 seconds
attempting to process the image, resulting in a CPU denial of service.

- **Affected file:** `poppler/Gfx.cc` (inline image BI/ID/EI handling)
- **Confirmed on commit:** `e3d56a0` (2026-04-04, poppler 26.04.90)
- **Sanitizer:** None required (timing-based DoS)
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **CVSS:** 7.5 (High) — AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H

---

## Vulnerable Code

```cpp
// poppler/Gfx.cc — inline image handling (BI/ID/EI operators)
//
// The parser reads /W and /H from the inline image dictionary and uses
// them to drive image decoding without bounding them against the actual
// data available in the content stream. No maximum dimension check exists.
```

The inline image specification in the PDF standard does not require the data
length to match the declared dimensions, so poppler trusts the declared values
and attempts to read `W * H * components` bytes even when far fewer are present.

---

## Proof of Concept

PoC file: `poc.pdf` (located in this directory, 485 bytes).

The PDF contains a single-page content stream with an inline image:
```
BI
  /W 32767
  /H 32767
  /CS /G
  /BPC 1
ID
<10 bytes of image data>
EI
```

### Reproduction

```bash
docker run --rm \
  -v /scr2/yiwei/vul-agent/zero-day/poppler_validated/11-pdfdoc-inline-img-dos:/work \
  vulagent/poppler:latest \
  /out/asan/pdf_draw_fuzzer /work/poc.pdf
```

### Observed Timing

| Input              | Execution time |
|--------------------|:--------------:|
| Blank page PDF     | ~39 ms         |
| `poc.pdf`          | ~56,698 ms     |
| **Slowdown factor**| **~1,455×**    |

No crash or sanitizer output is produced — the process eventually completes
after exhausting CPU time attempting to process the oversized image.

---

## Impact

A single 485-byte PDF file causes ~60 seconds of CPU saturation. Any service
that processes untrusted PDF files (converters, previewers, print spoolers) can
be made unresponsive by a small number of such files submitted concurrently.
No memory corruption or information disclosure is present; the impact is
availability only.

---

## Suggested Fix

Two complementary mitigations:

1. **Clamp dimensions.** Add a maximum dimension check in the inline image
   parser before accepting `/W` and `/H` values:

```cpp
// In Gfx.cc, after reading W and H from the inline image dict:
if (width > 16384 || height > 16384) {
    error(errSyntaxWarning, getPos(),
          "Inline image dimensions too large: {0:d}x{1:d}", width, height);
    return;
}
```

2. **Validate against available data.** Before beginning pixel decoding,
   estimate the expected byte count (`W * H * components / 8`) and compare
   it against the number of bytes remaining before the `EI` marker; abort
   if the declared size far exceeds the available data.
