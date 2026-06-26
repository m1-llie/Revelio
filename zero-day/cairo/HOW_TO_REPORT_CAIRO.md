# How to Report Cairo Vulnerabilities

This guide covers reporting the 5 cairo bugs (IDs cairo-1 through cairo-5) discovered
via OSS-Fuzz-style fuzzing of poppler's rendering pipeline. The vulnerable code resides
entirely within cairo — these must be reported to the cairo project, not to poppler.

---

## Cairo Project Information

| Item | Details |
|------|---------|
| Canonical repository | https://gitlab.freedesktop.org/cairo/cairo |
| Issue tracker | https://gitlab.freedesktop.org/cairo/cairo/-/issues |
| Mailing list | cairo@cairographics.org |
| Latest stable release | **cairo 1.18.4** (released 2025-03-08) |
| SECURITY.md | None — no private disclosure process found |

Because cairo has no `SECURITY.md` and no documented private vulnerability disclosure
process, the appropriate path is to file public GitLab issues. If you prefer coordinated
disclosure first, send an email to `cairo@cairographics.org` with a short description and
ask for a private channel; if there is no response within 14 days, proceed with public issues.

---

## Validity Assessment

All 5 bugs are **confirmed valid security vulnerabilities** triggered through documented
public cairo APIs. None require misuse of internal or private APIs:

| Bug ID | Public API Entry Point | Trigger Input |
|--------|----------------------|---------------|
| cairo-1 | `cairo_mask()` | PDF ImageMask XObject at extreme scale |
| cairo-2 | `cairo_stroke()` | PDF path spanning full fixed-point coordinate range |
| cairo-3 | `cairo_stroke()` | PDF Bezier curve with near-`INT_MAX` control points |
| cairo-4 | `cairo_surface_destroy()` | PDF with embedded malformed TrueType font |
| cairo-5 | `cairo_show_text()` + `cairo_surface_destroy()` | PDF with embedded Type1 font |

The attacker-controlled input in every case is a crafted PDF document. Any application
that renders attacker-supplied PDFs using cairo (evince, Inkscape, GNOME Shell, LibreOffice,
etc.) is in scope. The bugs were found with poppler as the PDF parsing layer — poppler is
not at fault; it correctly translates PDF operations into public cairo API calls.

---

## Bug Summary Table

| Folder | Vulnerable File | Bug Type | Severity | Sanitizer | Issue format |
|--------|----------------|----------|----------|-----------|--------------|
| `06-cairo-fixed-imgmask-overflow` | `cairo/src/cairo-fixed-private.h:233` | Signed integer overflow — INT_MIN negation (CWE-190) | Medium (CVSS 5.5) | UBSan | `bug_report.md` |
| `07-cairo-slope-path-overflow` | `cairo/src/cairo-slope-private.h:49` | Signed integer overflow — coordinate subtraction (CWE-190) | Medium (CVSS 5.5) | UBSan | `bug_report.md` |
| `08-cairo-pathbounds-overflow` | `cairo/src/cairo-path-bounds.c:180` | Signed integer overflow — stroke extent expansion (CWE-190) | Medium (CVSS 5.5) | UBSan | `bug_report.md` |
| `09-cairo-truetype-heapboflow` | `cairo/src/cairo-truetype-subset.c:1462` | Heap buffer overflow — TrueType name table (CWE-125/CWE-122) | **High (CVSS 7.8)** | ASan | `ISSUE.md` |
| `10-cairo-type1-intovf` | `cairo/src/cairo-type1-subset.c:667` | Signed integer overflow — Type1 charstring key (CWE-190) | Medium (CVSS 5.5) | UBSan | `bug_report.md` |

---

## Step-by-Step Reporting Instructions

### Step 1 — (Optional) Attempt coordinated disclosure via mailing list

Send an email to `cairo@cairographics.org`:

```
Subject: [Security] 5 integer/heap overflow bugs in cairo (UBSan/ASan confirmed)

Hi cairo team,

I have found 5 bugs in cairo (4 UBSan signed integer overflows, 1 ASan heap buffer
overflow) reachable through cairo's public drawing and surface APIs when processing
attacker-controlled font data or extreme coordinate values.

Summary:
  - cairo-fixed-private.h:233  — INT_MIN negation UB in _cairo_fixed_integer_floor()
  - cairo-slope-private.h:49   — coordinate subtraction overflow in _cairo_slope_init()
  - cairo-path-bounds.c:180    — stroke extent expansion overflow
  - cairo-truetype-subset.c:1462 — heap-buffer-overflow in find_name() [HIGH]
  - cairo-type1-subset.c:667   — signed overflow in Type1 charstring key computation

All bugs are confirmed on cairo git master (≥ 1.18.4) and reachable via public cairo
APIs. I would like to coordinate disclosure. Please let me know if there is a private
channel I can use.
```

Wait up to 14 days for a response. If none, proceed to Step 2.

### Step 2 — File public GitLab issues

Go to: https://gitlab.freedesktop.org/cairo/cairo/-/issues/new

File **one issue per bug**. Suggested fields for each issue:

**Title format**: `[Security] <short description> in <file>:<line> (CWE-NNN)`

Example titles:
- `[Security] Signed integer overflow (INT_MIN negation) in cairo-fixed-private.h:233 (CWE-190)`
- `[Security] Heap buffer overflow in find_name() cairo-truetype-subset.c:1462 (CWE-122)`
- `[Security] Signed integer overflow in _cairo_slope_init() cairo-slope-private.h:49 (CWE-190)`
- `[Security] Signed integer overflow in stroke extents cairo-path-bounds.c:180 (CWE-190)`
- `[Security] Signed integer overflow in Type1 charstring key cairo-type1-subset.c:667 (CWE-190)`

**Labels to apply** (select from the GitLab label list):
- `bug`
- `security` (if available; create it if not)

**Issue body**: Paste the contents of the corresponding `bug_report.md` or `ISSUE.md`
file. The reports are written for cairo developers and cover Summary, Public API Entry
Point, Vulnerable Code, Proof of Concept, Impact, and Suggested Fix.

**Attach**: `poc.pdf` from the same folder as a file attachment.

### Step 3 — File order (priority)

File the ASan bug first as it is the highest severity:

1. `09-cairo-truetype-heapboflow` — CVSS 7.8 / High (ASan heap-buffer-overflow)
2. `06-cairo-fixed-imgmask-overflow` — CVSS 5.5 / Medium (UBSan INT_MIN negation)
3. `07-cairo-slope-path-overflow` — CVSS 5.5 / Medium (UBSan subtraction overflow)
4. `08-cairo-pathbounds-overflow` — CVSS 5.5 / Medium (UBSan addition overflow)
5. `10-cairo-type1-intovf` — CVSS 5.5 / Medium (UBSan multiplication overflow)

### Step 4 — Track issue numbers

Record the GitLab issue URLs here once filed:

| Bug ID | GitLab Issue URL |
|--------|----------------|
| cairo-4 (truetype-heapboflow) | _to be filled_ |
| cairo-1 (fixed-imgmask-overflow) | _to be filled_ |
| cairo-2 (slope-path-overflow) | _to be filled_ |
| cairo-3 (pathbounds-overflow) | _to be filled_ |
| cairo-5 (type1-intovf) | _to be filled_ |

### Step 5 — Include reproduction environment in each issue

Add the following to each issue body:

```
## Reproduction environment

| Item | Value |
|------|-------|
| Cairo | git master (≥ 1.18.4), latest stable: cairo 1.18.4 (2025-03-08) |
| OS | Linux x86_64 |
| Compiler | clang++ with ASan/UBSan |

The attached `poc.pdf` can be fed directly to any cairo-based PDF renderer.
The quickest way to reproduce without building cairo from source:

    docker pull revelio/poppler:latest
    docker run --rm -v /path/to/dir:/data revelio/poppler:latest \
      /out/<sanitizer>/<fuzzer> /data/poc.pdf

  UBSan bugs (cairo-1,2,3,5): sanitizer = ubsan, fuzzer = pdf_draw_fuzzer (cairo-1,2,3)
                                                          or annot_fuzzer (cairo-5)
  ASan bug  (cairo-4):         sanitizer = asan,  fuzzer = annot_fuzzer
```

---

## Notes on Attribution

- The bugs were found via automated fuzzing with poppler as the document parsing entry
  point; the root cause in every case is in cairo source code.
- **Do not report these to the poppler project** — poppler is not at fault.
- All reproduction steps and call stacks in the individual reports are framed from
  cairo's perspective; poppler frames in the call stacks appear only as context for
  how the cairo code was reached.
- If cairo maintainers ask for a reproducer PDF, provide the `poc.pdf` from the relevant
  folder. Do not share heap addresses or environment-specific ASan detail beyond what is
  already documented in `ISSUE.md`.
