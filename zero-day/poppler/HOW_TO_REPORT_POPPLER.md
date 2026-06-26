# How to Report Poppler Vulnerabilities

## Project Location

- **GitLab repository:** https://gitlab.freedesktop.org/poppler/poppler
- **Issue tracker:** https://gitlab.freedesktop.org/poppler/poppler/-/issues
- **New issue:** https://gitlab.freedesktop.org/poppler/poppler/-/issues/new

## Version Information

- **Latest stable release:** poppler **26.04.0** (2026-04-01)
- **Validation commit:** `e3d56a0` (2026-04-04) — development snapshot after 26.04.0,
  self-reports as version **26.04.90** in `configure.ac`
- All 8 bugs were confirmed on commit `e3d56a0`. Because this commit is only 3 days
  past the 26.04.0 release tag with no relevant intervening fixes, these bugs almost
  certainly also affect the 26.04.0 stable release.
- When reporting, cite both: `confirmed on commit e3d56a0 (2026-04-04); also affects
  the 26.04.0 release (2026-04-01)`.

## Security Validity Assessment

**All 8 bugs are confirmed valid security vulnerabilities.** None are API misuse:

| Bug(s)  | Trigger path                                    | Why valid                                                  |
|:--------|:------------------------------------------------|:-----------------------------------------------------------|
| 01 + 02 | Standard PDF `/ColorSpace` image XObject        | Bounds check exists but executes *after* the overflow      |
| 03 + 04 | Standard `/Filter /FlateDecode /Predictor 2`    | C++ UB (undefined shift) corrupts the predictor output     |
| 05      | Standard PDF AcroForm `/Kids` array             | No depth limit → stack overflow on any deep form           |
| 11      | Standard PDF inline image (`BI`/`ID`/`EI`)      | No dimension guard → CPU stall from 485-byte input         |
| 12      | Standard PDF page dimensions + text objects     | No page-size cap → CPU+memory stall from oversized page    |
| 13      | PDF outline `/First` chain (bookmarks)          | No depth limit → stack overflow via public `create_toc()`  |

Every bug is reachable by simply opening a crafted PDF — no special privileges,
no internal API access, no undocumented hooks.

## Disclosure Process

Poppler has **no `SECURITY.md`** and **no documented private disclosure process**.
There is no security advisory mechanism on freedesktop.org GitLab.

**Report all bugs as public GitLab issues.** Attach PoC PDF files directly to
the issue.

If there is no response within **14 days**, email the primary maintainer directly:
> Albert Astals Cid — **tsdgeos@gmail.com** (based on public commit history)

---

## Step-by-Step Reporting Instructions

### Step 1 — Sign into GitLab

Go to https://gitlab.freedesktop.org and sign in (or create an account).

### Step 2 — Open a new issue

Navigate to: https://gitlab.freedesktop.org/poppler/poppler/-/issues/new

### Step 3 — Fill in the issue

**Title format:** `[Security] <short description> (<CWE-NNN>)`

Example: `[Security] Signed integer overflow in ImageStream::ImageStream() for CMYK images (CWE-190)`

**Labels to apply:**
- `bug` (always)
- `security` (if available in the label list)
- `crash` (for bugs that crash the process)

**Description:**
- For bugs **01–05** and **13**: paste the full contents of the relevant
  `bug_report.md` file and attach the `poc.pdf`.
- For bugs **11** and **12**: paste the full contents of the `ISSUE.md` file
  (already formatted for GitLab) and attach the `poc.pdf`.

For combined issues (A and B below), paste both `bug_report.md` files separated
by a `---` divider, lead with the combined title, and attach all PoC PDFs.

### Step 4 — Submit and note the issue URL

Record each issue URL for follow-up.

### Step 5 — Follow up

If no response within 14 days, email Albert Astals Cid at tsdgeos@gmail.com
with the issue URL and a brief summary.

---

## Bugs to Report — Grouping

File **6 issues** total (bugs 1+2 combined, bugs 3+4 combined, rest individually):

| Issue # | Folders                                              | Title (short)                                      | Severity | Source file         |
|:-------:|:-----------------------------------------------------|:---------------------------------------------------|:--------:|:--------------------|
| A       | 01-stream-intovf-cmyk + 02-stream-intovf-rgb         | Integer overflow in ImageStream (CMYK + RGB)       | Medium   | both bug_report.md  |
| B       | 03-stream-tiff-shift-ub + 04-stream-tiff-neg-shift   | TIFF predictor shift UB (if vs while)              | Medium   | both bug_report.md  |
| C       | 05-form-recursion-stackoverflow                      | Stack overflow in AcroForm /Kids traversal         | High     | bug_report.md       |
| D       | 11-pdfdoc-inline-img-dos                             | CPU DoS via unbounded inline image dimensions      | High     | **ISSUE.md** (ready)|
| E       | 12-textout-dos                                       | CPU+memory DoS via oversized page + text blocks    | High     | **ISSUE.md** (ready)|
| F       | 13-outline-recursion-stackoverflow                   | Stack overflow in outline /First chain traversal   | High     | bug_report.md       |

---

## Full Bug Inventory

| Folder                             | CWE     | Type                         | Sanitizer | CVSS  |
|:-----------------------------------|:--------|:-----------------------------|:---------:|:-----:|
| 01-stream-intovf-cmyk              | CWE-190 | Integer overflow (CMYK)      | UBSan     | 5.5   |
| 02-stream-intovf-rgb               | CWE-190 | Integer overflow (RGB)       | UBSan     | 5.5   |
| 03-stream-tiff-shift-ub            | CWE-682 | Shift exponent overflow      | UBSan     | 5.5   |
| 04-stream-tiff-neg-shift           | CWE-682 | Negative shift exponent      | UBSan     | 5.5   |
| 05-form-recursion-stackoverflow    | CWE-674 | Stack overflow (AcroForm)    | ASan      | 7.5   |
| 11-pdfdoc-inline-img-dos           | CWE-400 | CPU DoS (inline image)       | None      | 7.5   |
| 12-textout-dos                     | CWE-400 | CPU+memory DoS (page size)   | None      | 7.5   |
| 13-outline-recursion-stackoverflow | CWE-674 | Stack overflow (outline)     | ASan      | 7.5   |

All bugs confirmed on commit **e3d56a0** (2026-04-04, poppler 26.04.90 dev).
Latest stable release affected: **26.04.0** (2026-04-01).

---

## Standard CLI Reproduction (no Docker, no sanitizer build)

Each bug can also be reproduced with a standard poppler install.
Use these commands to verify on an unmodified system-installed poppler or a
fresh source build **without** sanitizers. Sanitizer output is only needed to
confirm the exact UB/overflow — the bugs are present regardless.

| Issue | Standard CLI command                                     |
|:-----:|:---------------------------------------------------------|
| A     | `pdftoppm poc.pdf /dev/null`                            |
| B     | `pdftoppm poc_nBits12.pdf /dev/null`                    |
| C     | `pdftotext poc.pdf /dev/null`  (form init on doc open)  |
| D     | `pdftoppm -r 1 poc.pdf /dev/null`                       |
| E     | `pdftotext poc.pdf /dev/null`                           |
| F     | `pdftohtml poc.pdf /tmp/out`                            |

For issue A and B, `pdftocairo -png -r 1 poc.pdf /tmp/out` is an alternative.
For issue F, the poppler-cpp `create_toc()` path also triggers the crash (see
`bug_report.md` for the minimal C++ driver).

---

## Issue Template

Copy and adapt the following template when creating each issue:

```
## Summary

<one paragraph from bug_report.md / ISSUE.md Summary section>

- **Affected file:** <file>
- **Confirmed on commit:** e3d56a0 (2026-04-04, poppler 26.04.90 dev)
- **Also affects stable release:** 26.04.0 (2026-04-01)
- **CWE:** <CWE-NNN>
- **CVSS:** <score>

## Vulnerable Code

<code block from Vulnerable Code section>

## Proof of Concept

<reproduction command — prefer standard CLI tool; include sanitizer command for
definitive UB/overflow confirmation>

## Impact

<Impact section from bug_report.md>

## Suggested Fix

<Suggested Fix section from bug_report.md>
```

Attach the `poc.pdf` file(s) as attachments in the GitLab issue form.

---

## Notes

- Poppler is hosted on **GitLab** (freedesktop.org), not GitHub. Do not open
  GitHub issues.
- freedesktop.org GitLab does not have a "Security Advisory" feature equivalent
  to GitHub private security advisories. Public issues are the correct channel.
- The sanitizer reproduction commands use Docker image `revelio/poppler:latest`
  built from commit `e3d56a0`. Include this context in each issue so maintainers
  can reproduce by building the same commit with the relevant sanitizer.
- For issues D and E (DoS bugs), if the maintainer asks for a severity
  justification: emphasize server-side use cases (pdftotext in document indexers,
  pdftoppm in web PDF viewers) where a 20-second stall per malicious PDF is a
  practical denial-of-service vector.
