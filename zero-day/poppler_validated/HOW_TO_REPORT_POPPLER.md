# How to Report Poppler Vulnerabilities

## Project Location

- **GitLab repository:** https://gitlab.freedesktop.org/poppler/poppler
- **Issue tracker:** https://gitlab.freedesktop.org/poppler/poppler/-/issues
- **New issue:** https://gitlab.freedesktop.org/poppler/poppler/-/issues/new

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

**Description:** Paste the full contents of the relevant `bug_report.md` file.
Attach the `poc.pdf` (or other PoC files) as file attachments.

### Step 4 — Submit and note the issue URL

Record each issue URL for follow-up.

### Step 5 — Follow up

If no response within 14 days, email Albert Astals Cid at tsdgeos@gmail.com
with the issue URL and a brief summary.

---

## Bugs to Report — Grouping

File **6 issues** total (bugs 1+2 combined, bugs 3+4 combined, rest individually):

| Issue # | Folders                                   | Title (short)                                      | Severity | Grouping note                     |
|:-------:|:------------------------------------------|:---------------------------------------------------|:--------:|:----------------------------------|
| A       | 01-stream-intovf-cmyk + 02-stream-intovf-rgb | Integer overflow in ImageStream (CMYK + RGB)    | Medium   | Same code, same fix — one issue   |
| B       | 03-stream-tiff-shift-ub + 04-stream-tiff-neg-shift | TIFF predictor shift UB (if vs while)  | Medium   | Same root cause, same fix — one issue |
| C       | 05-form-recursion-stackoverflow           | Stack overflow in AcroForm /Kids traversal         | High     | Standalone                        |
| D       | 11-pdfdoc-inline-img-dos                  | CPU DoS via unbounded inline image dimensions      | High     | Standalone                        |
| E       | 12-textout-dos                            | CPU+memory DoS via oversized page + text blocks    | High     | Standalone                        |
| F       | 13-outline-recursion-stackoverflow        | Stack overflow in outline /First chain traversal   | High     | Standalone                        |

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

All bugs confirmed on commit **e3d56a0** (2026-04-04, poppler 26.04.90).

---

## Issue Template

Copy and adapt the following template when creating each issue:

```
## Summary

<one paragraph from bug_report.md Summary section>

- **Affected file:** <file>
- **Confirmed on commit:** e3d56a0 (2026-04-04, poppler 26.04.90)
- **CWE:** <CWE-NNN>
- **CVSS:** <score>

## Vulnerable Code

<code block from Vulnerable Code section>

## Proof of Concept

<reproduction command from bug_report.md>

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
- The reproduction commands use Docker image `vulagent/poppler:latest` built
  from commit `e3d56a0`. Include this context in each issue so maintainers can
  reproduce without the Docker image by building the same commit with the
  relevant sanitizer.
