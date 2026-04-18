# How to Report Cairo Vulnerabilities

This guide covers reporting the 5 cairo bugs (IDs cairo-1 through cairo-5) discovered
during OSS-Fuzz poppler testing. Although the bugs are triggered via poppler's rendering
pipeline, the vulnerable code resides entirely within cairo — they must be reported to
the cairo project, not to poppler.

---

## Cairo Project Contacts

| Channel | Details |
|---------|---------|
| Canonical repository | https://gitlab.freedesktop.org/cairo/cairo |
| Issue tracker | https://gitlab.freedesktop.org/cairo/cairo/-/issues |
| Mailing list | cairo@cairographics.org |
| SECURITY.md | None — no private disclosure process found as of 2026-04-17 |

Because cairo has no `SECURITY.md` and no documented private vulnerability disclosure
process, the appropriate path is to file public GitLab issues. If you prefer to attempt
a coordinated disclosure before going public, send an email to `cairo@cairographics.org`
with a short description and ask for a private channel; if there is no response within
14 days, proceed with public issues.

---

## Bug Summary Table

| Folder | File Location | Bug Type | Severity | Sanitizer |
|--------|--------------|----------|----------|-----------|
| `06-cairo-fixed-imgmask-overflow` | `cairo/src/cairo-fixed-private.h:233` | Signed integer overflow — INT_MIN negation (CWE-190) | Medium (CVSS 5.5) | UBSan |
| `07-cairo-slope-path-overflow` | `cairo/src/cairo-slope-private.h:49` | Signed integer overflow — coordinate subtraction (CWE-190) | Medium (CVSS 5.5) | UBSan |
| `08-cairo-pathbounds-overflow` | `cairo/src/cairo-path-bounds.c:180` | Signed integer overflow — stroke extent expansion (CWE-190) | Medium (CVSS 5.5) | UBSan |
| `09-cairo-truetype-heapboflow` | `cairo/src/cairo-truetype-subset.c:1462` | Heap buffer overflow — TrueType name table (CWE-125/CWE-122) | High (CVSS 7.8) | ASan |
| `10-cairo-type1-intovf` | `cairo/src/cairo-type1-subset.c:667` | Signed integer overflow — Type1 metric computation (CWE-190) | Medium (CVSS 5.5) | UBSan |

---

## Step-by-Step Reporting Instructions

### Step 1 — (Optional) Attempt coordinated disclosure via mailing list

Send an email to `cairo@cairographics.org`:

```
Subject: [Security] 5 integer/heap overflow bugs found via OSS-Fuzz (UBSan/ASan)

Hi cairo team,

I have found 5 bugs in cairo (4 UBSan integer overflows, 1 ASan heap buffer overflow)
triggered through poppler's rendering pipeline. I would like to coordinate disclosure.
Please let me know if there is a private channel I can use.

Summary:
  - cairo-fixed-private.h:233 — INT_MIN negation UB (UBSan)
  - cairo-slope-private.h:49  — coordinate subtraction overflow (UBSan)
  - cairo-path-bounds.c:180   — stroke extent expansion overflow (UBSan)
  - cairo-truetype-subset.c:1462 — heap-buffer-overflow in find_name() (ASan)
  - cairo-type1-subset.c:667  — Type1 metric multiplication overflow (UBSan)

Contact: yiweihou233@gmail.com
```

Wait up to 14 days for a response. If none, proceed to Step 2.

### Step 2 — File public GitLab issues

Go to: https://gitlab.freedesktop.org/cairo/cairo/-/issues/new

File one issue per bug. Suggested fields for each issue:

**Title format**: `[Security] <short description> in <file>:<line> (CWE-NNN)`

Example titles:
- `[Security] Signed integer overflow (INT_MIN negation) in cairo-fixed-private.h:233 (CWE-190)`
- `[Security] Heap buffer overflow in find_name() cairo-truetype-subset.c:1462 (CWE-125)`

**Labels to apply** (select from the GitLab label list):
- `bug`
- `security` (if available; create it if not)

**Issue body**: Paste the contents of the corresponding `bug_report.md` file from this
repository. The reports are already in developer-ready format covering Summary,
Vulnerable Code, Proof of Concept, Impact, and Suggested Fix.

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
| cairo-1 (fixed-imgmask-overflow) | _to be filled_ |
| cairo-2 (slope-path-overflow) | _to be filled_ |
| cairo-3 (pathbounds-overflow) | _to be filled_ |
| cairo-4 (truetype-heapboflow) | _to be filled_ |
| cairo-5 (type1-intovf) | _to be filled_ |

### Step 5 — Include reproduction environment information

Add the following to each issue:

```
Reproduction environment:
  Cairo:   built from source alongside poppler 26.04.90 (OSS-Fuzz setup)
  Poppler: 26.04.90
  Trigger: docker run --rm -v /path:/path vulagent/poppler:latest \
             /out/<sanitizer>/<fuzzer> /path/to/poc.pdf
  UBSan bugs: fuzzer = pdf_draw_fuzzer or annot_fuzzer, sanitizer dir = ubsan
  ASan bug:   fuzzer = annot_fuzzer, sanitizer dir = asan
```

---

## Notes on Attribution

- The bugs were found via automated fuzzing (OSS-Fuzz-style setup) with poppler as the
  entry point; the root cause in every case is in cairo source code.
- Do not report these to the poppler project — poppler is not at fault.
- If cairo maintainers ask for a reproducer PDF, provide the PoC described in the
  relevant `bug_report.md`. Do not share heap addresses or other environment-specific
  ASan detail beyond what is already documented.
