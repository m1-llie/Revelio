# Reporting Guide: OpenEXR IDManifest Vulnerabilities (3 Issues)

Validated against OpenEXR **main branch, commit `c13e0e1` (2026-04-16)**.
All three issues reside in `src/lib/OpenEXR/ImfIDManifest.cpp` and are
reachable via any EXR file carrying an `idmanifest` attribute.

---

## Who Maintains OpenEXR

OpenEXR is a project of the **Academy Software Foundation (ASWF)**.

- **GitHub:** https://github.com/AcademySoftwareFoundation/openexr
- **Security email:** security@openexr.com
- **GitHub Security Advisory:** https://github.com/AcademySoftwareFoundation/openexr/security/advisories/new
- **TSC contact (for follow-up):** openexr-dev@lists.aswf.io (public mailing list)

---

## Security Disclosure Policy

OpenEXR follows the **GitHub private security advisory** model. From the project's
GitHub security tab:

- **Preferred channel:** Submit a private GitHub Security Advisory (GHSA) via
  https://github.com/AcademySoftwareFoundation/openexr/security/advisories/new
- **Email alternative:** security@openexr.com (acknowledged within 48 hours per ASWF policy)
- **SLA:** Critical issues: patch target 14 days; High: 90 days.
- **CVE assignment:** OpenEXR/ASWF self-assigns CVEs via GitHub as a CNA partner.

**Do NOT open a public GitHub issue** for security-sensitive bugs — use the private
advisory form or the security email.

---

## The Three Issues

| # | Sub-folder | Type | Sanitizer | Severity |
|---|-----------|------|-----------|----------|
| 1 | `01-idmanifest-ubsan-shift-overflow` | UBSan: shift exponent OOB | UBSan | High |
| 2 | `02-idmanifest-oob-string-prefix` | OOB read: missing string size check | ASan / `_GLIBCXX_DEBUG` | High |
| 3 | `03-idmanifest-oob-mapping-vector` | UBSan: off-by-one in bounds check → null ptr | UBSan | High |

All three affect the same code area (`ImfIDManifest.cpp`) and the same attack
surface (parsing `idmanifest` EXR attributes). **Report them together in a single
advisory** to allow the maintainers to audit and fix the whole function in one pass.

---

## Step-by-Step: GitHub Private Security Advisory (Recommended)

### 1. Open the Advisory Form

Go to:
```
https://github.com/AcademySoftwareFoundation/openexr/security/advisories/new
```
Log in with your GitHub account. The form creates a private GHSA visible only
to you and the OpenEXR maintainers.

### 2. Fill In the Form

**Ecosystem:** C/C++  
**Package name:** openexr  
**Affected versions:** `≤ main (c13e0e1, 2026-04-16)` (or whatever version you see in `openexr_version.h`)  
**Patched versions:** (leave blank — unfixed)

**Severity:** High (CVSS 3.1 base ≈ 6.5–7.5 for each issue individually)

**Title (suggested):**
```
Three security bugs in IDManifest parsing (ImfIDManifest.cpp): UBSan shift overflow, OOB string-prefix read, off-by-one mapping bounds check
```

**Description:** Paste the content from each `bug_report.md`, separated by headings,
or attach them as files. A concise combined summary:

---

> **Summary (combine in the advisory body):**
>
> Three separate bugs in `src/lib/OpenEXR/ImfIDManifest.cpp` allow a crafted
> EXR file with a malformed `idmanifest` attribute to trigger undefined behavior,
> out-of-bounds reads, or a null pointer dereference. All three are reachable
> without elevated privileges, just by opening a malicious `.exr` file.
>
> **Bug 1 — Shift exponent overflow (UBSan):**  
> `readVariableLengthInteger()` has no upper bound on the shift counter. After
> 10 continuation bytes, shift reaches 70 and `(uint64_t) << 70` is UB per
> C++14 §5.8/2. Fix: add `if (shift >= 64) throw …`.
>
> **Bug 2 — OOB read: missing bounds check before 2-byte prefix read:**  
> `IDManifest::init()` reads `stringList[i][0]` and `[1]` without checking
> `stringList[i].size() ≥ 2`. With a 0-byte string 1, both reads are OOB.
> Fix: add size checks before the reads.
>
> **Bug 3 — Off-by-one in string-index bounds check → null ptr deref:**  
> The check `size_t(stringIndex) > stringList.size()` uses `>` instead of `>=`.
> When `stringList` is empty and `stringIndex == 0`, the check passes and
> `mapping[0]` dereferences a null pointer. Fix: change `>` to `>=`.

---

### 3. Attach the Files

Attach or reference the following from this directory:

```
01-idmanifest-ubsan-shift-overflow/
  ├── poc.bin              ← PoC payload (24 bytes)
  ├── harness.cpp          ← minimal test harness
  ├── build.sh             ← one-step Docker build + run
  ├── bug_report.md        ← full technical report
  └── crash_output.txt     ← validated UBSan output

02-idmanifest-oob-string-prefix/
  ├── poc.bin              ← PoC payload (267 bytes)
  ├── harness.cpp
  ├── build.sh
  ├── bug_report.md
  └── crash_output.txt     ← ASAN + _GLIBCXX_DEBUG output

03-idmanifest-oob-mapping-vector/
  ├── poc.bin              ← PoC payload (68 bytes)
  ├── harness.cpp
  ├── build.sh
  ├── bug_report.md
  └── crash_output.txt     ← validated UBSan output
```

### 4. Submit and Wait

- Submit the advisory. The OpenEXR security team should acknowledge within 48 hours.
- If no response in 7 days, follow up at security@openexr.com.
- If no response in 14 days, you may escalate to the ASWF security working group.

---

## Alternative: Email

If you prefer email over the GitHub advisory form:

**To:** security@openexr.com  
**Subject:** `[SECURITY] Three bugs in IDManifest parsing (ImfIDManifest.cpp): UBSan, OOB read, null-ptr deref`

**Body template:**

```
Hello OpenEXR Security Team,

I am reporting three security bugs in ImfIDManifest.cpp, all confirmed against
main branch commit c13e0e1 (2026-04-16). All three are triggered by a crafted
EXR file with a malformed 'idmanifest' attribute.

Bug 1: Shift exponent overflow in readVariableLengthInteger()
  File: src/lib/OpenEXR/ImfIDManifest.cpp:122
  UBSan: "shift exponent 70 is too large for 64-bit type 'uint64_t'"
  Fix:   add if (shift >= 64) throw before the left-shift

Bug 2: OOB read — missing size check before 2-byte prefix read in IDManifest::init()
  File: src/lib/OpenEXR/ImfIDManifest.cpp:342-343
  _GLIBCXX_DEBUG: "Assertion '__pos <= size()' failed"
  Fix:   check stringList[i].size() >= 2 before accessing [0] and [1]

Bug 3: Off-by-one bounds check → null ptr deref on empty mapping vector
  File: src/lib/OpenEXR/ImfIDManifest.cpp (~line 521)
  UBSan: "reference binding to null pointer of type 'int'"
  Fix:   change > to >= in the stringIndex bounds check

I have attached per-bug technical reports, PoC payloads, and Docker-validated
crash outputs. Please let me know your preferred timeline for fixes.

I am following coordinated disclosure practices. I intend to disclose publicly
after a fix is available, or after 90 days from this report, whichever comes first.

[Your name / handle]
```

Attach all files listed in the attachments section above.

---

## CVE Assignment

OpenEXR participates in the GitHub CVE numbering authority (CNA) program. When
you submit a private GitHub Security Advisory, GitHub can assign CVE numbers
directly from the advisory form — select "Request CVE ID" at the bottom of the
form. One CVE per distinct bug is appropriate (three CVEs total).

---

## Do NOT Do

- Do **not** open a public GitHub issue — the security advisory form provides a
  private channel specifically for this.
- Do **not** post on the openexr-dev mailing list before a fix is confirmed —
  the list is public and archived.
- Do **not** request CVEs from MITRE before notifying the maintainers.

---

## Embargo and Public Disclosure

- Standard coordinated disclosure window: **90 days** from initial report.
- If maintainers release a fix sooner, publish your report the day of or after release.
- Update this guide with the CVE numbers once assigned.

---

## Files in This Report

```
4-openexr-260417/
├── REPORTING_GUIDE.md                         ← this file
├── 01-idmanifest-ubsan-shift-overflow/
│   ├── poc.bin                                ← 24-byte PoC
│   ├── harness.cpp                            ← test harness
│   ├── build.sh                               ← one-step build + run
│   ├── bug_report.md                          ← developer-facing report
│   └── crash_output.txt                       ← UBSan validated output
├── 02-idmanifest-oob-string-prefix/
│   ├── poc.bin                                ← 267-byte PoC
│   ├── harness.cpp
│   ├── build.sh
│   ├── bug_report.md
│   └── crash_output.txt                       ← ASAN + _GLIBCXX_DEBUG output
└── 03-idmanifest-oob-mapping-vector/
    ├── poc.bin                                ← 68-byte PoC
    ├── harness.cpp
    ├── build.sh
    ├── bug_report.md
    └── crash_output.txt                       ← UBSan validated output
```
