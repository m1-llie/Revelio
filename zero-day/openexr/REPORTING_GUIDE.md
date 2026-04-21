# Reporting Guide: OpenEXR IDManifest Vulnerabilities (2 Valid Issues)

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

## Issue Triage

| # | Sub-folder | Type | Sanitizer | Valid? | Severity |
|---|-----------|------|-----------|--------|----------|
| 1 | `01-idmanifest-ubsan-shift-overflow` | UBSan: shift exponent OOB → integer UB | UBSan | **YES** | High |
| 2 | `02-idmanifest-oob-string-prefix` | OOB read: missing string size check | ASan / `_GLIBCXX_DEBUG` | **YES** | High |
| 3 | `03-idmanifest-oob-mapping-vector` | Null-ptr deref via empty mapping vector | UBSan | **NO — excluded** | — |

**Why issue 3 is excluded:** The UBSan output is "reference binding to null pointer of
type 'int'" — `std::vector::data()` is `nullptr` for an empty vector and
`mapping[0]` dereferences it.  This is a null pointer dereference leading to a reliable
SIGSEGV (denial of service only).  Null pointer dereferences are not considered
actionable security vulnerabilities in this project's scope.

Both valid issues affect the same code area (`ImfIDManifest.cpp`) and the same attack
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
**Affected versions:** `≤ main (c13e0e1, 2026-04-16)` (or whatever version you see in `openexr_version.h`, 3.4.10)  
**Patched versions:** (leave blank — unfixed)

**Severity:** High (CVSS 3.1 base ≈ 6.5–7.5 for each issue individually)

**Title (suggested):**
```
Two security bugs in IDManifest parsing (ImfIDManifest.cpp): UBSan shift overflow, OOB string-prefix read
```

**Description:** Paste the content from each `ISSUE.md`, separated by headings,
or attach them as files. A concise combined summary:

---

> **Summary (combine in the advisory body):**
>
> Two separate bugs in `src/lib/OpenEXR/ImfIDManifest.cpp` allow a crafted
> EXR file with a malformed `idmanifest` attribute to trigger undefined behavior
> and out-of-bounds reads. Both are reachable without elevated privileges, just
> by opening a malicious `.exr` file.
>
> **Bug 1 — Shift exponent overflow (UBSan / integer UB):**  
> `readVariableLengthInteger()` has no upper bound on the shift counter. After
> 10 continuation bytes, shift reaches 70 and `(uint64_t) << 70` is UB per
> C++14 §5.8/2. The corrupted return value is immediately used as the string-list
> length, potentially causing the subsequent parsing loop to read far beyond the
> input buffer. Fix: add `if (shift >= 64) throw …`.
>
> **Bug 2 — OOB read: missing bounds check before 2-byte prefix read:**  
> `IDManifest::init()` reads `stringList[i][0]` and `[1]` without checking
> `stringList[i].size() ≥ 2`. In production builds (no ASan, no `_GLIBCXX_DEBUG`)
> `operator[](1)` on an empty string reads 1 byte past the heap-allocated string
> buffer. The out-of-bounds byte controls the prefix-reconstruction length, enabling
> heap memory disclosure or a reliable crash. Fix: add size checks before the reads.

---

### 3. Attach the Files

Attach or reference the following from this directory:

```
01-idmanifest-ubsan-shift-overflow/
  ├── poc.bin              ← PoC payload (24 bytes)
  ├── harness.cpp          ← minimal test harness
  ├── build.sh             ← one-step Docker build + run
  ├── ISSUE.md             ← full technical report
  └── crash_output.txt     ← validated UBSan output

02-idmanifest-oob-string-prefix/
  ├── poc.bin              ← PoC payload (267 bytes)
  ├── harness.cpp
  ├── build.sh
  ├── ISSUE.md             ← full technical report
  └── crash_output.txt     ← ASan + _GLIBCXX_DEBUG output
```

Note: `03-idmanifest-oob-mapping-vector/` is **not included** — that bug is a null
pointer dereference (DoS only) and is out of scope for this security advisory.

### 4. Submit and Wait

- Submit the advisory. The OpenEXR security team should acknowledge within 48 hours.
- If no response in 7 days, follow up at security@openexr.com.
- If no response in 14 days, you may escalate to the ASWF security working group.


## CVE Assignment

OpenEXR participates in the GitHub CVE numbering authority (CNA) program. When
you submit a private GitHub Security Advisory, GitHub can assign CVE numbers
directly from the advisory form — select "Request CVE ID" at the bottom of the
form. One CVE per distinct bug is appropriate (**two CVEs total** — one for the
shift overflow, one for the OOB string-prefix read).

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
