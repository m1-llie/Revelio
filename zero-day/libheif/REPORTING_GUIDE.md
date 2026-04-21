# Reporting Guide: libheif Validated Vulnerabilities

This guide covers how to responsibly disclose the confirmed libheif security bugs
to the project maintainers.

---

## Security Assessment Summary

Verified against: libheif **1.21.2** (latest release) and master commit
`f20a88baec0f34825cc076b3dfb2578fb2d5728c` (2026-04-17).

**Validity criteria applied:**
- ✅ VALID: bugs triggered by documented public APIs (or malicious files) with ASAN error types of heap-buffer-overflow, OOB read/write, double-free, or use-after-free
- ❌ EXCLUDED: NULL pointer dereference, memory leaks, out-of-memory, divide-by-zero, stack exhaustion, UBSan-only with no memory corruption

| # | Directory | Type | Trigger | ASAN Error | Report? |
|---|-----------|------|---------|-----------|---------|
| 01 | `01-track-oob-chunk-access` | Heap OOB read | Malicious HEIF file | `heap-buffer-overflow READ` | **YES** |
| 02 | `02-unci-empty-null-parameters` | NULL deref | `parameters=NULL` | SEGV @ 0x4 (null struct) | **NO** — null deref |
| 03 | `03-gimi-component-id-overflow` | Int overflow → heap OOB write | API: `component_idx=UINT32_MAX` | SEGV @ 0x47fff7ffd (OOB) | **YES** |
| 04 | `04-saiz-sampleauxinfo-oob` | Heap OOB read (assert-guarded) | Malicious HEIF file | SIGABRT via assert (OOB in release) | **YES** |
| 05 | `05-tild-ntiles-overflow` | Int overflow → OOB on empty container | Malicious HEIF file | SEGV (OOB on empty vector) | **YES** |
| 06 | `06-track-null-iloc-deref` | NULL deref | Malicious HEIF file (missing iloc) | SEGV @ 0xa0 (null struct) | **NO** — null deref |
| 07 | `07-track-api-oob-no-size` | Heap buffer overflow write | API: undersized buffer | `heap-buffer-overflow WRITE` | **YES** |
| 08 | `08-track-release-double-free` | Double-free / UAF | API: double release | `heap-use-after-free READ` | **YES** |
| 09 | `09-context-api-null-data` | NULL deref in memcpy | `data=NULL, size>0` | SEGV @ 0x0 | **NO** — null deref |
| 10 | `10-context-api-negative-size` | Uncaught exception → abort | `size=-1` | SIGABRT (std::length_error) | **NO** — not memory corruption |
| 11 | `11-metadata-invalid-compression-enum` | UB via invalid enum | API: enum=99 | UBSan only, no crash | **NO** — UBSan only, no memory corruption |
| 12 | `12-snuc-memory-exhaustion` | Memory exhaustion | Malicious HEIF file | OOM | **NO** — out-of-memory |

**6 valid security vulnerabilities to report.**

---

## Who Maintains libheif

**Dirk Farin** is the primary maintainer.

- **Email:** dirk.farin@gmail.com
- **GitHub:** https://github.com/strukturag/libheif

No `SECURITY.md` or dedicated security alias exists.

---

## Disclosure Channel

**Use GitHub Private Vulnerability Reporting (strongly preferred):**

> https://github.com/strukturag/libheif/security/advisories/new

This is the channel used for all past libheif CVEs. Dirk typically responds promptly.

**Alternative:** Email dirk.farin@gmail.com directly with the same content.

## CVSS 3.1 Estimates

| # | Bug | AV | AC | PR | UI | S | C | I | A | Score |
|---|-----|----|----|----|----|---|---|---|---|-------|
| 01 | Track OOB chunk access | N | L | N | R | U | L | N | H | **6.5 Medium** |
| 04 | SampleAuxInfoReader OOB | N | L | N | R | U | L | N | H | **6.5 Medium** |
| 05 | tild nTiles int overflow | N | L | N | R | U | N | N | H | **6.5 Medium** |
| 03 | GIMI component int overflow | L | L | N | N | U | N | L | H | **6.1 Medium** |
| 07 | Track API OOB write | L | L | N | N | U | N | L | H | **6.1 Medium** |
| 08 | Track release double-free/UAF | L | L | N | N | U | N | L | H | **6.1 Medium** |

---

## CVE Assignment

After Dirk confirms and ships patches, request CVEs via the GitHub advisory
interface (GitHub is a CNA). Do **not** request before notification.

---

## Follow-Up Timeline

- No response after **7 days** → follow-up email to dirk.farin@gmail.com
- No response after **21 days** → oss-security post with 90-day disclosure notice
- Standard embargo: **90 days** from initial report date

---

## Do NOT Do

- Do **not** open a public GitHub issue — use the private advisory link.
- Do **not** request a CVE before the maintainer confirms.
- Do **not** post publicly before a fix is released.
