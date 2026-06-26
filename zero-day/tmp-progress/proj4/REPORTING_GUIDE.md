# PROJ Vulnerability Reporting Guide

**Validated on commit:** `324ed2119011d74665548afe445eacb99afb9753` (master, 2026-04-17)  
**Latest release (also affected):** PROJ **9.8.1** (2026-04-10)  
**Current master (unverified):** `7f43bf300a3034566dda01d489f428ac7600de0e` (2026-04-21)  
**Valid public-API bugs:** **9** confirmed (2 excluded — internal C++ API only, see below)

---

## Validity Assessment

Two PoCs require `-DFROM_PROJ_CPP` and PROJ's internal C++ class API (`NN_NO_CHECK`,
`WKTNode` constructor, `ConcatenatedOperation::create()`, etc.).  These **cannot** be
triggered through PROJ's documented public C/C++ API:

| # | Folder | Exclusion reason |
|---|--------|-----------------|
| 01 | `01-io-SF09-wktnode-stack-overflow` | Internal C++ API only. The WKT *parser* enforces a 16-level depth cap, so no public-API caller can construct a tree deep enough to trigger `WKTNode::toString()` recursion. |
| 11 | `11-singleop-SF01-concatop-stack-overflow` | Internal C++ API only. A deeply nested `ConcatenatedOperation` cannot be created through the public API without first hitting bug #02 (PROJJSON parser crash), so this export path is never independently reachable. |

These two are real implementation deficiencies worth fixing, but they are **not reportable
as externally exploitable security vulnerabilities**.

---

## Summary of Valid Confirmed Bugs (9 total)

| # | Folder | Type | Severity | Public API entry point |
|---|--------|------|----------|------------------------|
| 02 | `02-crs-SF01-projjson-stack-overflow` | Stack overflow | High | `proj_create()` + `proj_as_projjson()` |
| 03 | `03-net-SF23-nfm-null-deref` | NULL deref (SEGV) | High | `proj_is_download_needed(ctx, NULL, …)` |
| 04 | `04-net-SF24-download-null-deref` | NULL deref (SEGV) | High | `proj_download_file(ctx, NULL, …)` |
| 05 | `05-isea-SF08-silent-inverse-failure` | Logic error | Medium | `proj_create()` + `proj_trans()` |
| 06 | `06-capi-SF22-null-deref-api-functions` | NULL deref (SEGV) | High | `proj_get_ellipsoid()` etc. with `NULL obj` |
| 07 | `07-capi-SF04-dangling-string-ptr` | Use-after-free | Medium | `proj_uom_get_info_from_database()` |
| 08 | `08-conv-SF02-null-deref-stack-oob` | NULL deref (SEGV) | High | `proj_create_conversion(…, 1, NULL)` |
| 09 | `09-grids-SF01-proj-grid-info-null` | Abort (exception) | Medium | `proj_grid_info(NULL)` |
| 10 | `10-grids-SF10-ntv2-destructor-overflow` | Stack overflow | High | crafted NTv2 `.gsb` file via `proj_create_crs_to_crs()` |

All bugs are **denial-of-service only** (no code execution, no memory disclosure). Public
reporting via GitHub Issues is appropriate; there is no private disclosure channel.

---

## Recommended Filing Plan — 7 GitHub Issues

### Issue 1 — NULL deref via `proj_is_download_needed()` / `proj_download_file()` (bugs #03 + #04)

**Title:** `[Bug] NULL pointer dereference in nfm_is_tilde_slash() via proj_is_download_needed() and proj_download_file()`

Merge #03 and #04 into one issue: same root cause (`nfm_is_tilde_slash()` dereferences
`*name` before checking for NULL), two distinct public API entry points.  Single fix
resolves both.

---

### Issue 2 — NULL deref in four C API functions with `NULL obj` (bug #06)

**Title:** `[Bug] NULL pointer dereference in proj_get_ellipsoid / proj_get_prime_meridian / proj_get_celestial_body_name / proj_normalize_for_visualization when obj is NULL`

Four functions share the same missing `if (!obj)` guard.  Report them together;
single fix pattern resolves all four.

---

### Issue 3 — NULL deref in `proj_create_conversion()` (bug #08)

**Title:** `[Bug] NULL pointer dereference in proj_create_conversion() when param_count > 0 and params is NULL`

---

### Issue 4 — Process abort in `proj_grid_info(NULL)` (bug #09)

**Title:** `[Bug] Uncaught std::logic_error / process abort in proj_grid_info() when gridname is NULL`

---

### Issue 5 — PROJJSON stack overflow (bug #02)

**Title:** `[Bug] Stack overflow via unbounded recursion in PROJJSON parsing (proj_create) and CRS JSON export (proj_as_projjson)`

Two sub-paths (parse and export); both are covered in `bug_report.md`.  One issue,
two suggested fixes.

---

### Issue 6 — NTv2 destructor stack overflow via crafted grid file (bug #10)

**Title:** `[Bug] Stack overflow in NTv2Grid destructor when loading malformed NTv2 grid file with deep parent-child hierarchy`

---

### Issue 7 — Medium-severity logic / API-contract bugs (bugs #05 + #07)

**Title:** `[Bug] Two medium-severity API issues: silent ISEA inverse failure (errno=0 on inf result) and dangling pointer from proj_uom_get_info_from_database()`

Bundle #05 and #07 in one issue to avoid noise.  Each has its own **Summary**,
**Vulnerable code**, **PoC**, and **Suggested fix** section inside the single issue body.

---

## GitHub Issue Template

```
**Title:** [Bug] <short description>

**PROJ version:** 9.8.1 (latest release); also confirmed on master commit 324ed2119011d74665548afe445eacb99afb9753 (2026-04-17)
**OS:** Linux x86_64 (Ubuntu 20.04)
**Build:** ASAN (-fsanitize=address -g -O1)

## Summary
[one paragraph from bug_report.md]

## Affected API
[function signature(s)]

## Vulnerable code
[code snippet from bug_report.md]

## Reproduction
[compilation + run commands — replace /path/to/ with actual mount paths]

## Observed output
[ASAN / abort output]

## Suggested fix
[diff from bug_report.md]

## Impact
[one paragraph from bug_report.md]
```

---

## Step-by-Step Filing Instructions

1. **Authenticate to GitHub** — log in to your account.
2. **Open a new issue** at https://github.com/OSGeo/PROJ/issues/new
3. **Fill in the template** using the corresponding `bug_report.md` in each subfolder.
4. **Attach PoC files** — attach `.c` / `.cpp` files and data files (`.gsb`, `.json`) as
   `.zip` archives (GitHub blocks executable extensions).
5. **Label** — use labels `bug` and `security` if available.
6. **Link related issues** — add "Related to #NNNN" when filing subsequent issues.

---

## Reproduction Environment

```
Docker image:  revelio/proj4-asan:latest (Ubuntu 20.04, clang 10)
PROJ source:   https://github.com/OSGeo/PROJ (commit 324ed211..., 2026-04-17)
Build flags:   -fsanitize=address -g -O1
PROJ_DATA:     /out/asan
sqlite3:       3.31.1 (Ubuntu 20.04 package)
```

Run all valid PoCs at once:

```bash
docker run --rm \
  -v /scr2/yiwei/revelio/zero-day/proj4_validated:/bugs \
  -v /tmp/PROJ-latest:/src/PROJ-latest:ro \
  -v /tmp/proj4-latest-build:/proj4-latest-build:ro \
  revelio/proj4-asan:latest bash /bugs/build_all.sh
```
