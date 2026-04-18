# PROJ Vulnerability Reporting Guide

**Date:** 2026-04-17  
**PROJ commit validated:** `324ed2119011d74665548afe445eacb99afb9753` (master)  
**Bugs:** 11 confirmed — all still present in latest code  

---

## Summary of Confirmed Bugs

| # | Folder | Type | Severity | One-liner |
|---|--------|------|----------|-----------|
| 01 | `01-io-SF09-wktnode-stack-overflow` | Stack overflow | High | `WKTNode::toString()` recurses without depth limit |
| 02 | `02-crs-SF01-projjson-stack-overflow` | Stack overflow | High | `DerivedCRS::_exportToJSON()` + PROJJSON parser recurse without depth limit |
| 03 | `03-net-SF23-nfm-null-deref` | NULL deref (SEGV) | High | `proj_is_download_needed(ctx, NULL)` → `nfm_is_tilde_slash(NULL)` crashes |
| 04 | `04-net-SF24-download-null-deref` | NULL deref (SEGV) | High | `proj_download_file(ctx, NULL, ...)` same root cause via #03 |
| 05 | `05-isea-SF08-silent-inverse-failure` | Logic error | Medium | ISEA inverse returns `{inf,inf}` with `errno=0` for non-default configs |
| 06 | `06-capi-SF22-null-deref-api-functions` | NULL deref (SEGV) | High | 4 API functions dereference `obj` without NULL check |
| 07 | `07-capi-SF04-dangling-string-ptr` | Use-after-free | Medium | `proj_uom_get_info_from_database()` second call may free prior `c_str()` pointer |
| 08 | `08-conv-SF02-null-deref-stack-oob` | NULL deref (SEGV) | High | `proj_create_conversion(param_count>0, NULL_params)` crashes |
| 09 | `09-grids-SF01-proj-grid-info-null` | Abort (exception) | Medium | `proj_grid_info(NULL)` throws uncaught `std::logic_error` |
| 10 | `10-grids-SF10-ntv2-destructor-overflow` | Stack overflow | High | Malformed NTv2 with deep parent-child chain → unbounded destructor recursion |
| 11 | `11-singleop-SF01-concatop-stack-overflow` | Stack overflow | High | `ConcatenatedOperation::_exportToWKT/JSON()` recurses without depth limit |

---

## How to Report to PROJ Maintainers

### PROJ's Disclosure Policy

PROJ **does not have a formal SECURITY.md or private vulnerability disclosure channel** as of 2026-04-17. The project accepts bug reports via public GitHub Issues at:

> https://github.com/OSGeo/PROJ/issues

Because all 11 bugs are **denial-of-service only** (no code execution, no memory disclosure), public reporting via GitHub Issues is appropriate. If you believe any issue may have broader security impact in your environment, contact the maintainers privately first via GitHub Discussions or the OSGeo mailing list before opening a public issue.

### Recommended Approach

Given the volume (11 bugs), file them in **two or three grouped issues** to avoid overwhelming the tracker:

**Issue Group A — NULL dereferences (bugs #03, #04, #06, #08, #09):** These share a common fix pattern (add NULL checks at function entry).

**Issue Group B — Unbounded recursion / stack overflows (bugs #01, #02, #10, #11):** These share a common fix pattern (add depth counters).

**Issue Group C — Logic/semantic issues (bugs #05, #07):** Silent data error and dangling pointer.

---

## Issue Template

Use this template for each GitHub issue:

```
**Title:** [Bug] NULL pointer dereference in `FUNCTION_NAME()` when `PARAM` is NULL

**PROJ version:** master (commit 324ed2119011d74665548afe445eacb99afb9753, 2026-04-17)
**OS:** Linux x86_64 (Ubuntu 20.04)
**Build:** ASAN (-fsanitize=address -g -O1)

## Summary
[One-paragraph description from bug_report.md]

## Vulnerable code
[Paste the code snippet from bug_report.md]

## Reproduction
[Paste the compilation and run commands from bug_report.md]

## Observed output
[Paste the ASAN output]

## Suggested fix
[Paste the diff from bug_report.md]
```

---

## Step-by-Step Filing Instructions

1. **Authenticate to GitHub** — log in to your GitHub account.

2. **Open a new issue** at https://github.com/OSGeo/PROJ/issues/new

3. **Fill in the template** using the corresponding `bug_report.md` in each subfolder.

4. **Attach PoC files** — GitHub allows attaching files to issues. Attach the `.c` / `.cpp` PoC and any data files (`.gsb`, `.json`) as `.zip` archives (GitHub blocks executable extensions).

5. **Label** — use labels `bug` and `security` if available (project maintainers control label creation).

6. **Link related issues** — when filing the second and third issue, add "Related to #NNNN" in the description.

---

## Reproduction Environment (for reference in issues)

```
Docker base image: vulagent/proj4-asan:latest (Ubuntu 20.04, clang 10)
PROJ source:       https://github.com/OSGeo/PROJ (commit 324ed2119011d74...)
Build flags:       -fsanitize=address -g -O1
PROJ_DATA:         /out/asan (from OSS-Fuzz proj4 image)
sqlite3:           3.31.1 (Ubuntu 20.04 package)
```

Run all PoCs at once:
```bash
docker run --rm \
  -v /scr2/yiwei/vul-agent/zero-day/1_reported/4-proj-260417:/bugs \
  -v /tmp/PROJ-latest:/src/PROJ-latest:ro \
  -v /tmp/proj4-latest-build:/proj4-latest-build:ro \
  vulagent/proj4-asan:latest bash /bugs/build_all.sh
```
