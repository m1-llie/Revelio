# Reporting Guide: SleuthKit Vulnerability Disclosure (updated 2026-04-19)

This guide covers reporting confirmed vulnerabilities in The Sleuth Kit (SleuthKit).

**Validation summary:**
- Target release: **SleuthKit 4.15.0** (tag `sleuthkit-4.15.0`, commit `01de034`, released 2026-04-15)
- Docker image: `vulagent/sleuthkit:4.15.0` (built from the 4.15.0 release tarball with ASAN fuzzers in `/out/asan415/`)

---

## 1. Reporting Channel

Per SleuthKit's `SECURITY.md`, **do not open public GitHub issues** for security bugs.

### GitHub Private Vulnerability Reporting (Preferred)

1. Go to: https://github.com/sleuthkit/sleuthkit/security/advisories/new
2. Fill in the form using the content from each issue's `ISSUE.md`:
   - **Title**: copy the plain first line of `ISSUE.md`
   - **CVE**: leave blank (GitHub will request a CVE on acceptance)
   - **Affected versions**: `<= 4.15.0` (commit `01de034`)
   - **Description**: paste full `ISSUE.md` content (Summary → Remediation)
   - **PoC**: attach the `.img` file; paste the Docker `docker run` block from `ISSUE.md`
   - **Severity**: High (ASAN-confirmed heap-buffer-overflow)
3. Attach each PoC image file

### Email (fallback)

Send to: **security@sleuthkit.org**  
Subject: `[SECURITY] <short title> in SleuthKit 4.15.0 (01de034)`  
Attach: PoC `.img` file

---

## 2. ASAN-Confirmed Crashes on SleuthKit 4.15.0

| Directory | Bug Type | Sanitizer | Status on 4.15.0 | Files |
|-----------|----------|-----------|------------------|-------|
| `10-ffs-cgiusedoff-oob` | FFS cg_iusedoff signed bypass OOB | ASAN | **CRASH CONFIRMED** | `ISSUE.md`, `bug_report.md`, `ffs_cgiusedoff_oob_read.img` |
| `11-ffs-itoo-oob` | FFS itoo_lcl OOB (anomalous fs_inopb) | ASAN | **CRASH CONFIRMED** | `ISSUE.md`, `bug_report.md`, `ffs_itoo_oob_write.img` |
| `13-ntfs-idxrec-oob` | NTFS ntfs_fix_idxrec upd_seq OOB | ASAN | **CRASH CONFIRMED** | `ISSUE.md`, `bug_report.md`, `ntfs_idxrec_oob.img` |

**Suggested grouping**: Submit as a single coordinated advisory or two separate advisories:
- **Advisory A**: issues 10 + 11 (both FFS/UFS1)
- **Advisory B**: issue 13 (NTFS)

---

## 3. Not Triggered / Not Applicable on 4.15.0

### Fixed in 4.15.0

| Directory | Bug Type | Notes |
|-----------|----------|-------|
| `02-apfs-getimageinfo-uninit-alloc` | APFS getImageInfo alloc-too-big | PoC does not crash 4.15.0; release notes mention APFS bounds-check fix ("Fix bounds checks. Reported by Mobasi") |

### Not in 4.15.0 Release (filesystem not included)

The 4.15.0 release tarball does not include `btrfs.cpp` or `xfs.cpp`. These issues exist in the `develop-4.14` branch source but are not reachable via the official release:

| Directory | Bug Type | Notes |
|-----------|----------|-------|
| `03-btrfs-sf01-zero-items` | btrfs zero items underflow | No btrfs support in 4.15.0 release |
| `04-btrfs-sf06-stripe-oob` | btrfs stripe_count OOB | No btrfs support in 4.15.0 release |
| `05-btrfs-sf07-large-num-items` | btrfs large number_of_items OOB | No btrfs support in 4.15.0 release |
| `06-btrfs-sf09-dir-entry-oob` | btrfs dir entry data_len OOB | No btrfs support in 4.15.0 release |
| `14-xfs-uint32-overflow` | XFS uint32 ag_offset overflow | No XFS support in 4.15.0 release |

### Code Present but PoC Not Triggered on 4.15.0

| Directory | Bug Type | Sanitizer | Notes |
|-----------|----------|-----------|-------|
| `01-apfs-btree-keycount-oob` | APFS btree key_count OOB | MSan-only | Requires MSan build; not confirmed with ASAN |
| `07-decmpfs-uncsize-overflow` | decmpfs uncSize integer overflow | ASAN | Code path not reached by original PoC on 4.15.0 |
| `08-12-decmpfs-noncompressed-oob` | decmpfs noncompressed OOB | ASAN | Code path not reached by original PoC on 4.15.0 |
| `15-yaffs2-uaf` | YAFFS2 yaffs2_open UAF | ASAN | Standalone harness insufficient to trigger |

---

## 4. Expected Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgment | 5 business days |
| Initial triage / severity | 10 business days |
| Fix timeline discussion | 15 business days |
| Patch + CVE assignment | 30–90 days |
| Public disclosure | After patch release |

---

## 5. Docker Image Reference

```
vulagent/sleuthkit:4.15.0   # 4.15.0 release (commit 01de034) — used for final validation
                             # ASAN fuzzers at /out/asan415/
```

Fuzzers available in `/out/asan415/`:
- `fls_ffs_fuzzer` — FFS/UFS (issues 10, 11)
- `fls_ntfs_fuzzer` — NTFS (issue 13)
- `fls_apfs_fuzzer` — APFS (issue 02)
- `fls_hfs_fuzzer` — HFS+
- `fls_ext_fuzzer` — ext2/3/4
- `fls_yaffs_fuzzer` — YAFFS2 (issue 15)
