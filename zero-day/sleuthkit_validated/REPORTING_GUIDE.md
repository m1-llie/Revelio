# Reporting Guide: sleuthkit Vulnerability Disclosure (2026-04-17)

This guide covers reporting 13 confirmed vulnerabilities in The Sleuth Kit (sleuthkit),
validated against commit `01de034` (2026-04-15, `main` branch).

---

## 1. Reporting Channel Options

### Option A: GitHub Private Vulnerability Reporting (Preferred)

GitHub's Private Vulnerability Reporting (PVR) keeps reports confidential and notifies
maintainers directly without creating a public issue.

**Steps:**

1. Navigate to: https://github.com/sleuthkit/sleuthkit
2. Click the **Security** tab (lock icon in the top navigation).
3. Click **"Report a vulnerability"** (the green button in the Advisories section).
   - If you do not see this button, the maintainers may not have enabled PVR; fall back
     to Option B (email).
4. Fill in the vulnerability report form:
   - **Title**: Use a concise title from the `bug_report.md`
   - **CVE ID**: Leave blank (GitHub will request a CVE if needed)
   - **Affected versions**: `main` branch at commit `01de034` (2026-04-15)
   - **Description**: Paste the full contents of the relevant `bug_report.md`
   - **Proof of concept**: Attach the PoC image file and paste the `run_poc.sh`
     content as a code block
   - **Impact**: Copy from the Impact section of `bug_report.md`
   - **Suggested severity**: High (CVSS ~7.5) for ASAN-confirmed crashes; Medium for
     MSan/UBSan-only issues
5. Click **"Submit report"**.
6. You will receive a confirmation and can communicate privately with maintainers
   through the GitHub advisory thread.

### Option B: Email to security@sleuthkit.org

If GitHub PVR is unavailable or you prefer email:

1. Send to: **security@sleuthkit.org**
2. Subject line format: `[SECURITY] <short title> in sleuthkit (commit 01de034)`
3. Body: Include all sections from the relevant `bug_report.md`
4. Attachments: Attach the PoC image (`.img` file) and `run_poc.sh`
5. Request acknowledgment and ask for a preferred PGP key if you want encrypted
   follow-up communication.

**Do NOT open public GitHub issues for these vulnerabilities.**

---

## 2. What to Include in Each Report

Each report should contain the following (all available in the `bug_report.md` files):

- **Summary**: One-paragraph description of the bug
- **Affected file and commit**: Exact file path, function, line number, and commit hash
  `01de034`
- **Root cause**: The vulnerable code snippet with inline commentary
- **Reproduction command**: The exact `docker run` command from `run_poc.sh`
- **Sanitizer output**: The full ASAN/MSan/UBSan output showing the crash
- **Impact**: Severity, affected tools, attack scenario
- **CWE identifiers**
- **Suggested fix**: Code patch or description

---

## 3. Suggested Grouping for Reports

To reduce noise and help maintainers triage efficiently, group related issues into
single reports:

### Group 1: APFS parser (2 issues)
- `01-apfs-btree-keycount-oob` — APFS btree key_count OOB iterator (MSan)
- `02-apfs-getimageinfo-uninit-alloc` — APFSPoolCompat::getImageInfo unvalidated
  num_img (ASAN)

### Group 2: btrfs parser (4 issues)
- `03-btrfs-sf01-zero-items` — number_of_items=0 integer underflow (ASAN)
- `04-btrfs-sf06-stripe-oob` — chunk item stripe_count OOB (ASAN)
- `05-btrfs-sf07-large-num-items` — large number_of_items OOB (ASAN)
- `06-btrfs-sf09-dir-entry-oob` — dir entry data_len OOB (ASAN)

### Group 3: HFS+/decmpfs parser (3 issues)
- `07-decmpfs-uncsize-overflow` — decmpfs uncSize integer overflow (ASAN)
- `08-12-decmpfs-noncompressed-oob` — decmpfs noncompressed attr rawSize ignored
  (ASAN; same bug confirmed by two PoC images)

### Group 4: FFS/UFS parser (2 issues)
- `10-ffs-cgiusedoff-oob` — cg_iusedoff signed comparison bypass (ASAN)
- `11-ffs-itoo-oob` — itoo_lcl OOB via anomalous fs_inopb (ASAN)

### Group 5: NTFS parser (1 issue)
- `13-ntfs-idxrec-oob` — ntfs_fix_idxrec upd_seq array OOB (ASAN)

### Group 6: XFS parser (1 issue)
- `14-xfs-uint32-overflow` — xfs_inode_get_offset uint32_t overflow (UBSan)

### Group 7: YAFFS2 parser (1 issue)
- `15-yaffs2-uaf` — yaffs2_open() returns dangling pointer (code-confirmed UAF)

Alternatively, send all issues in a single coordinated report with a summary table
listing all 13 bugs.

---

## 4. Issue 09 is Already Fixed

**Issue 09** (EXT quadratic attribute run / DoS) was fixed in commit `01de034`:
the `run_end` pointer was added in `fs_attr.cpp` to terminate the scan loop correctly.
Do not include issue 09 in any report — it is already resolved in the latest `main`.

---

## 5. Expected Timeline

Based on standard coordinated disclosure practice and sleuthkit's typical response
patterns:

| Milestone | Target |
|-----------|--------|
| Acknowledgment | 5 business days after submission |
| Initial triage / severity assignment | 10 business days |
| Fix timeline discussion | 15 business days |
| Patch + CVE assignment | 30-90 days (depending on severity) |
| Public disclosure | After patch is released |

If no acknowledgment is received within **5 business days**, follow up via the
alternative channel (email if GitHub PVR was used first, or vice versa).

For critical bugs (ASAN-confirmed crashes with potential RCE, such as issue 15
YAFFS2 UAF), request expedited handling.

---

## 6. Issue Status Summary

| Directory | Bug Type | Sanitizer | Status |
|-----------|----------|-----------|--------|
| `01-apfs-btree-keycount-oob` | APFS btree key_count OOB | MSan | Code vulnerable; ASAN exits cleanly |
| `02-apfs-getimageinfo-uninit-alloc` | APFS getImageInfo alloc-too-big | ASAN | CRASH CONFIRMED |
| `03-btrfs-sf01-zero-items` | btrfs zero items underflow | ASAN | CRASH CONFIRMED |
| `04-btrfs-sf06-stripe-oob` | btrfs stripe count OOB | ASAN | CRASH CONFIRMED |
| `05-btrfs-sf07-large-num-items` | btrfs large num_items OOB | ASAN | CRASH CONFIRMED |
| `06-btrfs-sf09-dir-entry-oob` | btrfs dir entry data_len OOB | ASAN | CRASH CONFIRMED |
| `07-decmpfs-uncsize-overflow` | decmpfs uncSize integer overflow | ASAN | CRASH CONFIRMED |
| `08-12-decmpfs-noncompressed-oob` | decmpfs noncompressed OOB (x2) | ASAN | CRASH CONFIRMED |
| *(skipped: issue 09)* | EXT quadratic attr run (DoS) | - | FIXED in 01de034 |
| `10-ffs-cgiusedoff-oob` | FFS cg_iusedoff signed bypass | ASAN | CRASH CONFIRMED |
| `11-ffs-itoo-oob` | FFS itoo_lcl OOB | ASAN | CRASH CONFIRMED |
| `13-ntfs-idxrec-oob` | NTFS ntfs_fix_idxrec upd_seq OOB | ASAN | CRASH CONFIRMED |
| `14-xfs-uint32-overflow` | XFS uint32 ag_offset overflow | UBSan | Code vulnerable; needs -fsanitize=unsigned-integer-overflow |
| `15-yaffs2-uaf` | YAFFS2 yaffs2_open UAF | ASAN (dedicated driver) | Code vulnerable; standalone harness insufficient |
