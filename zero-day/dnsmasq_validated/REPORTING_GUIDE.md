# Reporting Guide: dnsmasq Heap Buffer Overflow (DS Record)

This guide covers how to responsibly disclose the `log_query()` heap buffer overflow
to the dnsmasq maintainer, following the project's established security disclosure
practices.

---

## Who Maintains dnsmasq

**Simon Kelley** is the sole maintainer of dnsmasq. He handles all bug reports,
releases, and security disclosures personally.

- **Email:** simon@thekelleys.org.uk
- **Project site:** https://thekelleys.org.uk/dnsmasq/doc.html
- **Source (official gitweb):** https://thekelleys.org.uk/gitweb/?p=dnsmasq.git
- **Mailing list (public):** dnsmasq-discuss@lists.thekelleys.org.uk

There is no dedicated `security@` alias; use the personal email above.

---

## Disclosure Policy (Inferred from Precedent)

dnsmasq has no formally published security policy document, but historical CVE
disclosures establish a clear precedent for **private coordinated disclosure**:

- **2017 (CVE-2017-14491–14496, Google):** Google Security Team privately coordinated
  with Simon Kelley and gave major Linux distributions advance warning under embargo
  before public release.
- **2021 (DNSpooq CVEs):** Red Hat coordinated an embargo period with all major
  distributions before public announcement.
- **2024 (KeyTrap, CVE-2023-50387/50868):** DNSSEC vulnerabilities were embargoed
  to allow vendors testing time before release.

**Standard expectations:**
- Report privately first; allow time for a fix before public disclosure.
- No fixed embargo timeline is published — negotiate with Simon directly.
  A 90-day window is a widely accepted industry default if no agreement is made.
- Simon typically responds promptly for genuine security issues.

---

## Encrypted Communication (PGP)

Simon Kelley provides a GPG key for secure email. Key details:

- **Fingerprint:** E19135A2
- **Available from:** Debian keyserver (`hkps://keyserver.ubuntu.com`) and
  https://thekelleys.org.uk/
- Fetch and import:
  ```sh
  gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys E19135A2
  ```

Encryption is **recommended** for this issue given its severity (High, network-reachable
heap overflow). If PGP setup is inconvenient, an unencrypted email is still appropriate —
the private channel is more important than encryption for initial contact.

---

## CVE Numbers

dnsmasq has an extensive CVE history (CVE-2017-14491 series, CVE-2020-25681 series,
etc.). CVEs are assigned by MITRE or Linux-distro CNAs — dnsmasq does not self-assign.

**To request a CVE:**
1. After Simon acknowledges the issue (or after the fix is released), request a CVE
   via the MITRE CVE Request form: https://cveform.mitre.org/
2. Alternatively, Red Hat's Security Team (secalert@redhat.com) has acted as a CNA
   coordinator for past dnsmasq CVEs if coordination with distributions is needed.

Do **not** request a CVE before the maintainer is notified — this would constitute
public disclosure and break the embargo.

---

## Step-by-Step Reporting Instructions

### 1. Prepare Your Email

**To:** simon@thekelleys.org.uk  
**Subject:** `[SECURITY] Heap buffer overflow in log_query() via DS record (DNSSEC)`

**Attach** (or inline) the following files from this directory:
- `01-log_query-ds-heap-overflow/poc_reproducer.c` — standalone reproducer
- `01-log_query-ds-heap-overflow/ISSUE.md` — full bug report
- `01-log_query-ds-heap-overflow/asan_output_validated.txt` — confirmed crash output

**Body (template):**

```
Dear Simon,
I'm writing to report a heap buffer overflow in dnsmasq's log_query() function that is reachable from the network when DNSSEC validation and query logging are both enabled.

Summary:
  File:    src/cache.c, log_query(), line 2358
  Bug:     sprintf() writes 58 bytes into a 46-byte heap buffer (daemon->addrbuff)
  Trigger: DS record with key_tag=65535, algorithm=255, digest_type=255
           Both algorithm 255 and digest_type 255 are IANA-unassigned, causing
           the "(not supported)" branch in dnssec.c:1104 to fire.
  Impact:  Heap write overflow (12 bytes); DoS / potential heap metadata corruption
  CVSS 3.1: 7.5 (High) — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

Reproduced on dnsmasq v2.93test9 (latest as of 2026-04-18) with clang ASAN.
Confirmed still present in upstream HEAD 2d0e0c7a (thekelleys.org.uk gitweb).

I have attached a standalone reproducer and a detailed bug report.

Thank you for maintaining this project!
```

### 2. Send the Email

If using GPG encryption:
```sh
gpg --armor --encrypt --recipient E19135A2 \
    --sign report.txt > report.txt.asc
```
Then attach `report.txt.asc` to your email.

### 3. Follow Up

- If no response within **7 days**, send a follow-up to the same address.
- If no response within **14 days**, consider CC-ing the dnsmasq-discuss mailing list
  with a note that you attempted private disclosure.
- Industry-standard embargo maximum: **90 days** from initial report.

### 4. After the Fix

Once Simon releases a patched version:
1. Request a CVE from MITRE: https://cveform.mitre.org/
2. Publish your findings (this bug report) publicly.
3. Notify downstream packagers (Debian, Ubuntu, Red Hat, Pi-hole, AdGuard)
   if Simon has not already done so.

---

## Do NOT Do

- Do **not** open a GitHub issue (GitHub repos are community mirrors, not official).
- Do **not** post to the dnsmasq-discuss mailing list before the fix is released —
  it is a public, archived list.
- Do **not** request a CVE before Simon has been notified.

---

## Files in This Report

```
dnsmasq_validated/
├── REPORTING_GUIDE.md                        ← this file
└── 01-log_query-ds-heap-overflow/
    ├── poc_reproducer.c                       ← standalone ASAN reproducer
    ├── build.sh                               ← one-step build + run
    ├── ISSUE.md                               ← full technical bug report
    └── asan_output_validated.txt              ← Docker-validated crash output
```
