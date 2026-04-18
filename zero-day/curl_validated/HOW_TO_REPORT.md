# How to Report Vulnerabilities to curl

Validated date: 2026-04-17
Latest tested commit: `70281e3` (curl 8.20.0-DEV)

---

## curl's Security Reporting Policy

curl uses a responsible disclosure model documented at:
https://github.com/curl/curl/blob/master/SECURITY.md

Key points:
- Reports go to the **curl security team** via HackerOne (primary) or email
- The team aims to respond within **7 days**
- Embargo period is typically **14 days** before public disclosure
- curl has a **CVE numbering authority (CNA)** and assigns its own CVEs
- curl has an active **bug bounty program** on HackerOne (paid rewards)

---

## How to Submit via HackerOne (Preferred)

1. Go to: https://hackerone.com/curl
2. Click "Submit a Report"
3. Select severity: Critical / High / Medium / Low
4. Fill in the report form (see template below)
5. Attach PoC files (poc.c), crash output, and build.sh

**Note**: HackerOne is the preferred channel as it enables bounty payment tracking.

---

## Alternative: Email Submission

If HackerOne is unavailable, email:
- **security@haxx.se** — main curl security contact (Daniel Stenberg + team)
- Subject: `[SECURITY] <brief description>`
- Encrypt with PGP if possible (key at https://daniel.haxx.se/mykey.asc)

---

## Report Template

```
Title: <one-line description>

Affected component: lib/vtls/openssl.c (or whichever file)
Affected versions: All versions up to and including 8.20.0-DEV (commit 70281e3)
Severity: HIGH / MEDIUM / LOW
CWE: CWE-XXX

## Summary
<2-3 sentence description of the bug and its impact>

## Steps to Reproduce
1. Build curl with ASAN: ./configure --enable-debug --with-openssl CC=clang CFLAGS="-fsanitize=address -g" && make
2. Compile and run: gcc poc.c -lcurl -o poc && ./poc

## Root Cause
<Explain the exact code path and why it is incorrect>

## Crash Output / Evidence
<Paste ASAN/UBSan output or the exact behavior observed>

## Suggested Fix
<Propose a minimal patch>

## PoC
<Attach poc.c and build.sh>
```

---

## Priority Order for Submission (by severity)

Submit these vulnerabilities in the following order (highest severity first):

### Priority 1 — HIGH (submit first)

**vuln-01** — NULL deref in `EVP_PKEY_copy_parameters()` via unchecked `X509_get_pubkey()`
- File: `lib/vtls/openssl.c:1559`
- Impact: Remote DoS — attacker controls client certificate to trigger SIGSEGV
- CWE-476

**vuln-05** — Heap-UAF in `Curl_ssl_session_export()` via iterator invalidation
- File: `lib/vtls/vtls_scache.c:1214`
- Impact: Heap-use-after-free, potential RCE in applications using ssls export API
- CWE-416
- Requires: `--enable-ssls-export` (available in 8.x)

### Priority 2 — MEDIUM-HIGH

**vuln-06** — Stack buffer overflow (OOB read) in `curl_easy_ssls_import()`
- File: `lib/vtls/vtls_scache.c` → `cf_ssl_scache_peer_init:458`
- Impact: Attacker-controlled `shmac` buffer causes OOB read (info leak / crash)
- CWE-125
- Requires: `--enable-ssls-export`

**vuln-04** — Stack buffer overflow in `populate_fds()` with 5+ sockets
- File: `lib/easy.c` — `wait_or_timeout()` / `populate_fds()`
- Impact: Stack overflow when event loop has >4 concurrent sockets
- CWE-121

### Priority 3 — MEDIUM

**vuln-02** — NULL deref in `EVP_PKEY_id()` via unchecked `SSL_get_privatekey()`
- File: `lib/vtls/openssl.c:1568`
- Impact: DoS in deprecated/ENGINE key path
- CWE-476

**vuln-03** — Heap OOB write in `Curl_ssl_push_certinfo_len()`
- File: `lib/vtls/vtls.c:658`
- Impact: Only DEBUGASSERT guards `certnum` bounds — stripped in release
- CWE-787

**vuln-07** — NULL deref in `curl_easy_ssls_import()` with `sdata=NULL, sdata_len>0`
- File: `lib/vtls/vtls_scache.c:1097` + `vtls_spack.c:245`
- Impact: Crash via null pointer arithmetic in `Curl_ssl_session_unpack()`
- CWE-476
- Requires: `--enable-ssls-export`

**vuln-08** — Stack overflow via deeply nested `curl_mime_subparts()`
- File: `lib/mime.c:684` — `readback_bytes` recursive chain
- Impact: Stack exhaustion with ~9500 levels (no depth limit)
- CWE-674

**vuln-09** — Signed integer overflow in `encoder_base64_size()`
- File: `lib/mime.c:427`
- Impact: Wrong `Content-Length` reported to server (UB, negative value)
- CWE-190

### Priority 4 — LOW

**vuln-10** — `ws_send_raw_blocking()` never sets `*pnwritten`
- File: `lib/ws.c` — `ws_send_raw()` blocking path
- Impact: API contract violation — `curl_ws_send()` returns `*sent=0` on success
- CWE-252

---

## What to Include in Each Report

For each vulnerability, include:

1. **poc.c** — standalone proof-of-concept (from the vuln-XX folder)
2. **build.sh** — reproducible build and run script (from the vuln-XX folder)
3. **Crash output** — ASAN/UBSan report (from report.md validation section)
4. **Source diff / suggested fix** — minimal patch
5. **Affected curl version range** — "all versions containing commit X"
6. **Environment**: OS, compiler version, OpenSSL version

---

## Suggested Fixes Summary

| Vuln | File | Fix |
|------|------|-----|
| vuln-01 | `lib/vtls/openssl.c:1559` | Add `if(pktmp)` guard before `EVP_PKEY_copy_parameters` |
| vuln-02 | `lib/vtls/openssl.c:1568` | Add `if(priv_key)` guard before `EVP_PKEY_id` |
| vuln-03 | `lib/vtls/vtls.c:658` | Replace `DEBUGASSERT(certnum < ci->num_of_certs)` with a runtime check returning `CURLE_BAD_FUNCTION_ARGUMENT` |
| vuln-04 | `lib/easy.c` | Increase `fds[4]` to dynamic allocation, or add `DEBUGASSERT(numfds <= 4)` and a MAX_FDS check in `populate_fds()` |
| vuln-05 | `lib/vtls/vtls_scache.c` | Snapshot the iterator list before invoking callback, or snapshot `n = Curl_node_next(n)` before calling `export_fn` |
| vuln-06 | `lib/vtls/vtls_scache.c` | Validate actual buffer size vs `shmac_len` before `memcpy` in `cf_ssl_scache_peer_init` |
| vuln-07 | `lib/vtls/vtls_scache.c:1097` | Add `if(!sdata && sdata_len) return CURLE_BAD_FUNCTION_ARGUMENT;` before `Curl_ssl_session_unpack` |
| vuln-08 | `lib/mime.c` | Add recursion depth counter to `readback_part()`; abort/return error at limit (e.g. 100) |
| vuln-09 | `lib/mime.c:427` | Check for overflow before multiplication: `if(size > (curl_off_t)CURL_OFF_T_MAX / 4) return -1;` |
| vuln-10 | `lib/ws.c` | After `ws_send_raw_blocking()` succeeds, add `if(!result && pnwritten) *pnwritten = buflen;` |

---

## curl Bounty Program Notes

- curl's HackerOne program is at https://hackerone.com/curl
- Bounties are typically in the $100–$500 range for medium severity bugs
- Critical/high bugs may receive higher bounties
- curl team is responsive and professional — report honestly and completely
- Do NOT report to NVD/MITRE directly; curl is a CNA and handles its own CVEs
