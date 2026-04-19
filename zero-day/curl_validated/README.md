# curl Zero-Day Findings

**Date**: 2026-04-18  
**Source**: Automated hypothesis generation + manual validation against `vulagent/curl:latest`  
**Total hypotheses analyzed**: 128 across 10 file scanning sessions  
**Confirmed vulnerabilities**: 10  
**False positives**: 118  

---

## Confirmed Vulnerabilities

| # | Folder | Severity | Component | Bug | Build Req | CWE |
|---|--------|----------|-----------|-----|-----------|-----|
| 1 | `vuln-01-tls-null-deref-client-cert` | **HIGH** | `lib/vtls/openssl.c:1559` | NULL deref in `EVP_PKEY_copy_parameters()` — `X509_get_pubkey()` unchecked in `client_cert()` | any | CWE-476 |
| 2 | `vuln-02-tls-privkey-null-deref` | MEDIUM | `lib/vtls/openssl.c:1568` | NULL deref in `EVP_PKEY_id()` — `SSL_get_privatekey()` unchecked (ENGINE/deprecated path) | deprecated path | CWE-476 |
| 3 | `vuln-03-certinfo-oob-write` | **HIGH** | `lib/vtls/vtls.c:658` | Heap OOB write in `Curl_ssl_push_certinfo_len()` — sole guard is `DEBUGASSERT`, no-op in every release build; all 5 TLS backends funnel through this unguarded write; certnum derived from server cert chain | `CURLOPT_CERTINFO=1` | CWE-787 |
| 4 | `vuln-04-easy-stack-overflow` | MEDIUM | `lib/easy.c` | Stack buffer overflow in `populate_fds()` — `fds[4]` overflows with 5+ concurrent sockets via `curl_easy_perform_ev()` | `DEBUGBUILD` | CWE-121 |
| 5 | `vuln-05-ssls-export-uaf` | **HIGH** | `lib/vtls/vtls_scache.c:1214` | Heap-UAF in `Curl_ssl_session_export()` — iterator invalidated when callback calls `curl_easy_ssls_import` during export | `USE_SSLS_EXPORT` | CWE-416 |
| 6 | `vuln-06-ssls-import-oob-read` | MEDIUM-HIGH | `lib/vtls/vtls_scache.c` | OOB read in `curl_easy_ssls_import()` — `shmac_len` validates size but buffer can be smaller; reads 22B past end | `USE_SSLS_EXPORT` | CWE-125 |
| 7 | `vuln-07-ssls-import-null-deref` | MEDIUM | `lib/vtls/vtls_scache.c` | NULL deref in `Curl_ssl_session_import()` — `sdata=NULL` with `sdata_len>0` reaches `spack_dec8(*NULL)` in release | `USE_SSLS_EXPORT` | CWE-476 |
| 8 | `vuln-08-mime-recursion-stack-overflow` | MEDIUM | `lib/mime.c:684` | Stack overflow via unbounded recursion — ~9500 nested `curl_mime_subparts()` exhausts 8MB stack | any | CWE-674 |
| 9 | `vuln-09-mime-base64-int-overflow` | LOW-MEDIUM | `lib/mime.c:427` | Signed integer overflow in `encoder_base64_size()` — `datasize=LLONG_MAX` wraps to negative, corrupts Content-Length | any | CWE-190 |
| 10 | `vuln-10-ws-send-missing-nwritten` | LOW | `lib/ws.c` | API contract violation in `ws_send_raw_blocking()` — `*pnwritten` never written on success, callers get `sent=0` | any | CWE-252 |

---

## Reporting Split

curl's current policy says several categories are usually not security issues:
- API misuse
- debug-only paths
- experimental features that are off by default
- NULL dereferences and plain crashes
- busy-loops that eventually end

Based on that policy, the practical split is:

### Private security reports

- `vuln-05-ssls-export-uaf`
  - prepared in [ISSUE.md](/scr2/yiwei/vul-agent/zero-day/curl_validated/vuln-05-ssls-export-uaf/ISSUE.md)
  - note: policy risk remains because SSLS export/import is experimental and off by default
- `vuln-08-mime-recursion-stack-overflow`
  - prepared in [ISSUE.md](/scr2/yiwei/vul-agent/zero-day/curl_validated/vuln-08-mime-recursion-stack-overflow/ISSUE.md)
  - best remaining private-report candidate
- `vuln-03-certinfo-oob-write`
  - prepared in [ISSUE.md](/scr2/yiwei/vul-agent/zero-day/curl_validated/vuln-03-certinfo-oob-write/ISSUE.md)

### Public issues

- `vuln-01-tls-null-deref-client-cert`
  - prepared in [PUBLIC_ISSUE.md](/scr2/yiwei/vul-agent/zero-day/curl_validated/vuln-01-tls-null-deref-client-cert/PUBLIC_ISSUE.md)
- `vuln-02-tls-privkey-null-deref`
  - prepared in [PUBLIC_ISSUE.md](/scr2/yiwei/vul-agent/zero-day/curl_validated/vuln-02-tls-privkey-null-deref/PUBLIC_ISSUE.md)
- `vuln-04-easy-stack-overflow`
  - prepared in [PUBLIC_ISSUE.md](/scr2/yiwei/vul-agent/zero-day/curl_validated/vuln-04-easy-stack-overflow/PUBLIC_ISSUE.md)
- `vuln-06-ssls-import-oob-read`
  - prepared in [PUBLIC_ISSUE.md](/scr2/yiwei/vul-agent/zero-day/curl_validated/vuln-06-ssls-import-oob-read/PUBLIC_ISSUE.md)
  - this one is memory-unsafe, but curl can plausibly classify it as API misuse and also experimental-feature behavior
- `vuln-07-ssls-import-null-deref`
  - prepared in [PUBLIC_ISSUE.md](/scr2/yiwei/vul-agent/zero-day/curl_validated/vuln-07-ssls-import-null-deref/PUBLIC_ISSUE.md)
- `vuln-09-mime-base64-int-overflow`
  - prepared in [PUBLIC_ISSUE.md](/scr2/yiwei/vul-agent/zero-day/curl_validated/vuln-09-mime-base64-int-overflow/PUBLIC_ISSUE.md)
- `vuln-10-ws-send-missing-nwritten`
  - prepared in [PUBLIC_ISSUE.md](/scr2/yiwei/vul-agent/zero-day/curl_validated/vuln-10-ws-send-missing-nwritten/PUBLIC_ISSUE.md)
