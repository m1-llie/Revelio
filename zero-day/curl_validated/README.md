# curl Zero-Day Findings

**Date**: 2026-04-17  
**Source**: Automated hypothesis generation + manual validation against `vulagent/curl:latest`  
**Total hypotheses analyzed**: 128 across 10 scan sessions  
**Confirmed vulnerabilities**: 10  
**False positives**: 118  

---

## Confirmed Vulnerabilities

| # | Folder | Severity | Component | Bug | Build Req | CWE |
|---|--------|----------|-----------|-----|-----------|-----|
| 1 | `vuln-01-tls-null-deref-client-cert` | **HIGH** | `lib/vtls/openssl.c:1559` | NULL deref in `EVP_PKEY_copy_parameters()` — `X509_get_pubkey()` unchecked in `client_cert()` | any | CWE-476 |
| 2 | `vuln-02-tls-privkey-null-deref` | MEDIUM | `lib/vtls/openssl.c:1568` | NULL deref in `EVP_PKEY_id()` — `SSL_get_privatekey()` unchecked (ENGINE/deprecated path) | deprecated path | CWE-476 |
| 3 | `vuln-03-certinfo-oob-write` | MEDIUM | `lib/vtls/vtls.c:658` | Heap OOB write in `Curl_ssl_push_certinfo_len()` — `certnum` bounds only via `DEBUGASSERT`, stripped in release | release build | CWE-787 |
| 4 | `vuln-04-easy-stack-overflow` | MEDIUM | `lib/easy.c` | Stack buffer overflow in `populate_fds()` — `fds[4]` overflows with 5+ concurrent sockets via `curl_easy_perform_ev()` | `DEBUGBUILD` | CWE-121 |
| 5 | `vuln-05-ssls-export-uaf` | **HIGH** | `lib/vtls/vtls_scache.c:1214` | Heap-UAF in `Curl_ssl_session_export()` — iterator invalidated when callback calls `curl_easy_ssls_import` during export | `USE_SSLS_EXPORT` | CWE-416 |
| 6 | `vuln-06-ssls-import-oob-read` | MEDIUM-HIGH | `lib/vtls/vtls_scache.c` | OOB read in `curl_easy_ssls_import()` — `shmac_len` validates size but buffer can be smaller; reads 22B past end | `USE_SSLS_EXPORT` | CWE-125 |
| 7 | `vuln-07-ssls-import-null-deref` | MEDIUM | `lib/vtls/vtls_scache.c` | NULL deref in `Curl_ssl_session_import()` — `sdata=NULL` with `sdata_len>0` reaches `spack_dec8(*NULL)` in release | `USE_SSLS_EXPORT` | CWE-476 |
| 8 | `vuln-08-mime-recursion-stack-overflow` | MEDIUM | `lib/mime.c:684` | Stack overflow via unbounded recursion — ~9500 nested `curl_mime_subparts()` exhausts 8MB stack | any | CWE-674 |
| 9 | `vuln-09-mime-base64-int-overflow` | LOW-MEDIUM | `lib/mime.c:427` | Signed integer overflow in `encoder_base64_size()` — `datasize=LLONG_MAX` wraps to negative, corrupts Content-Length | any | CWE-190 |
| 10 | `vuln-10-ws-send-missing-nwritten` | LOW | `lib/ws.c` | API contract violation in `ws_send_raw_blocking()` — `*pnwritten` never written on success, callers get `sent=0` | any | CWE-252 |

---

## Folder Structure

```
curl/
├── README.md                              ← this file
│
├── vuln-01-tls-null-deref-client-cert/    HIGH   openssl.c EVP_PKEY_copy_parameters NULL deref
│   ├── poc.c
│   └── report.md
│
├── vuln-02-tls-privkey-null-deref/        MEDIUM openssl.c EVP_PKEY_id NULL deref
│   ├── poc.c
│   └── report.md
│
├── vuln-03-certinfo-oob-write/            MEDIUM vtls.c certnum OOB write (release build)
│   ├── poc.c
│   └── report.md
│
├── vuln-04-easy-stack-overflow/           MEDIUM easy.c populate_fds stack overflow (DEBUGBUILD)
│   ├── poc.c
│   └── report.md
│
├── vuln-05-ssls-export-uaf/               HIGH   vtls_scache.c session export heap-UAF
│   ├── poc.c
│   └── report.md
│
├── vuln-06-ssls-import-oob-read/          MED-HIGH vtls_scache.c shmac OOB read
│   ├── poc.c
│   └── report.md
│
├── vuln-07-ssls-import-null-deref/        MEDIUM vtls_scache.c sdata NULL deref
│   ├── poc.c
│   └── report.md
│
├── vuln-08-mime-recursion-stack-overflow/ MEDIUM mime.c unbounded recursion → stack overflow
│   ├── poc.c
│   └── report.md
│
├── vuln-09-mime-base64-int-overflow/      LOW-MED mime.c encoder_base64_size signed overflow
│   ├── poc.c
│   └── report.md
│
├── vuln-10-ws-send-missing-nwritten/      LOW    ws.c ws_send_raw_blocking missing *pnwritten
│   └── report.md
```

---

## Reporting Priority

1. **Report immediately** (no special build flags, ASAN-confirmed crash):
   - `vuln-01` — malformed client cert crashes any TLS connection using `CURLOPT_SSLCERT`
   - `vuln-08` — attacker-supplied MIME structure causes DoS via stack overflow

2. **Report with note on build flags**:
   - `vuln-05` — HIGH severity UAF but requires `USE_SSLS_EXPORT` (new API, may not be widely deployed)
   - `vuln-06`, `vuln-07` — same `USE_SSLS_EXPORT` gate

3. **Report as hardening / defense-in-depth**:
   - `vuln-03` — DEBUGASSERT-only bounds check should be a runtime check
   - `vuln-04` — fixed-size array in debug-only API path
   - `vuln-09` — UBSan-detected overflow, no direct memory corruption
   - `vuln-10` — low severity API contract issue
