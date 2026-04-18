# OpenSSL 4.1.0-dev Vulnerability Confirmation — Summary

**Date:** 2026-04-17  
**Target:** OpenSSL master branch, commit `04623f1`  
**Source:** `https://github.com/openssl/openssl` (cloned 2026-04-17)  
**Build:** ASAN + UBSAN (`clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1`)  
**Confirmed crashes:** **14** across 6 modules

---

## Confirmed Vulnerabilities

### Module 1: `crypto/pkcs7/pk7_doit.c` — 7 Confirmed Crashes

| Bug ID | Function | ASAN Type | Crash Site |
|--------|----------|-----------|------------|
| PK-TYPE-1 | `PKCS7_dataInit` | heap-buffer-overflow READ 8 | `pk7_doit.c:271` |
| PK-TYPE-1b | `PKCS7_dataInit` | heap-buffer-overflow READ 8 | `pk7_doit.c:272` |
| PK-TYPE-2 | `PKCS7_dataInit` | UBSAN null-member + SEGV | `pk7_doit.c:286` |
| PK-TYPE-3 | `PKCS7_dataFinal` | heap-buffer-overflow READ 8 | `pk7_doit.c:804` |
| PK-TYPE-4 | `PKCS7_dataVerify` | heap-buffer-overflow READ 8 | `pk7_doit.c` |
| PK-NEGIDX | `PKCS7_get_issuer_and_serial` | UBSAN null-member + SEGV | `pk7_doit.c:1177` |
| PK-ENCDAT | `PKCS7_dataInit` | UBSAN null-member + SEGV | `pk7_doit.c:286` |

**Root cause:** `PKCS7_dataInit/Final/Verify` dispatch on `p7->type` OID without
validating that `p7->d` matches the declared type. This is the same systemic
type-confusion root cause that was present in OpenSSL 3.3 — **unfixed in 4.1.0-dev**.

Reports: `01-pkcs7-type-confusion/`, `02-pkcs7-negidx-encdat/`

---

### Module 2: `crypto/evp/ctrl_params_translate.c` — 2 Confirmed Crashes

| Bug ID | Function | ASAN Type | Crash Site |
|--------|----------|-----------|------------|
| EVP-RSA-PAD | `fix_rsa_padding_mode` | UBSAN null write + SEGV | `ctrl_params_translate.c:1363` |
| EVP-PSS-SALT | `fix_rsa_pss_saltlen` | UBSAN null write + SEGV | `ctrl_params_translate.c:1443` |

**Root cause:** `orig_p2` is stored from caller's `p2 = NULL` and then
unconditionally written through in POST phase without NULL check.

Report: `03-evp-null-write/`

---

### Module 3: `ssl/ssl_lib.c` — 2 Confirmed Crashes

| Bug ID | Function | ASAN Type | Crash Site |
|--------|----------|-----------|------------|
| SSL-DANE-OOB | `dane_tlsa_add` | stack-buffer-overflow READ 256 | `ssl_lib.c:328` |
| SSL-CERT-TYPE | `validate_cert_type` | stack-buffer-overflow READ 1 | `ssl_lib.c:8389` |

Report: `04-ssl-oob-reads/`

---

### Module 4: `crypto/ec/ecp_nistz256.c` — 1 Confirmed Crash

| Bug ID | Function | ASAN Type | Crash Site |
|--------|----------|-----------|------------|
| EC-NULL-SCALAR | `ecp_nistz256_windowed_mul` | UBSAN null-member + SEGV | `ecp_nistz256.c:637` |

Report: `05-ec-null-scalar/`

---

### Module 5: `ssl/statem/statem_srvr.c` — 1 Confirmed Crash

| Bug ID | Function | ASAN Type | Crash Site |
|--------|----------|-----------|------------|
| ALPN-OVERREAD | `tls_handle_alpn` | heap-buffer-overflow READ 255 | `statem_srvr.c:2392` |

Report: `06-alpn-overread/`

---

### Module 6: `ssl/quic/quic_impl.c` — 1 Confirmed Crash

| Bug ID | Function | ASAN Type | Crash Site |
|--------|----------|-----------|------------|
| QUIC-PEERADDR | `ossl_quic_conn_set_initial_peer_addr` | stack-buffer-overflow READ 16 | `quic_impl.c:1309` |

Report: `07-quic-peeraddr-oob/`

---

## Reporting Priority

### Priority 1 — Report Immediately
1. **PKCS7 Type Confusion** — systemic; 5 crash paths in `dataInit/Final/Verify`
2. **EVP NULL Write** — NULL/arbitrary write primitive; `GET_RSA_PADDING` + `GET_PSS_SALTLEN`

### Priority 2 — Report
3. **DANE TLSA OOB Read** — OOB read from caller buffer via `SSL_dane_tlsa_add`
4. **ALPN Overread** — heap OOB read of up to 255 bytes via malicious ALPN callback
5. **QUIC Peer Addr OOB** — stack OOB read via `SSL_set1_initial_peer_addr`

### Priority 3 — Report
6. **PKCS7 Negative Index** — SEGV in `PKCS7_get_issuer_and_serial`
7. **PKCS7 NULL enc_data** — SEGV in `PKCS7_dataInit` enveloped branch
8. **validate_cert_type OOB** — stack OOB read via `SSL_set1_client_cert_type`
9. **EC NULL Scalar** — broken API contract in `EC_POINTs_mul`

---

## Submission

- **Email:** security@openssl.org
- **GitHub:** https://github.com/openssl/openssl/security/advisories/new
- **Policy:** OpenSSL responsible disclosure (90-day embargo)

---

## Directory Structure

```
zero-day/openssl/
├── SUMMARY.md                    ← this file
├── email_draft.md                ← draft submission email
├── build.sh                      ← clone + build OpenSSL with ASAN
├── 01-pkcs7-type-confusion/      ← PK-TYPE-1..4 (5 PoCs)
├── 02-pkcs7-negidx-encdat/       ← PK-NEGIDX, PK-ENCDAT (2 PoCs)
├── 03-evp-null-write/            ← EVP-RSA-PAD, EVP-PSS-SALT (2 PoCs)
├── 04-ssl-oob-reads/             ← SSL-DANE-OOB, SSL-CERT-TYPE (2 PoCs)
├── 05-ec-null-scalar/            ← EC-NULL-SCALAR (1 PoC)
├── 06-alpn-overread/             ← ALPN-OVERREAD (1 PoC)
└── 07-quic-peeraddr-oob/         ← QUIC-PEERADDR (1 PoC)
```
