---
To: security@openssl.org
Subject: [7 issues] Memory safety bugs confirmed on master (commit 04623f1, 2026-04-17)
Attachments:
  01-pkcs7-type-confusion/report.md  + 5 PoCs
  02-pkcs7-negidx-encdat/report.md   + 2 PoCs
  03-evp-null-write/report.md        + 2 PoCs
  04-ssl-oob-reads/report.md         + 2 PoCs
  05-ec-null-scalar/report.md        + 1 PoC
  06-alpn-overread/report.md         + 1 PoC
  07-quic-peeraddr-oob/report.md     + 1 PoC
---

Hello OpenSSL Security Team,

I am reporting 14 memory-safety bugs across 7 issue groups, all confirmed
on the current master branch (commit 04623f1, 2026-04-17) under ASAN+UBSAN
(`clang -fsanitize=address,undefined`). Each issue has a self-contained PoC.

---

## Issue 1 (Priority 1) — PKCS7 Systemic Type Confusion

**5 heap-buffer-overflow / NULL-deref crashes** in `crypto/pkcs7/pk7_doit.c`.

`PKCS7_dataInit()`, `PKCS7_dataFinal()`, and `PKCS7_dataVerify()` dispatch on
`p7->type` OID without validating that `p7->d` was initialized to match.
Constructing a PKCS7 with one type then changing `p7->type` to another causes
reads 4–8 bytes past the heap allocation.

| # | Function | Crash site |
|---|----------|-----------|
| 1a | `PKCS7_dataInit` | `pk7_doit.c:271` heap-OOB READ 8 |
| 1b | `PKCS7_dataInit` | `pk7_doit.c:272` heap-OOB READ 8 |
| 1c | `PKCS7_dataInit` | `pk7_doit.c:286` UBSAN null-member |
| 1d | `PKCS7_dataFinal` | `pk7_doit.c:804` heap-OOB READ 8 |
| 1e | `PKCS7_dataVerify` | `pk7_doit.c` heap-OOB READ 8 |

See: `01-pkcs7-type-confusion/report.md`

---

## Issue 2 (Priority 1) — PKCS7 Additional NULL Dereferences

**2 crashes** in `crypto/pkcs7/pk7_doit.c`:

- `PKCS7_get_issuer_and_serial()` at line 1177: negative `idx` → NULL pointer
  returned by `sk_PKCS7_RECIP_INFO_value()` → SEGV on member access.
- `PKCS7_dataInit()` at line 286: NULL `enc_data` → SEGV in the enveloped branch.

See: `02-pkcs7-negidx-encdat/report.md`

---

## Issue 3 (Priority 1) — NULL/Arbitrary Write in `ctrl_params_translate.c`

**2 crashes** in `crypto/evp/ctrl_params_translate.c`:

`fix_rsa_padding_mode()` (line 1363) and `fix_rsa_pss_saltlen()` (line 1443)
store `ctx->p2` (from the caller) in `ctx->orig_p2`, then unconditionally write
`*(int *)ctx->orig_p2 = value` in POST phase. Passing `p2 = NULL` causes an
immediate write to address 0x0 (DoS). A freed or attacker-controlled pointer
becomes an arbitrary 4-byte write primitive.

See: `03-evp-null-write/report.md`

---

## Issue 4 (Priority 2) — OOB Reads in `ssl_lib.c`

**2 crashes** in `ssl/ssl_lib.c`:

- `dane_tlsa_add()` (line 328): `memcpy(t->data, data, dlen)` reads `dlen` bytes
  from the caller's `data` without validating the buffer size. PoC: 4-byte buffer,
  `dlen = 256` → stack-buffer-overflow READ 256.
- `validate_cert_type()` (line 8389): iterates `val[0..len-1]` without checking
  the buffer contains `len` bytes. PoC: 1-byte buffer, `len = 64` → stack-buffer-
  overflow READ 1.

See: `04-ssl-oob-reads/report.md`

---

## Issue 5 (Priority 3) — ALPN Callback Heap OOB Read

**1 crash** in `ssl/statem/statem_srvr.c`:

`tls_handle_alpn()` (line 2392) calls `OPENSSL_memdup(selected, selected_len)`
trusting the callback-supplied `selected_len` without verifying that `selected`
contains `selected_len` bytes. A callback returning a 1-byte allocation with
`outlen = 255` causes a heap-buffer-overflow READ of 255 bytes.

See: `06-alpn-overread/report.md`

---

## Issue 6 (Priority 3) — QUIC Peer Addr Stack OOB

**1 crash** in `ssl/quic/quic_impl.c`:

`ossl_quic_conn_set_initial_peer_addr()` (line 1309) calls
`BIO_ADDR_copy(&ctx.qc->init_peer_addr, peer_addr)` which copies
`sizeof(BIO_ADDR)` = 112 bytes from `peer_addr`. Passing a smaller buffer
causes a stack-buffer-overflow read.

See: `07-quic-peeraddr-oob/report.md`

---

## Issue 7 (Priority 3) — EC NULL Scalar Broken Contract

**1 crash** in `crypto/ec/ecp_nistz256.c`:

`ecp_nistz256_windowed_mul()` (line 637) calls `BN_num_bits(scalar[i])`
unconditionally for each scalar, but the API contract (documented in source
comments) states NULL scalars should be treated as zero. Passing a NULL scalar
alongside a non-NULL point crashes in `BN_num_bits`.

See: `05-ec-null-scalar/report.md`

---

## Notes

- All 14 crashes are confirmed on commit `04623f1` (master, 2026-04-17).
- All PoCs compile against a static ASAN build of OpenSSL master with no
  external dependencies.
- I am reporting these together because several share root causes (PKCS7
  type dispatch, EVP orig_p2 pattern) and can likely be addressed in a
  small number of patches.
- I am prepared to provide additional information, patches, or CVE coordination
  as needed.

Thank you for your time.
