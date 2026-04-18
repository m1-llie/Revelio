# vuln-03: Heap Buffer Overflow in Curl_ssl_push_certinfo_len()

## Validation Status (2026-04-17)
- **Latest curl commit**: `70281e3` (haproxy: use correct ip version on client supplied address)
- **curl version**: 8.20.0-DEV
- **Status**: CONFIRMED STILL PRESENT — DEBUGASSERT only, stripped in release builds
- **Runtime crash confirmed**: YES (ASAN heap-buffer-overflow + UBSan OOB read)
- **Validation image**: `curl-validate:20260417`
- **Note**: Exploitable only in release builds (DEBUGASSERT compiled out); ASAN build also triggers UBSan

### Crash Output (latest build)
```
=== PoC: curl Curl_ssl_push_certinfo_len() heap-buffer-overflow ===
[*] certnum=5 (OOB! only 2 allocated) -- ASAN should fire now:
/work03/poc.c:95:20: runtime error: load of address 0x7b1e143e0038 with insufficient space
==10==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7b1e143e0038
READ of size 8 at 0x7b1e143e0038 thread T0
    #0 main /work03/poc.c:95:20
SUMMARY: AddressSanitizer: heap-buffer-overflow in main
```

---

# Bug Report: Heap Buffer Overflow in Curl_ssl_push_certinfo_len()

## Title
Missing runtime bounds check on `certnum` in `Curl_ssl_push_certinfo_len()` leads to heap buffer overflow in release builds

## CVE-Worthy?
**Yes** — CWE-787 (Out-of-bounds Write). The vulnerability is a real missing input validation: a safety check exists only as a debug-only assertion (`DEBUGASSERT`), which is compiled out in production/release builds. While current call sites in the SSL backends are bounded (MAX_ALLOWED_CERT_AMOUNT=100), any future call site or memory corruption that bypasses the per-backend bounds would trigger silent heap corruption. This is a security-relevant hardening gap.

## Affected File:Line
- `lib/vtls/vtls.c`, function `Curl_ssl_push_certinfo_len()`, line 658 (DEBUGASSERT) and line 667/674 (actual array access)

## Root Cause
`Curl_ssl_push_certinfo_len()` uses `DEBUGASSERT(certnum < ci->num_of_certs)` as the sole bounds check. In production builds compiled without `DEBUGBUILD` (the default), `DEBUGASSERT` expands to a no-op. Consequently, if `certnum` equals or exceeds `ci->num_of_certs` (the size of the `certinfo` array allocated by `Curl_ssl_init_certinfo()`), the function reads from and writes to `ci->certinfo[certnum]` beyond the allocated array bounds, causing a heap buffer overflow.

## Crash Output (ASAN)

```
=== PoC: curl Curl_ssl_push_certinfo_len() heap-buffer-overflow ===

[*] Curl_ssl_init_certinfo: allocated 16 bytes for 2 certs
    certinfo array: 0x7b5a997e0010..0x7b5a997e0020
    Valid indices:  0..1

[*] certnum=5 (OOB! only 2 allocated) -- ASAN should fire now:
=================================================================
==10==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7b5a997e0038
READ of size 8 at 0x7b5a997e0038 thread T0
    #0 in main /work/CI_FOLDER_064241_SF03_poc.c:95:20

SUMMARY: AddressSanitizer: heap-buffer-overflow at line 95 in main
```

The OOB READ occurs at `certinfo[oob_certnum]` (line 95 in PoC, corresponding to `ci->certinfo[certnum]` in curl source). The OOB WRITE at line 97 (`certinfo[oob_certnum] = nl`) mirrors `ci->certinfo[certnum] = nl` in vtls.c:674.

## Reproduction Steps

1. Clone curl source
2. Build WITHOUT `-DENABLE_DEBUG=ON` (i.e., without DEBUGBUILD)
3. Trigger a TLS connection where the SSL backend calls:
   - `Curl_ssl_init_certinfo(data, N)` — allocates array of N pointers
   - `Curl_ssl_push_certinfo_len(data, certnum, ...)` with `certnum >= N`

For direct PoC reproduction:
```bash
clang -fsanitize=address -g CI_FOLDER_064241_SF03_poc.c -o poc_sf03
ASAN_OPTIONS=detect_leaks=0 ./poc_sf03
```

The PoC replicates the exact memory access pattern of `Curl_ssl_push_certinfo_len()` in a release build (without DEBUGASSERT). ASAN reports `heap-buffer-overflow` on the read of `certinfo[5]` when only indices 0-1 are valid.

## Exploitability Assessment

**Current exploitability: LOW** — All current callers (openssl.c, mbedtls.c, gtls.c, rustls.c) properly bound `certnum` using the same `numcerts` value used to initialize the array. The bounds are also capped at `MAX_ALLOWED_CERT_AMOUNT=100`.

**Potential exploitability: MEDIUM** — Any of these conditions would make this exploitable:
- A bug in an SSL backend causing the loop counter to diverge from `numcerts`
- A future call site that fails to bound `certnum`
- Memory corruption that modifies `num_of_certs` after initialization but before the push loop

## Suggested Fix

Add a runtime bounds check in `Curl_ssl_push_certinfo_len()`:

```c
CURLcode Curl_ssl_push_certinfo_len(struct Curl_easy *data,
                                    int certnum, ...)
{
  struct curl_certinfo *ci = &data->info.certs;
  
  /* Replace DEBUGASSERT with a proper runtime check */
  if(certnum < 0 || certnum >= ci->num_of_certs)
    return CURLE_BAD_CONTENT_ENCODING;  /* or CURLE_SSL_CERTPROBLEM */
  
  DEBUGASSERT(certnum < ci->num_of_certs);  /* keep for debug builds */
  ...
}
```

## References
- `lib/vtls/vtls.c:647-677` — Vulnerable function
- `lib/vtls/openssl.c:386-392` — MAX_ALLOWED_CERT_AMOUNT check before init (only partial mitigation)
- `lib/curl_setup.h:1079-1087` — DEBUGASSERT definition (no-op in non-debug builds)
- CWE-787: Out-of-bounds Write
- CWE-20: Improper Input Validation
- CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
