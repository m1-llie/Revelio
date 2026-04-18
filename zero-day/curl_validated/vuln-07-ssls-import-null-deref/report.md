# vuln-07: NULL Pointer Dereference in curl_easy_ssls_import (sdata=NULL, sdata_len>0)

## Validation Status (2026-04-17)
- **Latest curl commit**: `70281e3` (haproxy: use correct ip version on client supplied address)
- **curl version**: 8.20.0-DEV
- **Status**: CONFIRMED STILL PRESENT — no NULL check on sdata before Curl_ssl_session_unpack
- **Runtime crash confirmed**: YES (UBSan null-pointer arithmetic + DEBUGASSERT abort)
- **Validation image**: `curl-validate:20260417`
- **Requires**: `--enable-ssls-export` build flag (present in curl-validate:20260417)

### Crash Output (latest build)
```
[*] Calling curl_easy_ssls_import with sdata=NULL, sdata_len=1
vtls/vtls_spack.c:245:34: runtime error: applying non-zero offset 1 to null pointer
    #0 Curl_ssl_session_unpack /src/curl/lib/vtls/vtls_spack.c:245:34
    #1 Curl_ssl_session_import /src/curl/lib/vtls/vtls_scache.c:1097:12
    #2 main /work07/poc.c:61:11
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior vtls/vtls_spack.c:245:34
poc07: vtls/vtls_spack.c:252: CURLcode Curl_ssl_session_unpack(...): Assertion `buf' failed.
```

---

# Bug Report: SC_FOLDER_071047_SF20

## Title
NULL pointer dereference in `curl_easy_ssls_import` when `sdata=NULL` but `sdata_len>0`

## CVE-worthy?
**Yes.** This is a denial-of-service vulnerability in a public API function (`curl_easy_ssls_import`) introduced with the SSLS_EXPORT feature. Any caller that passes `sdata=NULL` with a non-zero `sdata_len` will trigger an immediate crash. Real-world impact depends on how/whether user code or serialized session data can reach this code path with a NULL sdata.

## Affected File:Line
- `lib/vtls/vtls_scache.c:1097` — `Curl_ssl_session_import` calls `Curl_ssl_session_unpack` without checking `sdata != NULL`
- `lib/vtls/vtls_spack.c:59` — `spack_dec8` dereferences `*src` which is NULL

## Root Cause
`Curl_ssl_session_import` validates that at least one of `ssl_peer_key` or `shmac+shmac_len` is provided (line 1092-1095), but does **not** validate that `sdata` is non-NULL when `sdata_len > 0`. The function unconditionally calls `Curl_ssl_session_unpack(data, sdata, sdata_len, &s)` at line 1097. Inside `Curl_ssl_session_unpack`, `DEBUGASSERT(buf)` is the only guard, which is stripped in release builds. The function then computes `end = buf + buflen` (where `buf=NULL`), and the first `spack_dec8` call reads `**src` (i.e., `*NULL`) causing a segmentation fault.

## Crash Output (ASAN)
```
[*] Calling curl_easy_ssls_import with sdata=NULL, sdata_len=1
AddressSanitizer:DEADLYSIGNAL
=================================================================
==10==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x55c8814568a4 bp 0x7ffed4ac96f0 sp 0x7ffed4ac9650 T0)
==10==The signal is caused by a READ memory access.
==10==Hint: address points to the zero page.
    #0 0x55c8814568a4 in spack_dec8 /src/curl/lib/vtls/vtls_spack.c:59:10
    #1 0x55c8814568a4 in Curl_ssl_session_unpack /src/curl/lib/vtls/vtls_spack.c:256:7
    #2 0x55c881453e67 in Curl_ssl_session_import /src/curl/lib/vtls/vtls_scache.c:1097:7
    #3 0x55c8812ed5a6 in main /output/SC_FOLDER_071047_SF20_poc.c:61:11
SUMMARY: AddressSanitizer: SEGV /src/curl/lib/vtls/vtls_spack.c:59:10 in spack_dec8
==10==ABORTING
```

## Reproduction Steps
1. Build curl with `USE_SSLS_EXPORT=ON` and ASAN:
   ```bash
   cmake /src/curl -DUSE_SSLS_EXPORT=ON -DBUILD_SHARED_LIBS=OFF \
     -DCMAKE_C_FLAGS="-fsanitize=address -g -O1" ...
   make -j$(nproc)
   ```
2. Compile the PoC:
   ```bash
   clang -fsanitize=address -g -O1 SC_FOLDER_071047_SF20_poc.c \
     -I/src/curl/include libcurl.a -lssl -lcrypto -lz -lpthread -o poc_sf20
   ```
3. Run:
   ```bash
   ASAN_OPTIONS=detect_leaks=0 ./poc_sf20
   ```

## Suggested Fix
Add a NULL/zero check for `sdata` and `sdata_len` at the entry of `Curl_ssl_session_import` in `lib/vtls/vtls_scache.c`:

```c
// After the existing check at line 1092:
if(!sdata || !sdata_len) {
    r = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
}
```

Alternatively, add the check inside `Curl_ssl_session_unpack` in `vtls_spack.c` before dereferencing the buffer pointer (replacing or supplementing the DEBUGASSERT):

```c
if(!bufv || !buflen) {
    CURL_TRC_SSLS(data, "unpack: null or empty buffer");
    return CURLE_READ_ERROR;
}
```
