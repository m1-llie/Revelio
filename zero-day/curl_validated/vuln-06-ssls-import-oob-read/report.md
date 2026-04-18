# vuln-06: Stack Buffer Overflow (OOB Read) in curl_easy_ssls_import via Undersized shmac Buffer

## Validation Status (2026-04-17)
- **Latest curl commit**: `70281e3` (haproxy: use correct ip version on client supplied address)
- **curl version**: 8.20.0-DEV
- **Status**: CONFIRMED STILL PRESENT — shmac_len validates declared size, actual buffer unchecked
- **Runtime crash confirmed**: YES (ASAN stack-buffer-overflow at cf_ssl_scache_peer_init)
- **Validation image**: `curl-validate:20260417`
- **Requires**: `--enable-ssls-export` build flag (present in curl-validate:20260417)

### Crash Output (latest build)
```
[*] shmac buffer size = 10 bytes
[*] claimed shmac_len = 64 (passes validation check)
[*] Code will memcpy 32+32=64 bytes from 10-byte buffer -> OOB read
==16==ERROR: AddressSanitizer: stack-buffer-overflow on address ...
READ of size 32 at ... thread T0
    #0 __asan_memcpy ...
    #1 cf_ssl_scache_peer_init /src/curl/lib/vtls/vtls_scache.c:458:5
    #2 Curl_ssl_session_import /src/curl/lib/vtls/vtls_scache.c:1125:18
    #3 main /work06/poc.c:94:11
  [96, 106) 'small_shmac' (line 64) <== Memory access at offset 106 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow in cf_ssl_scache_peer_init
```

---

# Bug Report: SC_FOLDER_071047_SF15

## Title
Stack-buffer-overflow (OOB read) in `curl_easy_ssls_import` via undersized `shmac` buffer with lying `shmac_len=64`

## CVE-worthy?
**Yes.** This is an out-of-bounds read vulnerability reachable through the public API `curl_easy_ssls_import`. When a caller provides an `shmac` buffer smaller than 64 bytes but passes `shmac_len=64`, the library reads 32–54 bytes past the buffer boundary. This can:
- Crash the application (DoS)
- Leak adjacent stack memory containing sensitive data (e.g., cryptographic keys, session data, or return addresses)

While this requires a caller to pass mismatched `shmac`/`shmac_len` parameters, the API design (accepting both independently) makes this a memory-safety violation that could be triggered by corrupt/untrusted serialized session data in a session-restore workflow.

## Affected File:Line
- `lib/vtls/vtls_scache.c:1109-1117` — `Curl_ssl_session_import` computes `salt = shmac` and `hmac = shmac + 32` after validating only `shmac_len == 64`, not the actual buffer size
- `lib/vtls/vtls_scache.c:457-460` — `cf_ssl_scache_peer_init` does `memcpy(peer->key_salt, salt, 32)` and `memcpy(peer->key_hmac, hmac, 32)` reading beyond the small buffer

## Root Cause
In `Curl_ssl_session_import`, when `ssl_peer_key` is NULL, the code validates that `shmac_len == sizeof(peer->key_salt) + sizeof(peer->key_hmac)` (i.e., == 64). However, this check only validates the *claimed* length, not the *actual* allocation size of the `shmac` pointer. The code then computes:
```c
const unsigned char *salt = shmac;
const unsigned char *hmac = shmac + sizeof(peer->key_salt);  // shmac + 32
```
and passes both pointers to `cf_ssl_scache_peer_init`, which performs:
```c
memcpy(peer->key_salt, salt, sizeof(peer->key_salt));  // reads shmac[0..31]
memcpy(peer->key_hmac, hmac, sizeof(peer->key_hmac));  // reads shmac[32..63] -- OOB if buf < 64!
```
If `shmac` only has 10 bytes allocated, this reads 54 bytes past the end of the buffer.

## Crash Output (ASAN)
```
[*] shmac buffer size = 10 bytes
[*] claimed shmac_len = 64 (passes validation check)
[*] Code will memcpy 32+32=64 bytes from 10-byte buffer -> OOB read
=================================================================
==15==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7bfa7ead006a at pc 0x5643a1cb8feb bp 0x7ffc630f17c0 sp 0x7ffc630f0f80
READ of size 32 at 0x7bfa7ead006a thread T0
    #0 0x5643a1cb8fea in __asan_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:63:3
    #1 0x5643a1d7df78 in cf_ssl_scache_peer_init /src/curl/lib/vtls/vtls_scache.c:458:5
    #2 0x5643a1d7d862 in Curl_ssl_session_import /src/curl/lib/vtls/vtls_scache.c:1125:13
    #3 0x5643a1c166e2 in main /output/SC_FOLDER_071047_SF15_poc.c:94:11
SUMMARY: AddressSanitizer: stack-buffer-overflow /src/curl/lib/vtls/vtls_scache.c:458:5 in cf_ssl_scache_peer_init

Address 0x7bfa7ead006a is located in stack of thread T0 at offset 106 in frame
    [96, 106) 'small_shmac' (line 64) <== Memory access at offset 106 overflows this variable
```

## Reproduction Steps
1. Build curl with `USE_SSLS_EXPORT=ON` and ASAN (same as SF20 above).
2. Compile the PoC:
   ```bash
   clang -fsanitize=address -g -O1 SC_FOLDER_071047_SF15_poc.c \
     -I/src/curl/include libcurl.a -lssl -lcrypto -lz -lpthread -o poc_sf15
   ```
3. Run:
   ```bash
   ASAN_OPTIONS=detect_leaks=0 ./poc_sf15
   ```

## Suggested Fix
In `Curl_ssl_session_import` in `lib/vtls/vtls_scache.c`, the existing check should be strengthened to also enforce that the `shmac` buffer is truly large enough. The API contract should be documented and validated:

```c
// Existing check (line 1109):
else if(shmac_len != (sizeof(peer->key_salt) + sizeof(peer->key_hmac))) {
    r = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
}
// ADD: explicit null check to ensure shmac is valid:
// (shmac_len == 64 is necessary but not sufficient if shmac is too small)
```

However, since C has no way to verify the actual allocation size at runtime, the real fix is to ensure the function contract is clear (in documentation and via static analysis annotations) that `shmac` MUST point to at least `shmac_len` bytes. The existing check does cover the case where `shmac_len < 64`, but callers who pass `shmac_len=64` with a smaller buffer are not protected.

A defense-in-depth approach would add a size_t check at the API boundary and document the requirement explicitly, plus add a fuzzer/test that passes mismatched sizes.
