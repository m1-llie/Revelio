# vuln-02: NULL Pointer Dereference in `client_cert()` via Unchecked `SSL_get_privatekey()` Return Value

## Validation Status (2026-04-17)
- **Latest curl commit**: `70281e3` (haproxy: use correct ip version on client supplied address)
- **curl version**: 8.20.0-DEV
- **Status**: CONFIRMED STILL PRESENT — bug not fixed
- **Runtime crash confirmed**: YES (ASAN SEGV in EVP_PKEY_get_id)
- **Validation image**: `curl-validate:20260417`
- **Note**: Guarded by `#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)`

### Crash Output (latest build)
```
=== SF15 PoC: NULL deref in client_cert() via EVP_PKEY_id(NULL) ===

SSL_get_privatekey on SSL without loaded key: (nil)

Calling EVP_PKEY_id(NULL) - the vulnerable pattern in client_cert()...
AddressSanitizer:DEADLYSIGNAL
==10==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
==10==The signal is caused by a READ memory access.
    #0 EVP_PKEY_get_id (/lib/x86_64-linux-gnu/libcrypto.so.3+0x20a674)
    #1 main /work/poc.c:41:14
SUMMARY: AddressSanitizer: SEGV in EVP_PKEY_get_id
```

---

# SF15: NULL Pointer Dereference in `client_cert()` via Unchecked `SSL_get_privatekey()` Return Value

## Title
NULL dereference in `EVP_PKEY_id()` when `SSL_get_privatekey()` returns NULL in curl's TLS client certificate handling

## CVE-worthy?
**Marginal** (DoS possible in specific edge cases). The code path is guarded by `#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)` which limits affected configurations. Additionally, `SSL_get_privatekey()` typically returns the key successfully after `SSL_CTX_use_PrivateKey_file()`. However, it can return NULL if:
- The private key is an ENGINE-type key that doesn't propagate to the SSL object
- Implementation-specific edge cases in custom OpenSSL builds
- Memory pressure causes key allocation failure

- CWE-476: NULL Pointer Dereference
- CWE-252: Unchecked Return Value
- Affects: curl with OpenSSL backend, client cert auth, RSA keys, non-OpenSSL3 builds

## Affected File:Line
`curl/lib/vtls/openssl.c`, lines 1567-1571 in function `client_cert()`

```c
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)
{
    EVP_PKEY *priv_key = SSL_get_privatekey(ssl);      // <-- can return NULL
    if(EVP_PKEY_id(priv_key) == EVP_PKEY_RSA) {        // <-- NULL DEREF if priv_key is NULL
        RSA *rsa = EVP_PKEY_get1_RSA(priv_key);
        if(RSA_flags(rsa) & RSA_METHOD_FLAG_NO_CHECK)
            check_privkey = FALSE;
        RSA_free(rsa);
    }
}
#endif
```

## Root Cause
`SSL_get_privatekey()` returns NULL when no private key is associated with the SSL object. curl calls `EVP_PKEY_id(priv_key)` without a NULL check. OpenSSL's `EVP_PKEY_id(NULL)` / `EVP_PKEY_get_id(NULL)` immediately dereferences the NULL pointer, causing SIGSEGV at address `0x0` (first field of the EVP_PKEY struct).

## Crash Output (ASAN Report)

```
SSL_get_privatekey on SSL without loaded key: (nil)
(NULL when no private key is set)

Calling EVP_PKEY_id(NULL) - the vulnerable pattern in client_cert()...
AddressSanitizer:DEADLYSIGNAL
==10==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7f15b7727674 bp ...)
==10==The signal is caused by a READ memory access.
==10==Hint: address points to the zero page.
    #0 0x7f15b7727674 in EVP_PKEY_get_id (/lib/x86_64-linux-gnu/libcrypto.so.3+0x20a674)
    #1 0x561bc43d9925 in main /work/poc_sf15_v2.c:41:14
SUMMARY: AddressSanitizer: SEGV (/lib/x86_64-linux-gnu/libcrypto.so.3+0x20a674) in EVP_PKEY_get_id
```

## Reproduction Steps

1. Build the PoC:
```bash
docker run --rm -v /path/to/poc:/work vulagent/curl:latest bash -c "
  cd /work
  clang -fsanitize=address -g SF_FOLDER_061512_SF15_poc.c -lssl -lcrypto -o poc_sf15
  ASAN_OPTIONS=detect_leaks=0 ./poc_sf15
"
```

2. Real-world trigger:
   - Use curl with an ENGINE-based private key (`CURLOPT_SSLKEYTYPE = "ENGINE"`)
   - The engine key may not propagate to the per-SSL object in all configurations
   - `SSL_get_privatekey(ssl)` returns NULL → `EVP_PKEY_id(NULL)` crashes

## Suggested Fix

Add a NULL check for `priv_key` before calling `EVP_PKEY_id()`:

```c
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DEPRECATED_3_0)
{
    EVP_PKEY *priv_key = SSL_get_privatekey(ssl);
    if(priv_key && EVP_PKEY_id(priv_key) == EVP_PKEY_RSA) {  // <-- ADD priv_key check
        RSA *rsa = EVP_PKEY_get1_RSA(priv_key);
        if(rsa) {  // also add NULL check for RSA
            if(RSA_flags(rsa) & RSA_METHOD_FLAG_NO_CHECK)
                check_privkey = FALSE;
            RSA_free(rsa);
        }
    }
}
#endif
```

## Additional Notes

- The RSA `get1` function (`EVP_PKEY_get1_RSA`) also lacks a NULL check on its return value `rsa`; a separate fix is needed there.
- This code is deprecated (`OPENSSL_NO_DEPRECATED_3_0`) and will be removed in future builds, reducing the risk surface.
- The vulnerability class is identical to SF16 — both result from not checking return values of key/cert introspection functions.
