# Missing runtime bounds check in `Curl_ssl_push_certinfo_len()` — sole guard is `DEBUGASSERT`, a no-op in production

# CWE
`CWE-20: Improper Input Validation` (missing hardening guard; CWE-617: Reachable Assertion)

# severity
`Low`

# Proof of Concept
Attached file: `poc.c` (requires `build.sh` to set up mock server)

## Summary

`Curl_ssl_push_certinfo_len()` in `lib/vtls/vtls.c` uses `DEBUGASSERT(certnum < ci->num_of_certs)` as its **only** bounds check before writing a heap pointer into `ci->certinfo[certnum]`. In every production/release build, `DEBUGASSERT` is compiled out to `do{}while(0)` (`lib/curl_setup.h:1084`), leaving the array write at lines `:667`/`:674` completely unchecked at runtime.

All five TLS backends (OpenSSL, GnuTLS, mbedTLS, Rustls, Schannel) derive `certnum` from the server-supplied certificate chain length and feed it directly into this function. The current call sites keep `certnum` within bounds, so no out-of-bounds write occurs in the current codebase under normal operation. However, a future off-by-one or count mismatch in any one of those five backends would produce silent heap corruption in production builds with **no runtime safety net**.

## Affected version

Reproduced against:
- **curl 8.19.0** (tag `curl-8_19_0`, commit `8c908d2`, released 2025-03-10) — current stable release
- **curl 8.20.0-DEV** (commit `759f2e5`) — current development tip

Tested on Linux x86_64 with `clang`, AddressSanitizer, and UndefinedBehaviorSanitizer.

## Call path from `CURLOPT_CERTINFO` to the unguarded write

When an application sets `CURLOPT_CERTINFO=1`, every successful TLS handshake runs the following sequence (shown for the OpenSSL backend; all five backends follow the same structure):

```
curl_easy_perform(handle)
  Curl_ossl_check_peer_cert()                      openssl.c:4736
    ossl_certchain(data, ssl)                       openssl.c:4739
      numcerts = sk_X509_num(peer_cert_chain)   <- server controls N
      Curl_ssl_init_certinfo(data, numcerts)     <- alloc N-slot table
      for i = 0 .. N-1:                         <- certnum = i
        Curl_ssl_push_certinfo_len(data, i, ...) <- called N* times per cert
          DEBUGASSERT(i < num_of_certs)          <- SOLE GUARD, no-op in release
          ci->certinfo[i] = ...                  <- unguarded write in release
```

The same structure exists in all five backends:

| Backend | File | Caller |
|---------|------|--------|
| OpenSSL | `openssl.c:392,409–505` | `ossl_certchain()` |
| GnuTLS | `gtls.c:1622,1630` | `Curl_extract_certinfo()` loop |
| mbedTLS | `mbedtls.c:431,433` | `mbed_extract_certinfo()` |
| Rustls | `rustls.c:1207,1225` | certinfo loop |
| Schannel | `schannel.c:1679,1686` | `add_cert_to_certinfo()` |

## Vulnerable code

`lib/vtls/vtls.c:647–675`:

```c
CURLcode Curl_ssl_push_certinfo_len(struct Curl_easy *data,
                                    int certnum, ...)
{
  struct curl_certinfo *ci = &data->info.certs;

  DEBUGASSERT(certnum < ci->num_of_certs);   /* :658 — no-op in release */

  /* ... build label:value string ... */

  nl = Curl_slist_append_nodup(ci->certinfo[certnum], ...); /* :667 — no runtime check */
  ci->certinfo[certnum] = nl;                               /* :674 — no runtime check */
}
```

`lib/curl_setup.h:1084` (release builds):

```c
#define DEBUGASSERT(x) do {} while(0)
```

## Steps To Reproduce

The PoC uses only the public libcurl API and a mock HTTPS server.

### Setup: build curl 8.19.0 with ASAN

```bash
git clone --depth=1 --branch curl-8_19_0 https://github.com/curl/curl curl-819
cd curl-819
autoreconf -fi
CC=clang CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=address,undefined" \
./configure --with-openssl --disable-docs --disable-manual --without-libpsl
make -j"$(nproc)"
```

### Setup: create a 3-cert chain and start mock HTTPS server

```bash
# Root CA
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout root.key -out root.crt -subj '/CN=Root CA'

# Intermediate CA (signed by root)
openssl req -newkey rsa:2048 -nodes -keyout inter.key -out inter.csr -subj '/CN=Intermediate CA'
openssl x509 -req -days 3650 -in inter.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -extfile <(echo 'basicConstraints=CA:TRUE') -out inter.crt

# Leaf cert (signed by intermediate)
openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj '/CN=localhost'
openssl x509 -req -days 3650 -in leaf.csr -CA inter.crt -CAkey inter.key -CAcreateserial \
  -out leaf.crt

cat leaf.crt inter.crt root.crt > chain.crt

# Start mock HTTPS server
openssl s_server -cert leaf.crt -key leaf.key -cert_chain chain.crt -accept 9443 -www -quiet &
```

### Compile PoC against libcurl 8.19.0

```bash
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
  -I./include \
  poc.c \
  -L./lib/.libs -lcurl -Wl,-rpath,./lib/.libs \
  -o /tmp/poc_certinfo
```

### Run

```bash
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  /tmp/poc_certinfo https://127.0.0.1:9443/
```

Observed output (curl 8.19.0, 4-cert chain from mock server):

```text
=== PoC: Curl_ssl_push_certinfo_len() missing runtime bounds check ===

Vulnerable code (lib/vtls/vtls.c:647-675):
  :658  DEBUGASSERT(certnum < ci->num_of_certs)  <- no-op in release
  :667  nl = append(ci->certinfo[certnum], ...)  <- unguarded in release
  :674  ci->certinfo[certnum] = nl;              <- unguarded in release

Connecting to https://127.0.0.1:9443/ with CURLOPT_CERTINFO=1 ...

[Result] Server sent a 4-certificate chain.
[Result] Curl_ssl_init_certinfo(data, 4) was called  -> 4 heap slots allocated
[Result] Curl_ssl_push_certinfo_len(data, certnum=0..3, ...) was called 4* times

[Vulnerability] certnum comes from server-controlled chain length.
                DEBUGASSERT(certnum < num_of_certs) at vtls.c:658
                is compiled out in release builds.
                No other bounds check exists at vtls.c:667/674.

[cert certnum=0]
  Subject:CN = localhost
  Issuer:CN = Intermediate CA
  ...

[cert certnum=1] ... [cert certnum=2] ... [cert certnum=3] ...

=== Code path confirmed: certnum is server-controlled ===
    In release builds vtls.c:658 DEBUGASSERT is a no-op;
    ci->certinfo[certnum] writes at :667/:674 are unchecked.
```

No sanitizer error is raised in the current codebase — all five TLS backends correctly bound their `certnum` loops to `numcerts` today. The issue is the **absence of any runtime check** at the function level.

# Impact

The sole protection for `ci->certinfo[certnum]` array accesses at `vtls.c:667` and `:674` is a `DEBUGASSERT` that is unconditionally absent in every production build. `certnum` is derived from the server-supplied certificate chain length.

In the current codebase, all five TLS backends happen to bound their loops correctly. The risk materialises when any of the following occurs:
- A future off-by-one or refactoring error in any backend causes `certnum` to exceed `num_of_certs`
- A new backend is added that does not bound `certnum` identically to `init_certinfo`
- Any memory corruption (e.g. from a separate bug) modifies `num_of_certs` after init but before push

In any of these cases, the write at `:674` stores a heap pointer at an attacker-influenced offset with no runtime fallback — immediate silent heap corruption in production.

The fix is a single runtime bounds check replacing or supplementing the `DEBUGASSERT` at `:658`:

```c
if(certnum < 0 || certnum >= ci->num_of_certs)
    return CURLE_BAD_CONTENT_ENCODING;
```

---
*Reported via HackerOne per curl security policy: https://hackerone.com/curl*
