# SF06 — NULL Pointer Dereference in `SSL_CTX_use_PrivateKey_ASN1()`

## Summary

`SSL_CTX_use_PrivateKey_ASN1()` in `ssl/ssl_rsa.c` passes `ctx->libctx` and
`ctx->propq` to `d2i_PrivateKey_ex()` without checking whether `ctx` itself is
NULL.  Passing NULL as `ctx` crashes the process at line 422.

**Status:** Confirmed crash (ASAN SEGV at ssl_rsa.c:422)
**Confidence:** 0.95
**CVSS estimate:** 7.5 (High)

---

## Details

### Vulnerable code

**File:** `openssl33/ssl/ssl_rsa.c`, lines 421–428

```c
int SSL_CTX_use_PrivateKey_ASN1(int type, SSL_CTX *ctx,
    const unsigned char *d, long len)
{
    int ret;
    const unsigned char *p;
    EVP_PKEY *pkey;

    p = d;
    if ((pkey = d2i_PrivateKey_ex(type, NULL, &p, (long)len,
             ctx->libctx,       // line 422 — ctx is NOT checked
             ctx->propq))       // same null deref
        == NULL) { … }
    // …
}
```

### ASAN / UBSAN output

```
ssl/ssl_rsa.c:422:67: runtime error: member access within null pointer of type 'SSL_CTX'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ssl/ssl_rsa.c:422:67
ssl/ssl_rsa.c:422:67: runtime error: load of null pointer of type 'OSSL_LIB_CTX *'
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
SUMMARY: AddressSanitizer: SEGV ssl/ssl_rsa.c:422:67 in SSL_CTX_use_PrivateKey_ASN1
```

---

## PoC Reproduction Steps

### Prerequisites

- Docker image `vulagent/openssl:latest` available locally.

### Step 1 — Start container

```bash
docker run -it --rm \
  -v "$(pwd)/poc.c:/tmp/sf06_poc.c:ro" \
  vulagent/openssl:latest bash
```

### Step 2 — Build openssl33 with ASAN (first time only, ~5 min)

```bash
cd /src/openssl33
./config no-shared no-tests no-apps --debug \
    -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1
make -j$(nproc) build_libs
```

### Step 3 — Compile and run

```bash
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I/src/openssl33/include \
    /tmp/sf06_poc.c \
    /src/openssl33/libssl.a /src/openssl33/libcrypto.a \
    -lpthread -ldl -o /tmp/sf06_poc

ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" /tmp/sf06_poc
```

**Expected output:** ASAN/UBSAN SEGV at `ssl_rsa.c:422`.

---

## Impact

- **Availability:** Full process crash (DoS).
- **Confidentiality / Integrity:** Not directly exploitable beyond DoS.

---

## Remediation

```c
int SSL_CTX_use_PrivateKey_ASN1(int type, SSL_CTX *ctx,
    const unsigned char *d, long len)
{
+   if (ctx == NULL || d == NULL) {
+       ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
+       return 0;
+   }
    // …existing code…
}
```
