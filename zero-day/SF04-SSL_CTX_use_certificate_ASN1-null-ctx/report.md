# SF04 — NULL Pointer Dereference in `SSL_CTX_use_certificate_ASN1()`

## Summary

`SSL_CTX_use_certificate_ASN1()` in `ssl/ssl_rsa.c` dereferences the `ctx`
parameter at the very first line of its body without a NULL guard.  Passing
NULL as `ctx` causes an immediate SIGSEGV inside `X509_new_ex()`, which reads
`ctx->libctx` and `ctx->propq`.

**Status:** Confirmed crash (ASAN SEGV at ssl_rsa.c:348)
**Confidence:** 0.95
**CVSS estimate:** 7.5 (High)

---

## Details

### Vulnerable code

**File:** `openssl33/ssl/ssl_rsa.c`, lines 343–355

```c
int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, const unsigned char *d)
{
    X509 *x;
    int ret;

    x = X509_new_ex(ctx->libctx, ctx->propq);  // ctx deref at line 348 — NO null check
    if (x == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_ASN1_LIB);
        return 0;
    }
    // …
}
```

### ASAN / UBSAN output

```
ssl/ssl_rsa.c:348:26: runtime error: member access within null pointer of type 'SSL_CTX'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ssl/ssl_rsa.c:348:26
ssl/ssl_rsa.c:348:26: runtime error: load of null pointer of type 'OSSL_LIB_CTX *'
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
SUMMARY: AddressSanitizer: SEGV ssl/ssl_rsa.c:348:26 in SSL_CTX_use_certificate_ASN1
```

---

## PoC Reproduction Steps

### Prerequisites

- Docker image `vulagent/openssl:latest` available locally.

### Step 1 — Start container

```bash
docker run -it --rm \
  -v "$(pwd)/poc.c:/tmp/sf04_poc.c:ro" \
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
    /tmp/sf04_poc.c \
    /src/openssl33/libssl.a /src/openssl33/libcrypto.a \
    -lpthread -ldl -o /tmp/sf04_poc

ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" /tmp/sf04_poc
```

**Expected output:** ASAN/UBSAN SEGV at `ssl_rsa.c:348`.

---

## Impact

Applications passing a potentially-NULL `SSL_CTX *` (e.g., after a failed
`SSL_CTX_new()` allocation) to `SSL_CTX_use_certificate_ASN1()` crash
immediately.

- **Availability:** Full process crash (DoS).
- **Confidentiality / Integrity:** Not directly exploitable for code execution.

---

## Remediation

```c
int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, const unsigned char *d)
{
+   if (ctx == NULL || d == NULL) {
+       ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
+       return 0;
+   }
    X509 *x;
    int ret;
    x = X509_new_ex(ctx->libctx, ctx->propq);
    // …
}
```
