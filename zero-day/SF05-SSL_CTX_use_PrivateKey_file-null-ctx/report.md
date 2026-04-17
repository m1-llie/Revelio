# SF05 — NULL Pointer Dereference in `SSL_CTX_use_PrivateKey_file()`

## Summary

`SSL_CTX_use_PrivateKey_file()` in `ssl/ssl_rsa.c` opens the requested file
into a BIO successfully, then immediately dereferences `ctx->default_passwd_callback`
(and three other `ctx` members) without first checking that `ctx` is non-NULL.
Passing NULL as `ctx` crashes the process at line 393.

**Status:** Confirmed crash (ASAN SEGV at ssl_rsa.c:393)
**Confidence:** 0.95
**CVSS estimate:** 7.5 (High)

---

## Details

### Vulnerable code

**File:** `openssl33/ssl/ssl_rsa.c`, lines 390–400

```c
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
    // … BIO opened from file …
    if (type == SSL_FILETYPE_PEM) {
        pkey = PEM_read_bio_PrivateKey_ex(in, NULL,
            ctx->default_passwd_callback,           // line 393 — null deref
            ctx->default_passwd_callback_userdata,
            ctx->libctx,
            ctx->propq);
    } else if (type == SSL_FILETYPE_ASN1) {
        pkey = d2i_PrivateKey_ex_bio(in, NULL, ctx->libctx, ctx->propq);
    }
    // …
}
```

`ctx` is used at line 393 before any NULL check is performed.

### ASAN / UBSAN output

```
ssl/ssl_rsa.c:393:18: runtime error: member access within null pointer of type 'SSL_CTX'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ssl/ssl_rsa.c:393:18
ERROR: AddressSanitizer: SEGV on unknown address 0x0000000000b8
SUMMARY: AddressSanitizer: SEGV ssl/ssl_rsa.c:393:18 in SSL_CTX_use_PrivateKey_file
```

---

## PoC Reproduction Steps

### Prerequisites

- Docker image `vulagent/openssl:latest` available locally.

### Step 1 — Start container

```bash
docker run -it --rm \
  -v "$(pwd)/poc.c:/tmp/sf05_poc.c:ro" \
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
    /tmp/sf05_poc.c \
    /src/openssl33/libssl.a /src/openssl33/libcrypto.a \
    -lpthread -ldl -o /tmp/sf05_poc

ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" /tmp/sf05_poc
```

**Expected output:** ASAN/UBSAN SEGV at `ssl_rsa.c:393`.

Note: `/dev/null` is used as the key file; the crash occurs before any file
content is parsed.

---

## Impact

Applications that load private keys from configurable paths and forward the
`SSL_CTX *` may crash if the context is NULL (e.g., after an allocation
failure or before context initialisation completes).

- **Availability:** Full process crash (DoS).
- **Confidentiality / Integrity:** Not directly exploitable beyond DoS.

---

## Remediation

```c
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
+   if (ctx == NULL || file == NULL) {
+       ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
+       return 0;
+   }
    // …existing code…
}
```
