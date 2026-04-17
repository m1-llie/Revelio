# SF01 — NULL Pointer Dereference in `SSL_CTX_use_PrivateKey()`

## Summary

`SSL_CTX_use_PrivateKey()` in `ssl/ssl_rsa.c` does not validate the `ctx`
parameter before dereferencing it.  Passing a NULL `SSL_CTX *` together with
a valid `EVP_PKEY *` triggers an immediate SIGSEGV, enabling denial of service
for any application that forwards an untrusted or potentially-NULL context
pointer to this function.

**Status:** Confirmed crash (ASAN/UBSAN — SIGSEGV at ssl_rsa.c:371)
**Confidence:** 0.98
**CVSS estimate:** 7.5 (High) — Network-reachable DoS where ctx can be NULL

---

## Details

### Vulnerable code

**File:** `openssl33/ssl/ssl_rsa.c`, lines 365–372

```c
int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
{
    if (pkey == NULL) {                          // pkey is guarded …
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return ssl_set_pkey(ctx->cert, pkey, ctx);   // … but ctx is NOT (line 371)
}
```

`pkey == NULL` is checked, but `ctx` is silently assumed non-NULL.  The first
member access `ctx->cert` at line 371 causes a null-pointer dereference when
`ctx` is NULL.

Compare with `SSL_CTX_use_serverinfo_ex()` in the same file which correctly
opens with:
```c
if (ctx == NULL || serverinfo == NULL || serverinfo_length == 0) {
    ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
}
```

### ASAN / UBSAN output

```
ssl/ssl_rsa.c:371:30: runtime error: member access within null pointer of type 'SSL_CTX'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ssl/ssl_rsa.c:371:30
AddressSanitizer:DEADLYSIGNAL
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000158
SUMMARY: AddressSanitizer: SEGV ssl/ssl_rsa.c:371:30 in SSL_CTX_use_PrivateKey
```

---

## PoC Reproduction Steps

### Prerequisites

- Docker image `vulagent/openssl:latest` available locally.

### Step 1 — Start container

```bash
docker run -it --rm \
  -v "$(pwd)/poc.c:/tmp/sf01_poc.c:ro" \
  -v "$(pwd)/build.sh:/tmp/build.sh:ro" \
  vulagent/openssl:latest bash
```

### Step 2 — Build openssl33 with ASAN (first time only, ~5 min)

```bash
cd /src/openssl33
./config no-shared no-tests no-apps --debug \
    -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1
make -j$(nproc) build_libs
```

### Step 3 — Compile and run the PoC

```bash
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I/src/openssl33/include \
    /tmp/sf01_poc.c \
    /src/openssl33/libssl.a /src/openssl33/libcrypto.a \
    -lpthread -ldl -o /tmp/sf01_poc

ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" /tmp/sf01_poc
```

**Expected output:** ASAN/UBSAN reports SEGV at `ssl_rsa.c:371` and the
process terminates abnormally.

Or use the convenience wrapper:
```bash
bash /tmp/build.sh
```

---

## Impact

Any application that accepts an `SSL_CTX *` from user-controlled input (e.g.,
configuration parsing, plugin loading, or an API wrapper that can return NULL
on allocation failure) and then calls `SSL_CTX_use_PrivateKey()` without
checking for NULL first will crash.

- **Availability:** Full process crash (DoS).
- **Confidentiality / Integrity:** Not directly exploitable for code execution
  via this path alone; crash terminates before any heap write.

---

## Remediation

Add a NULL check for `ctx` at the top of `SSL_CTX_use_PrivateKey()`,
consistent with the pattern used elsewhere in the same file:

```c
int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
{
+   if (ctx == NULL) {
+       ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
+       return 0;
+   }
    if (pkey == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return ssl_set_pkey(ctx->cert, pkey, ctx);
}
```
