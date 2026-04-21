# NULL Pointer Dereference in `SSL_CTX_use_PrivateKey()`

## Summary

`SSL_CTX_use_PrivateKey()` in `ssl/ssl_rsa.c` dereferences the `ctx` parameter
without a NULL guard. Calling the function with a NULL `SSL_CTX *` and a valid
`EVP_PKEY *` causes an immediate SIGSEGV. The crash reproduces on a plain debug
build of the current OpenSSL master branch — no sanitizers required.

- **Affected file:** `ssl/ssl_rsa.c`
- **Confirmed on commit:** `6983b5c` (2026-04-16, OpenSSL master)
- **Crash address:** `ssl_rsa.c:390` — `ctx->cert` member access through NULL
- **Impact:** Denial of service (process crash)

---

## Vulnerable Code

```c
// ssl/ssl_rsa.c (master, line 384)
int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
{
    if (pkey == NULL) {                        // pkey IS guarded …
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return ssl_set_pkey(ctx->cert, pkey, ctx); // … but ctx is NOT (line 390)
}
```

`pkey == NULL` is checked; `ctx == NULL` is not. The first member access
`ctx->cert` at line 390 dereferences the null pointer.

**Code inconsistency:** `SSL_CTX_use_serverinfo_ex()` in the same file does
guard `ctx` correctly:

```c
if (ctx == NULL || serverinfo == NULL || serverinfo_length == 0) {
    ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
}
```

The `ctx` check was not added to `SSL_CTX_use_PrivateKey()`.

---

## Proof of Concept

```c
/* 01-SSL_CTX_use_PrivateKey-null-ctx.c */
#include <openssl/ssl.h>
#include <openssl/evp.h>

static EVP_PKEY *make_rsa_key(void)
{
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);
    return pkey;
}

int main(void)
{
    OPENSSL_init_ssl(0, NULL);
    EVP_PKEY *pkey = make_rsa_key();
    SSL_CTX *ctx = NULL;                    /* intentionally NULL */
    SSL_CTX_use_PrivateKey(ctx, pkey);      /* SIGSEGV here */
    EVP_PKEY_free(pkey);
    return 0;
}
```

### Reproduction Steps

Compile the attached `01-SSL_CTX_use_PrivateKey-null-ctx.c` against a debug
build of OpenSSL master (`$OPENSSL` = path to source tree):

```bash
clang -g -O0 -I$OPENSSL/include 01-SSL_CTX_use_PrivateKey-null-ctx.c \
    $OPENSSL/libssl.a $OPENSSL/libcrypto.a -lpthread -ldl -o poc
./poc
```

**Observed — plain build (no sanitizers):**
```
Segmentation fault
```
Exit status: 139 (signal 11, SIGSEGV)

**Observed — ASAN/UBSAN build (additional detail):**
```bash
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I$OPENSSL/include 01-SSL_CTX_use_PrivateKey-null-ctx.c \
    $OPENSSL/libssl.a $OPENSSL/libcrypto.a -lpthread -ldl -o poc
ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" ./poc
```
```
ssl/ssl_rsa.c:390:30: runtime error: member access within null pointer of type 'SSL_CTX'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ssl/ssl_rsa.c:390:30
==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000178
SUMMARY: AddressSanitizer: SEGV ssl/ssl_rsa.c:390:30 in SSL_CTX_use_PrivateKey
    #0 SSL_CTX_use_PrivateKey  ssl/ssl_rsa.c:390
    #1 main                    01-SSL_CTX_use_PrivateKey-null-ctx.c:21
```

---

## Impact

Any caller that passes a NULL `SSL_CTX *` to `SSL_CTX_use_PrivateKey()` will
crash the process. A NULL context can reach this function when:

- `SSL_CTX_new()` returns NULL on allocation failure and the caller does not
  check the return value before calling configuration APIs.
- A multi-layer system passes the context pointer through without validating it
  at each layer.

Impact is limited to availability (process termination / denial of service).
No memory disclosure or code execution path exists at this crash site.

---

## Suggested Fix

Add a `ctx == NULL` check at function entry, matching the pattern already used
in other functions in the same file:

```diff
 int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
 {
+    if (ctx == NULL) {
+        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
+        return 0;
+    }
     if (pkey == NULL) {
         ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
         return 0;
     }
     return ssl_set_pkey(ctx->cert, pkey, ctx);
 }
```
