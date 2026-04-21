# NULL Pointer Dereference in `SSL_CTX_use_PrivateKey_ASN1()`

## Summary

`SSL_CTX_use_PrivateKey_ASN1()` in `ssl/ssl_rsa.c` passes `ctx->libctx` and
`ctx->propq` directly to `d2i_PrivateKey_ex()` without checking whether `ctx`
is NULL. Passing a NULL `SSL_CTX *` causes an immediate SIGSEGV before any
key data is parsed. The crash reproduces on a plain debug build — no sanitizers
required.

- **Affected file:** `ssl/ssl_rsa.c`
- **Confirmed on commit:** `6983b5c` (2026-04-16, OpenSSL master)
- **Crash address:** `ssl_rsa.c:446` — `ctx->libctx` member access through NULL
- **Impact:** Denial of service (process crash)

---

## Vulnerable Code

```c
// ssl/ssl_rsa.c (master, line 438)
int SSL_CTX_use_PrivateKey_ASN1(int type, SSL_CTX *ctx,
    const unsigned char *d, long len)
{
    int ret;
    const unsigned char *p;
    EVP_PKEY *pkey;

    p = d;
    if ((pkey = d2i_PrivateKey_ex(type, NULL, &p, (long)len,
             ctx->libctx,    // line 446 — ctx NOT checked before this
             ctx->propq))
        == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_ASN1_LIB);
        return 0;
    }
    // …
}
```

`ctx` is used at line 446 as the first action in the function body, before any
NULL validation.

---

## Proof of Concept

```c
/* 04-SSL_CTX_use_PrivateKey_ASN1-null-ctx.c */
#include <openssl/ssl.h>
#include <openssl/evp.h>

int main(void)
{
    OPENSSL_init_ssl(0, NULL);

    /* Minimal DER stub — crash happens before any parsing */
    static const unsigned char der[] = { 0x30, 0x06, 0x02, 0x01, 0x00,
                                         0x02, 0x01, 0x00 };

    SSL_CTX *ctx = NULL;   /* intentionally NULL */
    SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx, der, sizeof(der)); /* SIGSEGV */
    return 0;
}
```

### Reproduction Steps

Compile the attached `04-SSL_CTX_use_PrivateKey_ASN1-null-ctx.c` against a
debug build of OpenSSL master (`$OPENSSL` = path to source tree):

```bash
clang -g -O0 -I$OPENSSL/include 04-SSL_CTX_use_PrivateKey_ASN1-null-ctx.c \
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
    -I$OPENSSL/include 04-SSL_CTX_use_PrivateKey_ASN1-null-ctx.c \
    $OPENSSL/libssl.a $OPENSSL/libcrypto.a -lpthread -ldl -o poc
ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" ./poc
```
```
ssl/ssl_rsa.c:446:67: runtime error: member access within null pointer of type 'SSL_CTX'
ssl/ssl_rsa.c:446:67: runtime error: load of null pointer of type 'OSSL_LIB_CTX *'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ssl/ssl_rsa.c:446:67
==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
SUMMARY: AddressSanitizer: SEGV ssl/ssl_rsa.c:446:67 in SSL_CTX_use_PrivateKey_ASN1
    #0 SSL_CTX_use_PrivateKey_ASN1  ssl/ssl_rsa.c:446
    #1 main                         04-SSL_CTX_use_PrivateKey_ASN1-null-ctx.c:12
```

---

## Impact

Any caller that passes a NULL `SSL_CTX *` to `SSL_CTX_use_PrivateKey_ASN1()`
will crash the process. The crash occurs before any ASN.1 parsing of the key
data — the buffer contents are irrelevant to triggering the crash.

A NULL context can reach this function when:

- `SSL_CTX_new()` returns NULL on allocation failure and the caller does not
  check the return value before calling configuration APIs.
- A multi-layer system passes the context pointer through without validating it
  at each layer.

Impact is limited to availability (process termination / denial of service).
No memory disclosure or code execution path exists at this crash site.

---

## Suggested Fix

Add a NULL check for `ctx` (and `d`) at function entry:

```diff
 int SSL_CTX_use_PrivateKey_ASN1(int type, SSL_CTX *ctx,
     const unsigned char *d, long len)
 {
+    if (ctx == NULL || d == NULL) {
+        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
+        return 0;
+    }
     int ret;
     const unsigned char *p;
     EVP_PKEY *pkey;
     // …
 }
```
