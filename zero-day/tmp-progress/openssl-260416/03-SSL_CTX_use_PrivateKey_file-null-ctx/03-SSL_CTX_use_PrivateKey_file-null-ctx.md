# NULL Pointer Dereference in `SSL_CTX_use_PrivateKey_file()`

## Summary

`SSL_CTX_use_PrivateKey_file()` in `ssl/ssl_rsa.c` validates the `file`
parameter (guards against NULL) but does not validate `ctx`. The function opens
the file into a BIO successfully, then immediately dereferences
`ctx->default_passwd_callback` without first checking that `ctx` is non-NULL.
The crash reproduces on a plain debug build — no sanitizers required.

- **Affected file:** `ssl/ssl_rsa.c`
- **Confirmed on commit:** `6983b5c` (2026-04-16, OpenSSL master)
- **Crash address:** `ssl_rsa.c:417` — `ctx->default_passwd_callback` access through NULL
- **Impact:** Denial of service (process crash)

---

## Vulnerable Code

```c
// ssl/ssl_rsa.c (master, line 393)
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
    int j, ret = 0;
    BIO *in = NULL;
    EVP_PKEY *pkey = NULL;

    if (file == NULL) {                    // file IS guarded …
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        goto end;
    }

    in = BIO_new(BIO_s_file());
    // … BIO opened from file successfully …

    if (type == SSL_FILETYPE_PEM) {
        pkey = PEM_read_bio_PrivateKey_ex(in, NULL,
            ctx->default_passwd_callback,          // line 417 — ctx NOT checked
            ctx->default_passwd_callback_userdata,
            ctx->libctx,
            ctx->propq);
    } else if (type == SSL_FILETYPE_ASN1) {
        pkey = d2i_PrivateKey_ex_bio(in, NULL, ctx->libctx, ctx->propq);
    }
    // …
}
```

`file == NULL` is checked at line 399; `ctx == NULL` is not. The crash occurs
at line 417 after the file has already been opened — before any key material
is parsed.

---

## Proof of Concept

```c
/* 03-SSL_CTX_use_PrivateKey_file-null-ctx.c */
#include <openssl/ssl.h>

int main(void)
{
    OPENSSL_init_ssl(0, NULL);

    SSL_CTX *ctx = NULL;   /* intentionally NULL */
    /* Any readable path works; crash is before file content is parsed */
    SSL_CTX_use_PrivateKey_file(ctx, "/dev/null", SSL_FILETYPE_PEM); /* SIGSEGV */
    return 0;
}
```

### Reproduction Steps

Compile the attached `03-SSL_CTX_use_PrivateKey_file-null-ctx.c` against a
debug build of OpenSSL master (`$OPENSSL` = path to source tree):

```bash
clang -g -O0 -I$OPENSSL/include 03-SSL_CTX_use_PrivateKey_file-null-ctx.c \
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
    -I$OPENSSL/include 03-SSL_CTX_use_PrivateKey_file-null-ctx.c \
    $OPENSSL/libssl.a $OPENSSL/libcrypto.a -lpthread -ldl -o poc
ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" ./poc
```
```
ssl/ssl_rsa.c:417:18: runtime error: member access within null pointer of type 'SSL_CTX'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ssl/ssl_rsa.c:417:18
==ERROR: AddressSanitizer: SEGV on unknown address 0x0000000000d8
SUMMARY: AddressSanitizer: SEGV ssl/ssl_rsa.c:417:18 in SSL_CTX_use_PrivateKey_file
    #0 SSL_CTX_use_PrivateKey_file  ssl/ssl_rsa.c:417
    #1 main                         03-SSL_CTX_use_PrivateKey_file-null-ctx.c:7
```

---

## Impact

Any caller that passes a NULL `SSL_CTX *` to `SSL_CTX_use_PrivateKey_file()`
with a valid file path will crash the process. The crash occurs before file
content is parsed — the file itself does not need to contain valid key material.

A NULL context can reach this function when:

- `SSL_CTX_new()` returns NULL on allocation failure and the caller does not
  check the return value before calling configuration APIs.
- A multi-layer system passes the context pointer through without validating it
  at each layer.

Impact is limited to availability (process termination / denial of service).
No memory disclosure or code execution path exists at this crash site.

---

## Suggested Fix

Add a `ctx == NULL` check alongside the existing `file == NULL` check at
function entry:

```diff
 int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
 {
     int j, ret = 0;
     BIO *in = NULL;
     EVP_PKEY *pkey = NULL;

+    if (ctx == NULL) {
+        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
+        goto end;
+    }
     if (file == NULL) {
         ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
         goto end;
     }
     // …
 }
```


