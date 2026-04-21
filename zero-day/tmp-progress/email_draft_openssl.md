---
To: openssl-security@openssl.org
Subject: [ssl/ssl_rsa.c] Four missing ctx==NULL guards — NULL pointer dereference DoS
Attachments:
  01-SSL_CTX_use_PrivateKey-null-ctx.md
  01-SSL_CTX_use_PrivateKey-null-ctx.c
  02-SSL_CTX_use_certificate_ASN1-null-ctx.md
  02-SSL_CTX_use_certificate_ASN1-null-ctx.c
  03-SSL_CTX_use_PrivateKey_file-null-ctx.md
  03-SSL_CTX_use_PrivateKey_file-null-ctx.c
  04-SSL_CTX_use_PrivateKey_ASN1-null-ctx.md
  04-SSL_CTX_use_PrivateKey_ASN1-null-ctx.c
---

Hello OpenSSL Team,

I am reporting four NULL pointer dereference bugs in `ssl/ssl_rsa.c`, all sharing the same root cause: the `ctx` parameter of public `SSL_CTX_*` API functions is not validated before being dereferenced. Each issue causes an immediate process crash (SIGSEGV) when a NULL `SSL_CTX *` is passed, which constitutes a denial-of-service condition.

All four have been confirmed on the current master branch (commit 6983b5c, 2026-04-16). The crashes reproduce on a plain debug build with no sanitizers required.

| # | Function | File | Crash site |
|---|----------|------|------------|
| 1 | `SSL_CTX_use_PrivateKey()` | `ssl/ssl_rsa.c` | line 390 — `ctx->cert` |
| 2 | `SSL_CTX_use_certificate_ASN1()` | `ssl/ssl_rsa.c` | line 367 — `ctx->libctx` |
| 3 | `SSL_CTX_use_PrivateKey_file()` | `ssl/ssl_rsa.c` | line 417 — `ctx->default_passwd_callback` |
| 4 | `SSL_CTX_use_PrivateKey_ASN1()` | `ssl/ssl_rsa.c` | line 446 — `ctx->libctx` |

A self-contained PoC and bug report are attached for each function.

I am reporting these together as a batch because they share a single root cause, affect the same source file, and can be fixed in a single patch.

Thank you for your time.
