# NULL Pointer Dereference in `PKCS7_get_issuer_and_serial()` and `PKCS7_dataInit()` — 2 Confirmed Crashes

## Summary

Two additional NULL-pointer dereferences in `crypto/pkcs7/pk7_doit.c`:

1. **PK-NEGIDX:** `PKCS7_get_issuer_and_serial()` at line 1177 does not validate
   that `idx` is non-negative before calling `sk_PKCS7_RECIP_INFO_value()`.
   A negative index maps to a NULL pointer, causing an immediate SIGSEGV.

2. **PK-ENCDAT:** `PKCS7_dataInit()` at line 286 dereferences
   `p7->d.enveloped->enc_data` without checking that `enc_data` is non-NULL.
   Setting `enc_data = NULL` after type construction crashes in the enveloped
   branch.

- **Affected file:** `crypto/pkcs7/pk7_doit.c`
- **Confirmed on commit:** `04623f1` (2026-04-17, OpenSSL 4.1.0-dev master)
- **Build:** ASAN + UBSAN

---

## Bug 1 — PK-NEGIDX: Negative Index in `PKCS7_get_issuer_and_serial`

### Vulnerable Code

```c
/* pk7_doit.c ~line 1175 */
PKCS7_ISSUER_AND_SERIAL *PKCS7_get_issuer_and_serial(PKCS7 *p7, int idx)
{
    STACK_OF(PKCS7_RECIP_INFO) *rsk;
    ...
    rsk = p7->d.enveloped->recipientinfo;
    ri = sk_PKCS7_RECIP_INFO_value(rsk, idx);  /* line 1177 — no lower-bound check */
    return ri->issuer_and_serial;
```

`sk_PKCS7_RECIP_INFO_value()` returns NULL for out-of-range indices (including
all negative values). The next line dereferences the returned NULL pointer.

### ASAN Output

```
crypto/pkcs7/pk7_doit.c:1177:16: runtime error: member access within null pointer of type 'PKCS7_RECIP_INFO'
==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000008
    #0 PKCS7_get_issuer_and_serial  pk7_doit.c:1177:16
    #1 main                         poc_SF13.c:86:36
SUMMARY: AddressSanitizer: SEGV pk7_doit.c:1177:16 in PKCS7_get_issuer_and_serial
```

### Suggested Fix

```diff
 ri = sk_PKCS7_RECIP_INFO_value(rsk, idx);
+if (ri == NULL)
+    return NULL;
 return ri->issuer_and_serial;
```

---

## Bug 2 — PK-ENCDAT: NULL `enc_data` Dereference in `PKCS7_dataInit`

### Vulnerable Code

```c
/* pk7_doit.c:284 */
case NID_pkcs7_enveloped:
    rsk  = p7->d.enveloped->recipientinfo;
    xalg = p7->d.enveloped->enc_data->algorithm;    /* line 286 — enc_data not checked */
    evp_cipher = p7->d.enveloped->enc_data->cipher;
```

`p7->d.enveloped->enc_data` can legally be NULL if the caller frees it or sets
it to NULL after construction. No NULL check precedes the member access.

### ASAN Output

```
crypto/pkcs7/pk7_doit.c:286:43: runtime error: member access within null pointer of type 'PKCS7_ENC_CONTENT'
==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000008
    #0 PKCS7_dataInit  pk7_doit.c:286:43
    #1 main            poc_SF16.c:55:16
SUMMARY: AddressSanitizer: SEGV pk7_doit.c:286:43 in PKCS7_dataInit
```

### Suggested Fix

```diff
 case NID_pkcs7_enveloped:
     rsk = p7->d.enveloped->recipientinfo;
+    if (p7->d.enveloped->enc_data == NULL) {
+        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_NO_CONTENT);
+        goto err;
+    }
     xalg = p7->d.enveloped->enc_data->algorithm;
```

---

## Proof of Concept

### Reproduction Steps

```bash
OPENSSL=/path/to/openssl-master

./config no-shared no-tests no-apps --debug CC=clang \
    CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
make -j$(nproc) build_libs

# PK-NEGIDX
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I$OPENSSL/include poc_SF13.c \
    $OPENSSL/libssl.a $OPENSSL/libcrypto.a -lpthread -ldl -o poc13
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" ./poc13

# PK-ENCDAT
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I$OPENSSL/include poc_SF16.c \
    $OPENSSL/libssl.a $OPENSSL/libcrypto.a -lpthread -ldl -o poc16
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" ./poc16
```

---

## Impact

Both bugs cause immediate process termination (SIGSEGV) — denial of service.
PK-NEGIDX is reachable from any caller that controls the `idx` parameter of
`PKCS7_get_issuer_and_serial()`. PK-ENCDAT is reachable from any caller that
modifies `enc_data` after PKCS7 construction.
