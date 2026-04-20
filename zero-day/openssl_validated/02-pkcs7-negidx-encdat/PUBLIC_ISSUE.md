# NULL dereference in `PKCS7_get_issuer_and_serial()` with negative index

## Summary

`PKCS7_get_issuer_and_serial(PKCS7 *p7, int idx)` does not validate that `idx >= 0`.
The only bounds check is:

```c
/* pk7_doit.c:1174 */
if (sk_PKCS7_RECIP_INFO_num(rsk) <= idx)
    return NULL;
```

For `idx = -1`, the comparison `num <= -1` is **false** (both sides are `int`,
`num >= 0`), so the guard passes. `sk_PKCS7_RECIP_INFO_value(rsk, -1)` returns NULL,
and the next line dereferences it:

```c
ri = sk_PKCS7_RECIP_INFO_value(rsk, idx);   /* returns NULL for idx < 0 */
return ri->issuer_and_serial;               /* NULL dereference → crash */
```


## Environment

- **Version:** OpenSSL 4.0.0 (tag `openssl-4.0.0`, commit `11b7b6e`)
- **OS:** Linux x86_64
- **Compiler:** clang with AddressSanitizer + UndefinedBehaviorSanitizer
- **Build:** `./config no-shared no-tests no-apps --debug CC=clang CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"`

## Steps to reproduce

```bash
./config no-shared no-tests no-apps --debug \
    CC=clang CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
make -j$(nproc) build_libs

OPENSSL=/tmp/openssl-4.0.0
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I"$OPENSSL/include" poc_negidx.c \
    "$OPENSSL/libssl.a" "$OPENSSL/libcrypto.a" -lpthread -ldl -o poc_negidx
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" ./poc_negidx
```

## Expected behavior

`PKCS7_get_issuer_and_serial()` returns `NULL` for any out-of-range index, including
negative values.

## Actual behavior

```
crypto/pkcs7/pk7_doit.c:1177:16: runtime error: member access within null pointer of type 'PKCS7_RECIP_INFO'
==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000008
    #0 PKCS7_get_issuer_and_serial  crypto/pkcs7/pk7_doit.c:1177
    #1 main                         poc_negidx.c
SUMMARY: AddressSanitizer: SEGV pk7_doit.c:1177:16 in PKCS7_get_issuer_and_serial
```

## Suggested fix

Add a lower-bound check before the existing guard:

```diff
 PKCS7_ISSUER_AND_SERIAL *PKCS7_get_issuer_and_serial(PKCS7 *p7, int idx)
 {
     ...
+    if (idx < 0)
+        return NULL;
     if (sk_PKCS7_RECIP_INFO_num(rsk) <= idx)
         return NULL;
     ri = sk_PKCS7_RECIP_INFO_value(rsk, idx);
     return ri->issuer_and_serial;
 }
```
