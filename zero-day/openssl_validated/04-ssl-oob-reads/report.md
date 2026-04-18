# OOB Reads in `ssl/ssl_lib.c` — DANE TLSA and `validate_cert_type`

## Summary

Two stack-buffer-overflow (OOB read) bugs in `ssl/ssl_lib.c`:

1. **SSL-DANE-OOB:** `dane_tlsa_add()` at line 328 calls `memcpy(t->data, data, dlen)` reading `dlen` bytes from the caller's `data` buffer without validating that `data` actually contains `dlen` bytes. A caller that provides a small stack buffer but inflates `dlen` triggers an OOB read.

2. **SSL-CERT-TYPE:** `validate_cert_type()` at line 8389 iterates `val[0..len-1]` without validating that the `val` buffer contains `len` bytes. Passing a 1-byte buffer with `len = 64` causes an OOB read of 63 bytes past the end.

- **Affected file:** `ssl/ssl_lib.c`
- **Confirmed on commit:** `04623f1` (2026-04-17, OpenSSL 4.1.0-dev master)
- **Build:** ASAN

---

## Bug 1 — SSL-DANE-OOB: `dane_tlsa_add` unchecked memcpy source

### Vulnerable Code

```c
/* ssl/ssl_lib.c:326 */
t->data = OPENSSL_malloc(dlen);
if (t->data == NULL) { ... }
memcpy(t->data, data, dlen);     /* line 328 — reads dlen bytes from caller's data */
```

For `mtype = DANETLS_MATCHING_FULL` (value 0), the function skips digest-based
validation of `dlen`. If the caller passes a buffer smaller than `dlen`, the
`memcpy` reads beyond the end of the caller's allocation.

### ASAN Output

```
==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fffece25ce4
READ of size 256 at 0x7fffece25ce4 thread T0
    #0 __asan_memcpy
    #1 dane_tlsa_add             ssl/ssl_lib.c:328:5
    #2 SSL_dane_tlsa_add         ssl/ssl_lib.c:1421:12
    #3 main                      poc_dane_oob.c:16:13

[32, 36) 'small_buf' (line 14) <== Memory access at offset 36 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow in __asan_memcpy
```

### Suggested Fix

```diff
+if (dlen > INT_MAX || (size_t)dlen > sizeof(stack_sized_limit)) {
+    /* validate dlen against reasonable upper bound or cert/key size */
+    ERR_raise(ERR_LIB_SSL, SSL_R_BAD_LENGTH);
+    return -1;
+}
 t->data = OPENSSL_malloc(dlen);
```

Or document and enforce that callers must pass a `data` buffer of exactly
`dlen` bytes (current documentation does not make this explicit).

---

## Bug 2 — SSL-CERT-TYPE: `validate_cert_type` OOB iteration

### Vulnerable Code

```c
/* ssl/ssl_lib.c:8389 */
for (i = 0; i < len; i++) {
    switch (val[i]) {    /* line 8389 — reads val[0..len-1] without size check */
    ...
    }
}
```

`SSL_set1_client_cert_type(ssl, val, len)` passes `(val, len)` directly to
`validate_cert_type()`. No check confirms that the `val` buffer contains at
least `len` bytes before the loop starts.

### ASAN Output

```
==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffe2e927f21
READ of size 1 at 0x7ffe2e927f21 thread T0
    #0 validate_cert_type       ssl/ssl_lib.c:8389:17
    #1 set_cert_type            ssl/ssl_lib.c:8416:10
    #2 SSL_set1_client_cert_type ssl/ssl_lib.c:8435:12
    #3 main                     poc_cert_type.c:14:13

[32, 33) 'cert_types' (line 12) <== Memory access at offset 33 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow ssl/ssl_lib.c:8389:17 in validate_cert_type
```

### Suggested Fix

The issue is in the caller (`SSL_set1_client_cert_type`) or in `set_cert_type`
— they should pass only what is verifiably within the buffer. A length sanity
check against a maximum valid type list length would also be appropriate.

---

## Proof of Concept

### Reproduction Steps

```bash
OPENSSL=/path/to/openssl-master

./config no-shared no-tests no-apps --debug CC=clang \
    CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
make -j$(nproc) build_libs

# SSL-DANE-OOB
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I$OPENSSL/include poc_dane_oob.c \
    $OPENSSL/libssl.a $OPENSSL/libcrypto.a -lpthread -ldl -o poc_dane
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" ./poc_dane

# SSL-CERT-TYPE
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I$OPENSSL/include poc_cert_type.c \
    $OPENSSL/libssl.a $OPENSSL/libcrypto.a -lpthread -ldl -o poc_cert
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" ./poc_cert
```

---

## Impact

Both bugs are triggered by the caller of OpenSSL APIs passing inconsistent
size/buffer pairs. The OOB reads can disclose stack contents. DoS (via crash)
is guaranteed when ASAN/UBSAN is enabled; without sanitizers, the behavior is
undefined but typically silent corruption or segfault.

SSL-DANE-OOB could be triggered from network-facing code if an application
propagates TLSA record data from DNS without validating the record length
against the actual data buffer size.
