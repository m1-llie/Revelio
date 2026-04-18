# Heap OOB Read in `tls_handle_alpn()` via Malicious ALPN Select Callback

## Summary

`tls_handle_alpn()` in `ssl/statem/statem_srvr.c` calls
`OPENSSL_memdup(selected, selected_len)` at line 2392 without validating that
the `selected` buffer returned by the ALPN select callback actually contains
`selected_len` bytes. A callback that returns a 1-byte allocation but sets
`*outlen = 255` causes `OPENSSL_memdup` to read 254 bytes past the end of the
heap allocation.

- **Affected file:** `ssl/statem/statem_srvr.c`
- **Confirmed on commit:** `04623f1` (2026-04-17, OpenSSL 4.1.0-dev master)
- **Build:** ASAN
- **Severity:** Medium (heap OOB read; information disclosure potential; DoS)

---

## Vulnerable Code

```c
/* ssl/statem/statem_srvr.c:2383 */
int r = sctx->ext.alpn_select_cb(SSL_CONNECTION_GET_USER_SSL(s),
    &selected, &selected_len,
    s->s3.alpn_proposed, (unsigned int)s->s3.alpn_proposed_len,
    sctx->ext.alpn_select_cb_arg);

if (r == SSL_TLSEXT_ERR_OK) {
    OPENSSL_free(s->s3.alpn_selected);
    s->s3.alpn_selected = OPENSSL_memdup(selected, selected_len);  /* line 2392 */
```

The function trusts `selected_len` as returned by the callback. No check
confirms that `selected` points to a buffer of at least `selected_len` bytes
before the `memdup` reads from it.

---

## ASAN Output

```
==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000010a71
READ of size 255 at 0x602000010a71 thread T0
    #0 __asan_memcpy
    #1 CRYPTO_memdup              crypto/o_str.c:65:12
    #2 tls_handle_alpn            ssl/statem/statem_srvr.c:2392:35
    #3 tls_post_process_client_hello  ssl/statem/statem_srvr.c:2548:45
    #4 ossl_statem_server_post_process_message
    #5 read_state_machine
    #6 SSL_do_handshake

0x602000010a71 is located 0 bytes to the right of 1-byte region [0x602000010a70,0x602000010a71)
allocated by thread T0 here:
    #0 malloc
    #1 CRYPTO_malloc
    #2 alpn_select_cb_oob        poc.c:92:37     ← 1-byte malloc, outlen=255
    #3 tls_handle_alpn            statem_srvr.c:2384:17

SUMMARY: AddressSanitizer: heap-buffer-overflow in __asan_memcpy
```

---

## Proof of Concept

See attached `poc.c`. Sets up a TLS server with an ALPN callback that returns
`malloc(1)` (1-byte buffer) but sets `*outlen = 255`. Any TLS handshake attempt
then triggers the overflow in `tls_handle_alpn`.

### Reproduction Steps

```bash
OPENSSL=/path/to/openssl-master

./config no-shared no-tests no-apps --debug CC=clang \
    CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
make -j$(nproc) build_libs

clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I$OPENSSL/include poc.c \
    $OPENSSL/libssl.a $OPENSSL/libcrypto.a -lpthread -ldl -o poc
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" ./poc
```

---

## Impact

The heap OOB read discloses heap contents (up to 254 bytes in the PoC).
The size is limited only by `selected_len` which is a `uint8_t` (max 255).
Applications using ALPN with dynamically-computed `selected_len` values or
library bindings that do not tightly enforce buffer sizes are affected.

---

## Suggested Fix

The ALPN API contract states that `selected` must point to a buffer of at
least `*outlen` bytes. Document this more prominently and add a defensive
assertion or size limit in `tls_handle_alpn`:

```diff
+if (selected_len == 0 || selected == NULL) {
+    SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
+    return 0;
+}
 s->s3.alpn_selected = OPENSSL_memdup(selected, selected_len);
```

Note: this is a defense-in-depth fix. The fundamental contract is that the
callback must return a valid buffer; OpenSSL cannot verify this without
copying.
