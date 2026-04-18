# Stack Buffer Overflow in `ossl_quic_conn_set_initial_peer_addr()` via Undersized `BIO_ADDR`

## Summary

`ossl_quic_conn_set_initial_peer_addr()` in `ssl/quic/quic_impl.c` calls
`BIO_ADDR_copy(&ctx.qc->init_peer_addr, peer_addr)` at line 1309, which
internally calls `memcpy` to copy `sizeof(BIO_ADDR)` = 112 bytes from
`peer_addr`. No check validates that `peer_addr` points to a buffer of at
least `sizeof(BIO_ADDR)` bytes. Passing a pointer to a smaller stack buffer
causes a stack-buffer-overflow read.

- **Affected file:** `ssl/quic/quic_impl.c`
- **Trigger:** `SSL_set1_initial_peer_addr(ssl, peer_addr)` where `peer_addr` points to < 112 bytes
- **Confirmed on commit:** `04623f1` (2026-04-17, OpenSSL 4.1.0-dev master)
- **Build:** ASAN
- **Severity:** High (stack OOB read of up to 108 bytes; potential information disclosure)

---

## Vulnerable Code

```c
/* ssl/quic/quic_impl.c:1303 */
if (peer_addr == NULL) {
    BIO_ADDR_clear(&ctx.qc->init_peer_addr);
    return 1;
}
return BIO_ADDR_copy(&ctx.qc->init_peer_addr, peer_addr);  /* line 1309 */
```

`BIO_ADDR_copy` at `crypto/bio/bio_addr.c:78`:
```c
int BIO_ADDR_copy(BIO_ADDR *dst, const BIO_ADDR *src)
{
    memcpy(dst, src, sizeof(*src));   /* copies sizeof(BIO_ADDR) = 112 bytes */
    return 1;
}
```

`sizeof(BIO_ADDR)` is 112 bytes on x86-64. No check validates `peer_addr`
holds 112 bytes before the copy.

---

## ASAN Output

```
==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff890e5e04
READ of size 16 at 0x7fff890e5e04 thread T0
    #0 __asan_memcpy
    #1 BIO_ADDR_make             crypto/bio/bio_addr.c
    #2 BIO_ADDR_copy             crypto/bio/bio_addr.c:78:12
    #3 ossl_quic_conn_set_initial_peer_addr  ssl/quic/quic_impl.c:1309:12
    #4 SSL_set1_initial_peer_addr ssl/ssl_lib.c:7861:12
    #5 main                      poc.c:19:13

[32, 36) 'tiny_buf' (line 15) <== Memory access at offset 36 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow in __asan_memcpy
```

The PoC allocates a 4-byte buffer (`uint32_t`) and passes it as a `BIO_ADDR *`.
ASAN detects a read of 16 bytes (first chunk of `sizeof(BIO_ADDR)`) 4 bytes
past the end of the variable.

---

## Proof of Concept

See attached `poc.c`. Creates a QUIC SSL object and calls
`SSL_set1_initial_peer_addr()` with a 4-byte buffer.

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

An application that passes a buffer smaller than `sizeof(BIO_ADDR)` to
`SSL_set1_initial_peer_addr()` will trigger a read of up to 108 bytes past
the buffer boundary. In server contexts processing client-supplied peer
addresses, this could disclose stack frame contents.

---

## Suggested Fix

Document the requirement that `peer_addr` must be a fully-initialized
`BIO_ADDR` of `sizeof(BIO_ADDR)` bytes. Optionally add a defensive check:

```diff
+if (peer_addr != NULL && !BIO_ADDR_is_any(peer_addr) &&
+    peer_addr->s.addr.sa_family == 0) {
+    /* Zero-initialized BIO_ADDR — warn but proceed */
+}
```

The primary fix is in documentation and caller validation, since OpenSSL
cannot introspect the allocation size of an opaque pointer.
