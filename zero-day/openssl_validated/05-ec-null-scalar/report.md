# NULL Scalar Dereference in `ecp_nistz256_windowed_mul` — Broken API Contract

## Summary

`ecp_nistz256_windowed_mul()` in `crypto/ec/ecp_nistz256.c` calls
`BN_num_bits(scalar[i])` at line 637 without checking whether `scalar[i]` is
NULL. A comment in the source states "NULL scalars are treated as 0", but this
invariant is not implemented — passing a NULL scalar triggers an immediate NULL
pointer dereference.

- **Affected file:** `crypto/ec/ecp_nistz256.c`
- **Trigger:** `EC_POINTs_mul(group, r, NULL, 1, points, scalars, ctx)` where `scalars[0] == NULL` but `points[0] != NULL`
- **Confirmed on commit:** `04623f1` (2026-04-17, OpenSSL 4.1.0-dev master)
- **Build:** ASAN + UBSAN
- **Severity:** Medium (DoS; broken documented API contract)

---

## Vulnerable Code

```c
/* crypto/ec/ecp_nistz256.c:637 */
for (i = 0; i < num; i++) {
    P256_POINT *row = table[i];

    /* This is an unusual input, we don't guarantee constant-timeness. */
    if ((BN_num_bits(scalar[i]) > 256) || BN_is_negative(scalar[i])) {
        /* ^ scalar[i] == NULL → BN_num_bits() dereferences NULL at bn_lib.c:180 */
```

The comment above the function says scalars can be NULL (meaning treat as zero),
but the first use of `scalar[i]` is an unconditional `BN_num_bits()` call.

---

## ASAN Output

```
crypto/bn/bn_lib.c:180:16: runtime error: member access within null pointer of type 'const BIGNUM'
==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000008
==The signal is caused by a READ memory access.
    #0 BN_num_bits              crypto/bn/bn_lib.c:180:16
    #1 ecp_nistz256_windowed_mul crypto/ec/ecp_nistz256.c:637:14
    #2 ecp_nistz256_points_mul   crypto/ec/ecp_nistz256.c:1124:14
    #3 EC_POINTs_mul             crypto/ec/ec_lib.c:1151:15
    #4 main                     poc.c:68:15

SUMMARY: AddressSanitizer: SEGV crypto/bn/bn_lib.c:180:16 in BN_num_bits
```

---

## Proof of Concept

See attached `poc.c`. The PoC creates an EC_GROUP for P-256, allocates a point,
and calls `EC_POINTs_mul` with one entry where `scalars[0] = NULL`.

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

Any caller of `EC_POINTs_mul` that passes a NULL scalar alongside a non-NULL
point (a valid use case per the comment in the source) will crash the process.
This can be reached from TLS code during ECDH/ECDSA operations if a NULL scalar
is produced by an error path that does not propagate the error properly.

---

## Suggested Fix

```diff
 for (i = 0; i < num; i++) {
     P256_POINT *row = table[i];

-    if ((BN_num_bits(scalar[i]) > 256) || BN_is_negative(scalar[i])) {
+    if (scalar[i] == NULL) {
+        /* NULL scalar → treat as 0: skip this point */
+        continue;  /* or handle as zero scalar per documented contract */
+    }
+    if ((BN_num_bits(scalar[i]) > 256) || BN_is_negative(scalar[i])) {
```
