# `ecp_nistz256_windowed_mul` crashes on NULL scalar despite documented contract

## Summary

The comment in `crypto/ec/ecp_nistp256.c` (line 2090) explicitly documents the `EC_POINTs_mul` API contract:

> "we treat NULL scalars as 0, and NULL points as points at infinity"

The optimized x86-64 implementation `ecp_nistz256_windowed_mul()` in `crypto/ec/ecp_nistz256.c` does **not** implement this contract. At line 637, `BN_num_bits(scalar[i])` is called unconditionally before any NULL check, causing an immediate crash when `scalar[i] == NULL`.

The inconsistency is between two implementations of the same logical interface:
- `ecp_nistp256.c` (generic): honours the NULL-scalar contract
- `ecp_nistz256.c` (x86-64 optimised): crashes on NULL scalar

## Note on deprecated API

`EC_POINTs_mul()` is marked deprecated since OpenSSL 3.0 and compiled under `#ifndef OPENSSL_NO_DEPRECATED_3_0`. It is still present in OpenSSL 4.0.0. The crash is only reachable through this deprecated function; the active `EC_POINT_mul` path never passes NULL scalars to `ecp_nistz256_points_mul`. Applications using old code that calls `EC_POINTs_mul` with error-path NULL scalars will crash on x86-64.

## Environment

- **Version:** OpenSSL 4.0.0 (tag `openssl-4.0.0`, commit `11b7b6e`)
- **OS:** Linux x86_64
- **Compiler:** clang with AddressSanitizer + UndefinedBehaviorSanitizer
- **Build:** `./config no-shared no-tests no-apps --debug CC=clang CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"`

## Steps to reproduce

I attached poc.c

```bash
cd /tmp/openssl-4.0.0
./config no-shared no-tests no-apps --debug \
    CC=clang CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
make -j$(nproc) build_libs

OPENSSL=/tmp/openssl-4.0.0
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I"$OPENSSL/include" poc.c \
    "$OPENSSL/libssl.a" "$OPENSSL/libcrypto.a" -lpthread -ldl -o poc_ec
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" ./poc_ec
```

## Expected behavior

`EC_POINTs_mul` with `scalars[i] = NULL` treats the corresponding scalar as zero, consistent with the documented contract and the `ecp_nistp256.c` implementation.

## Actual behavior (on x86-64, which routes through ecp_nistz256)

```
crypto/bn/bn_lib.c:180:16: runtime error: member access within null pointer of type 'const BIGNUM'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior bn_lib.c:180:16 in BN_num_bits
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000008
    #0 BN_num_bits                   crypto/bn/bn_lib.c:180
    #1 ecp_nistz256_windowed_mul      crypto/ec/ecp_nistz256.c:637
    #2 ecp_nistz256_points_mul        crypto/ec/ecp_nistz256.c:1124
    #3 EC_POINTs_mul                  crypto/ec/ec_lib.c
    #4 main                           poc.c
SUMMARY: AddressSanitizer: SEGV bn_lib.c:180:16 in BN_num_bits
```

## Vulnerable code

```c
/* ecp_nistz256.c:637 — no NULL check before BN_num_bits */
for (i = 0; i < num; i++) {
    P256_POINT *row = table[i];
    if ((BN_num_bits(scalar[i]) > 256) || BN_is_negative(scalar[i])) {
         /* ^ crashes if scalar[i] == NULL */
```

Compare with `ecp_nistp256.c:2093` which correctly implements the contract:
```c
for (i = 0; i < num_points; ++i) {
    if (scalars[i] == NULL)
        continue;  /* skip — treated as 0 */
```

## Suggested fix

```diff
 for (i = 0; i < num; i++) {
     P256_POINT *row = table[i];
+    if (scalar[i] == NULL)
+        continue;  /* treat NULL scalar as 0 per documented contract */
     if ((BN_num_bits(scalar[i]) > 256) || BN_is_negative(scalar[i])) {
```

Alternatively, `EC_POINTs_mul` could filter NULL scalars before dispatching to the
method, providing a single authoritative fix across all backends.
