# NULL pointer write in `EVP_PKEY_CTX_get_rsa_padding()` and `EVP_PKEY_CTX_get_rsa_pss_saltlen()` when output pointer is NULL

## Summary

`EVP_PKEY_CTX_get_rsa_padding()` and `EVP_PKEY_CTX_get_rsa_pss_saltlen()` do not validate that the output-pointer argument is non-NULL before writing to it. Passing `NULL` causes a NULL pointer write (SIGBUS/SEGV) instead of a proper error return.

The affected functions in `crypto/evp/ctrl_params_translate.c`:
- `fix_rsa_padding_mode()` at line 1363: `*(int *)ctx->orig_p2 = str_value_map[i].id;`
- `fix_rsa_pss_saltlen()` at line 1443: `*(int *)ctx->orig_p2 = val;`

`ctx->orig_p2` is set from the caller's `p2` argument during `PRE_CTRL_TO_PARAMS`.
No NULL check precedes either store.

## Environment

- **Version:** OpenSSL 4.0.0 (tag `openssl-4.0.0`, commit `11b7b6e`)
- **OS:** Linux x86_64
- **Compiler:** clang with AddressSanitizer + UndefinedBehaviorSanitizer
- **Build:** `./config no-shared no-tests no-apps --debug CC=clang CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"`

## Steps to reproduce

I attached poc_minimal.c

```bash
cd /tmp/openssl-4.0.0
./config no-shared no-tests no-apps --debug \
    CC=clang CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
make -j$(nproc) build_libs

OPENSSL=/tmp/openssl-4.0.0
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I"$OPENSSL/include" poc_minimal.c \
    "$OPENSSL/libssl.a" "$OPENSSL/libcrypto.a" -lpthread -ldl -o poc_evp
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" ./poc_evp
```

## Expected behavior

`EVP_PKEY_CTX_get_rsa_padding(ctx, NULL)` returns `-1` and sets an error
(`EVP_R_MISSING_PARAMETERS` or similar). Same for `EVP_PKEY_CTX_get_rsa_pss_saltlen`.

## Actual behavior

```
crypto/evp/ctrl_params_translate.c:1363:13: runtime error: store to null pointer of type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ctrl_params_translate.c:1363:13 in fix_rsa_padding_mode
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
SUMMARY: AddressSanitizer: SEGV ctrl_params_translate.c:1363:34 in fix_rsa_padding_mode
```

## Root cause

The ctrl-to-params translation for `EVP_PKEY_CTRL_GET_RSA_PADDING` saves the caller's `p2` into `ctx->orig_p2` without checking for NULL:

```c
/* ctrl_params_translate.c:1280 */
ctx->orig_p2 = ctx->p2;   /* p2 = NULL from caller → orig_p2 = NULL */

/* ... later at POST_CTRL_TO_PARAMS: */
*(int *)ctx->orig_p2 = str_value_map[i].id;  /* write to NULL → crash */
```

The same pattern exists in `fix_rsa_pss_saltlen` at line 1401/1443.

## Suggested fix

Add a NULL guard in both functions, or add it in the public wrapper:

```diff
+/* In EVP_PKEY_CTX_get_rsa_padding() wrapper: */
 int EVP_PKEY_CTX_get_rsa_padding(EVP_PKEY_CTX *ctx, int *pad_mode)
 {
+    if (pad_mode == NULL) {
+        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
+        return -1;
+    }
     return RSA_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_GET_RSA_PADDING, 0, pad_mode);
 }
```

Or alternatively at the `ctrl_params_translate.c` layer:

```diff
 } else if (state == POST_CTRL_TO_PARAMS) {
+    if (ctx->orig_p2 == NULL) {
+        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
+        return -1;
+    }
     *(int *)ctx->orig_p2 = str_value_map[i].id;
```
