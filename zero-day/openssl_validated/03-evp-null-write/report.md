# NULL Pointer Write (Arbitrary Write Primitive) in `fix_rsa_padding_mode()` and `fix_rsa_pss_saltlen()`

## Summary

`fix_rsa_padding_mode()` and `fix_rsa_pss_saltlen()` in
`crypto/evp/ctrl_params_translate.c` store the caller-supplied `p2` pointer
in `ctx->orig_p2` during the `PRE_CTRL_TO_PARAMS` phase, then unconditionally
write through `ctx->orig_p2` in the `POST_CTRL_TO_PARAMS` phase — without
checking that `orig_p2` is non-NULL or otherwise valid. Calling either GET
variant with `p2 = NULL` causes a write to address 0x0 (NULL pointer
dereference write). With a freed or crafted pointer, this is an arbitrary
write primitive.

- **Affected file:** `crypto/evp/ctrl_params_translate.c`
- **Confirmed on commit:** `04623f1` (2026-04-17, OpenSSL 4.1.0-dev master)
- **Build:** ASAN + UBSAN
- **Severity:** High (NULL write → DoS; freed/crafted p2 → heap corruption / potential code execution)

---

## Vulnerable Code

### `fix_rsa_padding_mode` (lines ~1340–1365)

```c
/* PRE_CTRL_TO_PARAMS phase: save raw p2 without validation */
ctx->orig_p2 = ctx->p2;       /* ctx->p2 was set from caller's p2 = NULL */
ctx->p2 = ctx->name_buf;

/* ... provider call fills ctx->name_buf with padding name ... */

/* POST_CTRL_TO_PARAMS phase: unconditional write through orig_p2 */
} else if (state == POST_CTRL_TO_PARAMS) {
    *(int *)ctx->orig_p2 = str_value_map[i].id;  /* line 1363 — WRITE TO NULL */
}
```

### `fix_rsa_pss_saltlen` (lines ~1430–1445)

```c
} else if (state == POST_CTRL_TO_PARAMS) {
    *(int *)ctx->orig_p2 = val;   /* line 1443 — same pattern, same bug */
}
```

The `EVP_PKEY_CTRL_GET_RSA_PADDING` and `EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN`
GET commands are documented to write the retrieved value through `p2`. However,
the implementation never validates that `p2` is non-NULL before storing it or
before dereferencing it.

---

## Confirmed Crashes

| PoC | API Call | Crash Site | ASAN Type |
|-----|----------|-----------|-----------|
| `poc_rsa_padding.c` | `EVP_PKEY_CTRL_GET_RSA_PADDING` w/ `p2=NULL` | `ctrl_params_translate.c:1363` | UBSAN null write + SEGV |
| `poc_pss_salt.c` | `EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN` w/ `p2=NULL` | `ctrl_params_translate.c:1443` | UBSAN null write + SEGV |

### ASAN Output — poc_rsa_padding

```
crypto/evp/ctrl_params_translate.c:1363:13: runtime error: store to null pointer of type 'int'
==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
==The signal is caused by a WRITE memory access.
    #0 fix_rsa_padding_mode    ctrl_params_translate.c:1363:34
    #1 evp_pkey_ctx_ctrl_to_param
    #2 evp_pkey_ctx_ctrl_int
    #3 EVP_PKEY_CTX_ctrl
    #4 main                    poc_rsa_padding.c:102:11
SUMMARY: AddressSanitizer: SEGV ctrl_params_translate.c:1363:34 in fix_rsa_padding_mode
```

### ASAN Output — poc_pss_salt

```
crypto/evp/ctrl_params_translate.c:1443:13: runtime error: store to null pointer of type 'int'
==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
==The signal is caused by a WRITE memory access.
    #0 fix_rsa_pss_saltlen     ctrl_params_translate.c:1443
    #1 evp_pkey_ctx_ctrl_to_param
    #2 evp_pkey_ctx_ctrl_int
    #3 EVP_PKEY_CTX_ctrl
    #4 main                    poc_pss_salt.c:15:15
SUMMARY: AddressSanitizer: SEGV ctrl_params_translate.c in fix_rsa_pss_saltlen
```

---

## Proof of Concept

### Reproduction Steps

```bash
OPENSSL=/path/to/openssl-master

./config no-shared no-tests no-apps --debug CC=clang \
    CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
make -j$(nproc) build_libs

# EVP-RSA-PAD
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I$OPENSSL/include poc_rsa_padding.c \
    $OPENSSL/libssl.a $OPENSSL/libcrypto.a -lpthread -ldl -o poc
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" ./poc

# EVP-PSS-SALT
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I$OPENSSL/include poc_pss_salt.c \
    $OPENSSL/libssl.a $OPENSSL/libcrypto.a -lpthread -ldl -o poc2
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" ./poc2
```

---

## Impact

- **Null p2:** unconditional write to address 0x0 → immediate SIGSEGV → DoS
- **Freed p2:** use-after-free write → heap corruption → potential RCE
- **Arbitrary p2:** arbitrary 4-byte write at attacker-controlled address → privilege escalation / RCE

Any caller that passes `p2 = NULL` to `EVP_PKEY_CTX_ctrl()` with a GET command
(`EVP_PKEY_CTRL_GET_RSA_PADDING` or `EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN`) on a
PROVIDER-state context triggers this. Passing a freed pointer is a realistic
scenario in multi-step EVP key operations.

---

## Suggested Fix

```diff
 } else if (state == POST_CTRL_TO_PARAMS) {
-    *(int *)ctx->orig_p2 = str_value_map[i].id;
+    if (ctx->orig_p2 == NULL) {
+        ERR_raise(ERR_LIB_RSA, ERR_R_PASSED_NULL_PARAMETER);
+        return -1;
+    }
+    *(int *)ctx->orig_p2 = str_value_map[i].id;
 }
```

Apply the equivalent fix in `fix_rsa_pss_saltlen`. The guard in
`PRE_CTRL_TO_PARAMS` is also a valid alternative location.
