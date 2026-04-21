# `curl_easy_ssls_import()` should reject `sdata == NULL` when `sdata_len > 0`

## Description

### I did this
I reproduced a null-dereference path in `curl_easy_ssls_import()` when `sdata` is `NULL` but `sdata_len` is non-zero. `Curl_ssl_session_import()` passes the buffer directly into `Curl_ssl_session_unpack()` without validating that `sdata` is non-NULL. In release-style behavior that reaches `spack_dec8()` and dereferences a null pointer.

The attached `poc.c` calls `curl_easy_ssls_import()` with a non-NULL `session_key`, `sdata = NULL`, and `sdata_len = 1`, and it crashes in the unpack path. This was observed on curl 8.20.0-DEV (`70281e3`) with `--enable-ssls-export`.

### I expected the following
`curl_easy_ssls_import()` should reject `sdata == NULL` when `sdata_len > 0` before calling the unpack helper.

### curl/libcurl version
Reproduced against curl 8.20.0-DEV (`70281e3`) with the SSLS export/import feature enabled.

### operating system
Linux x86_64

## Reproduction notes
Build curl with `--enable-ssls-export`, then compile and run the attached `poc.c`.

Example:

```bash
autoreconf -fi
CC=clang CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=address,undefined" \
./configure --disable-shared --enable-ssls-export --with-openssl \
  --disable-docs --disable-manual
make -j"$(nproc)"
# If configure fails on optional deps (e.g. libpsl), add --without-libpsl

clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
  -I./include -I./lib \
  poc.c ./lib/.libs/libcurl.a \
  -lssl -lcrypto -lz -lpthread -ldl \
  -o /tmp/poc_curl_ssls_import_null

ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  /tmp/poc_curl_ssls_import_null
```

Observed result:

```text
vtls/vtls_spack.c:245:34: runtime error: applying non-zero offset 1 to null pointer
    #0 Curl_ssl_session_unpack /src/curl/lib/vtls/vtls_spack.c:245
    #1 Curl_ssl_session_import /src/curl/lib/vtls/vtls_scache.c:1097
    #2 main poc.c:61
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior vtls/vtls_spack.c:245:34
Assertion `buf' failed. (Aborted)
```
