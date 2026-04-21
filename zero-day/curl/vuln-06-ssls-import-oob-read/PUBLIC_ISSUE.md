# `curl_easy_ssls_import()` trusts `shmac_len` without protecting against undersized backing storage

## Description

### I did this
I reproduced an out-of-bounds read in `curl_easy_ssls_import()` when `session_key == NULL` and `shmac_len` is set to 64 even though the actual `shmac` buffer is smaller. In the tested code path, `Curl_ssl_session_import()` accepts the claimed length and then `cf_ssl_scache_peer_init()` copies two 32-byte chunks from `shmac`.

The attached `poc.c` passes a 10-byte buffer with `shmac_len = 64` and triggers AddressSanitizer in `lib/vtls/vtls_scache.c`. I observed this on curl GitHub HEAD `54ded66618a2388e88e715c5eb4477d1083582ef` with `--enable-ssls-export`.

### I expected the following
The API should reject inconsistent pointer/length combinations instead of blindly reading the claimed byte count.

### curl/libcurl version
Reproduced against curl GitHub HEAD `54ded66618a2388e88e715c5eb4477d1083582ef` with `--disable-shared --enable-ssls-export --with-openssl`.

### operating system
Linux x86_64

## Reproduction notes
Build curl with `--enable-ssls-export`:

```bash
autoreconf -fi
CC=clang CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=address,undefined" \
./configure --disable-shared --enable-ssls-export --with-openssl \
  --disable-docs --disable-manual
make -j"$(nproc)"
```

If `configure` fails due to optional dependencies such as `libpsl`, add `--without-libpsl`.

Compile the attached `poc.c` against the resulting static libcurl:

```bash
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
  -I./include -I./lib \
  poc.c ./lib/.libs/libcurl.a \
  -lssl -lcrypto -lz -lpthread -ldl \
  -o /tmp/poc_curl_ssls_import_oob
```

Run it:

```bash
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  /tmp/poc_curl_ssls_import_oob
```

Observed result:

```text
ERROR: AddressSanitizer: stack-buffer-overflow
#1 cf_ssl_scache_peer_init /src/curl/lib/vtls/vtls_scache.c:458
```
