# `encoder_base64_size()` overflows for very large `datasize` values

## Description

### I did this
I reproduced a signed integer overflow in `encoder_base64_size()` by creating a MIME part with `datasize = LLONG_MAX` and base64 encoding enabled. The formula in `lib/mime.c` performs signed arithmetic without overflow checks and UBSan reports overflow when `Curl_creader_set_mime()` reaches `mime_size()`.

The attached `poc.c` demonstrates this with curl 8.20.0-DEV (`70281e3`).

### I expected the following
The size calculation should detect overflow and return an error or an "unknown size" result instead of invoking undefined behavior.

### curl/libcurl version
curl 8.20.0-DEV (`70281e3`).

### operating system
Linux x86_64

## Reproduction notes
Build curl with UBSan enabled, then compile and run the attached `poc.c`.

Example:

```bash
autoreconf -fi
CC=clang CFLAGS="-fsanitize=undefined -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=undefined" \
./configure --disable-shared --with-openssl --disable-docs --disable-manual
make -j"$(nproc)"
# If configure fails on optional deps (e.g. libpsl), add --without-libpsl

clang -fsanitize=undefined -fno-omit-frame-pointer -g -O1 \
  -I./include -I./lib \
  poc.c ./lib/.libs/libcurl.a \
  -lssl -lcrypto -lz -lpthread -ldl \
  -o /tmp/poc_curl_mime_base64_overflow

UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  /tmp/poc_curl_mime_base64_overflow
```

Observed result:

```text
mime.c:427:12: runtime error: signed integer overflow: 4 * 3074457345618258603 cannot be represented in type 'curl_off_t' (aka 'long')
    #0 encoder_base64_size /src/curl/lib/mime.c:427
    #1 mime_size /src/curl/lib/mime.c:1577
    #2 Curl_creader_set_mime /src/curl/lib/mime.c:2121
    #3 main poc.c:93
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior mime.c:427:12
```
