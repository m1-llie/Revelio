# `client_cert()` should guard `SSL_get_privatekey()` before calling `EVP_PKEY_id()`

## Description

### I did this
I reproduced a crash pattern in curl's OpenSSL client-certificate handling where `client_cert()` calls `EVP_PKEY_id()` on the result of `SSL_get_privatekey()` without checking whether that call returned `NULL`.

The attached `poc.c` demonstrates the same OpenSSL call sequence directly on a fresh `SSL` object with no private key loaded. The affected code is in `lib/vtls/openssl.c` around lines 1567-1571 in the curl 8.20.0-DEV tree I tested (`70281e3`).

### I expected the following
curl should verify that `SSL_get_privatekey()` returned a non-NULL key before calling `EVP_PKEY_id()` or related RSA helpers.

### curl/libcurl version
Reproduced against curl 8.20.0-DEV (`70281e3`) with the OpenSSL backend. This path is inside the RSA / deprecated-OpenSSL guard in `client_cert()`.

### operating system
Linux x86_64

## Reproduction notes
Compile and run the attached `poc.c`:

```bash
clang -fsanitize=address -fno-omit-frame-pointer -g -O1 \
  poc.c -lssl -lcrypto -o /tmp/poc_curl_privkey_null

ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" \
  /tmp/poc_curl_privkey_null
```

Observed result:

```text
AddressSanitizer:DEADLYSIGNAL
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
The signal is caused by a READ memory access.
Hint: address points to the zero page.
    #0 EVP_PKEY_id (/lib/x86_64-linux-gnu/libcrypto.so.1.1+...)
    #1 main poc.c:41
SUMMARY: AddressSanitizer: SEGV ... in EVP_PKEY_id
```
