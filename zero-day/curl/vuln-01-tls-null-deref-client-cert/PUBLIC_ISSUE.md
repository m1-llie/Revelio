# `client_cert()` should guard `X509_get_pubkey()` before calling `EVP_PKEY_copy_parameters()`

## Description

### I did this
I reproduced a crash pattern in curl's OpenSSL client-certificate handling where `client_cert()` calls `EVP_PKEY_copy_parameters()` on the result of `X509_get_pubkey()` without checking whether that call returned `NULL`.

The attached `poc.c` demonstrates the same OpenSSL call sequence directly:

- `X509_get_pubkey()` returns `NULL` for an X509 object without a usable public key
- `EVP_PKEY_copy_parameters(NULL, ...)` then crashes

The affected code is in `lib/vtls/openssl.c` in `client_cert()` around lines 1558-1560 in the curl 8.20.0-DEV tree I tested (`70281e3`).

### I expected the following
curl should check the result of `X509_get_pubkey()` before calling `EVP_PKEY_copy_parameters()`.

### curl/libcurl version
8.20.0-DEV (`70281e3`)

### operating system
Linux x86_64

## Reproduction notes
Compile and run the attached `poc.c`:

```bash
clang -fsanitize=address -fno-omit-frame-pointer -g -O1 \
  poc.c -lssl -lcrypto -o /tmp/poc_curl_client_cert_null

ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" \
  /tmp/poc_curl_client_cert_null
```

Observed result:

```text
AddressSanitizer:DEADLYSIGNAL
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
The signal is caused by a READ memory access.
Hint: address points to the zero page.
    #0 EVP_PKEY_copy_parameters (/lib/x86_64-linux-gnu/libcrypto.so.1.1+...)
    #1 main poc.c:44
SUMMARY: AddressSanitizer: SEGV ... in EVP_PKEY_copy_parameters
```
