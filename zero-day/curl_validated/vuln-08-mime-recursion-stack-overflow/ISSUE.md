# Stack exhaustion in MIME multipart reading with deeply nested subparts

# CWE
`CWE-674: Uncontrolled Recursion`

# severity
`Medium`

# Proof of Concept
Attached file: `poc.c`

## Summary:
The MIME read path uses mutually recursive helpers for nested multipart structures without enforcing a recursion depth limit. A sufficiently deep tree of nested `curl_mime_subparts()` objects causes stack exhaustion when libcurl starts reading the MIME body. The attached PoC builds a deeply nested MIME structure and triggers an AddressSanitizer stack-overflow in `readback_bytes()` / `mime_subparts_read()`. I reproduced this on curl 8.20.0-DEV at commit `70281e3` on Linux x86_64. The affected code is in `lib/mime.c`, primarily the `readback_part()`, `read_part_content()`, and `mime_subparts_read()` call chain.

## Affected version
Reproduced against curl 8.20.0-DEV (`70281e3`) on Linux x86_64 with `clang` and AddressSanitizer.

## Steps To Reproduce:
1. Build curl with AddressSanitizer enabled and static libcurl available, for example:

```bash
autoreconf -fi
CC=clang CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=address" \
./configure --disable-shared --with-openssl \
  --disable-docs --disable-manual
make -j"$(nproc)"
# If configure fails on optional deps (e.g. libpsl), add --without-libpsl
```

2. Compile the attached `poc.c` against the built libcurl:

```bash
clang -fsanitize=address -fno-omit-frame-pointer -g -O1 \
  -I./include -I./lib \
  poc.c ./lib/.libs/libcurl.a \
  -lssl -lcrypto -lz -lpthread -ldl \
  -o /tmp/poc_curl_mime_recursion
```

3. Run it with a large nesting depth:

```bash
ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" \
  /tmp/poc_curl_mime_recursion 10000
```

4. The PoC constructs a MIME tree with thousands of nested multipart layers and then triggers the MIME read path.

Observed sanitizer output:

```text
AddressSanitizer:DEADLYSIGNAL
ERROR: AddressSanitizer: stack-overflow on address ...
    #0 __asan_memcpy
    #1 readback_bytes /src/curl/lib/mime.c:684
    #2 mime_subparts_read /src/curl/lib/mime.c:919
    #3 read_part_content /src/curl/lib/mime.c:717
    #4 readback_part /src/curl/lib/mime.c:866
    [... pattern repeats for each nesting level ...]
SUMMARY: AddressSanitizer: stack-overflow /src/curl/lib/mime.c:684 in readback_bytes
```

# Impact:
An application that constructs or forwards attacker-influenced nested MIME structures through libcurl can be crashed through stack exhaustion. In the tested configuration this is a reliable denial of service.
