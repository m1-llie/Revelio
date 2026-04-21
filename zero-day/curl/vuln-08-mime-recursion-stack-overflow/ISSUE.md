# Stack exhaustion in MIME multipart reading with deeply nested subparts

# CWE
`CWE-674: Uncontrolled Recursion`

# severity
`Medium`

# Proof of Concept
Attached file: `poc.c`

## Summary:
The MIME read path uses mutually recursive helpers for nested multipart structures without enforcing a recursion depth limit. A sufficiently deep tree of nested `curl_mime_subparts()` objects causes stack exhaustion when libcurl starts reading the MIME body. The attached PoC builds a deeply nested MIME structure and triggers an AddressSanitizer stack-overflow in `readback_bytes()` / `mime_subparts_read()`. I reproduced this on curl 8.19.0 (latest stable release) and also on the current development tip (`759f2e5`) on Linux x86_64. The affected code is in `lib/mime.c`, primarily the `readback_part()`, `read_part_content()`, and `mime_subparts_read()` call chain.

## Affected version
Reproduced against:
- **curl 8.19.0** (tag `curl-8_19_0`, commit `8c908d2`, released 2025-03-10) — current stable release
- **curl 8.20.0-DEV** (commit `759f2e5`) — current development tip

Tested on Linux x86_64 with `clang` and AddressSanitizer.

## Steps To Reproduce:
1. Build curl with AddressSanitizer enabled and static libcurl available, for example:

```bash
autoreconf -fi
CC=clang CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=address" \
./configure --disable-shared --with-openssl \
  --disable-docs --disable-manual --without-libpsl
make -j"$(nproc)"
```

2. Compile the attached `poc.c` against the built libcurl (public headers only — no private `-I./lib` needed):

```bash
clang -fsanitize=address -fno-omit-frame-pointer -g -O1 \
  -I./include \
  poc.c ./lib/.libs/libcurl.a \
  -lssl -lcrypto -lz -lpthread -ldl \
  -o /tmp/poc_curl_mime_recursion
```

3. Run it with a large nesting depth:

```bash
ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" \
  /tmp/poc_curl_mime_recursion 20000
```

4. The PoC uses only documented public API (`curl_mime_init`, `curl_mime_addpart`, `curl_mime_subparts`, `curl_easy_setopt(CURLOPT_MIMEPOST, ...)`, `curl_easy_perform`). It constructs a MIME tree with thousands of nested multipart layers and triggers the recursive read path through a standard `curl_easy_perform()` POST to a loopback socket.

Observed sanitizer output (curl 8.19.0, depth=20000):

```text
AddressSanitizer:DEADLYSIGNAL
==25988==ERROR: AddressSanitizer: stack-overflow on address 0x7ffd763b6fa8
    #0 0x...  in __asan_memcpy
    #1 0x...  in readback_bytes lib/mime.c:683:3
    #2 0x...  in mime_subparts_read lib/mime.c:918:12
    #3 0x...  in read_part_content lib/mime.c:716:12
    #4 0x...  in readback_part lib/mime.c:865:14
    #5 0x...  in mime_subparts_read lib/mime.c:939:12
    #6 0x...  in read_part_content lib/mime.c:716:12
    #7 0x...  in readback_part lib/mime.c:865:14
    [... pattern repeats for each nesting level ...]
SUMMARY: AddressSanitizer: stack-overflow lib/mime.c:683:3 in readback_bytes
```

# Impact:
An application that constructs or forwards attacker-influenced nested MIME structures through libcurl can be crashed through stack exhaustion. In the tested configuration this is a reliable denial of service.