# vuln-09: Signed Integer Overflow in encoder_base64_size()

## Validation Status (2026-04-17)
- **Latest curl commit**: `70281e3` (haproxy: use correct ip version on client supplied address)
- **curl version**: 8.20.0-DEV
- **Status**: CONFIRMED STILL PRESENT — no overflow guard in encoder_base64_size()
- **Runtime crash confirmed**: YES (UBSan signed-integer-overflow at mime.c:427)
- **Validation image**: `curl-validate:20260417`

### Crash Output (latest build)
```
[SF06] Testing signed integer overflow in encoder_base64_size
[SF06] datasize = LLONG_MAX = 9223372036854775807
mime.c:427:12: runtime error: signed integer overflow: 4 * 3074457345618258603 cannot be represented in type 'curl_off_t' (aka 'long')
    #0 encoder_base64_size /src/curl/lib/mime.c:427:12
    #1 mime_size /src/curl/lib/mime.c:1577:12
    #2 Curl_creader_set_mime /src/curl/lib/mime.c:2121:20
    #3 main /work09/poc.c:93:10
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior mime.c:427:12
```

---

# SF06/SF03: Signed Integer Overflow in encoder_base64_size()

## Title
Signed integer overflow in `encoder_base64_size()` when `datasize` is near `LLONG_MAX`, producing incorrect `Content-Length`

## CVE-worthy?
**Marginal** — This is a real, reproducible undefined behavior (UBSan confirms). In practice, an application would need to set `datasize` to `LLONG_MAX` (e.g., via `curl_mime_data_cb(part, LLONG_MAX, ...)`), which is an unusual but valid API call. The overflow results in a large negative Content-Length being computed and potentially sent to HTTP/SMTP servers. This could confuse servers into malformed request handling. However, the encoding itself (actual data bytes written) is bounded by the caller's read buffer, so no heap overflow occurs from this bug alone.

CWE: CWE-190 (Integer Overflow or Wraparound)

## Affected File:Line
- `/src/curl/lib/mime.c:427` — `encoder_base64_size()`: `size = 4 * (1 + ((size - 1) / 3));`
- `/src/curl/lib/mime.c:1577` — `mime_size()` calls `encoder_base64_size`
- `/src/curl/lib/mime.c:2121` — `Curl_creader_set_mime()` calls `mime_size`

## Root Cause
`encoder_base64_size()` computes the base64-encoded output size using signed 64-bit arithmetic without overflow checks. When `part->datasize` is `LLONG_MAX` (9223372036854775807), the first computation overflows:

```c
size = 4 * (1 + ((size - 1) / 3));
// = 4 * (1 + 3074457345618258602)
// = 4 * 3074457345618258603
// = 12297829382473034412  >  LLONG_MAX (9223372036854775807)
// Wraps to: -6148914691236517204  (undefined behavior)
```

This produces a large negative value that is returned as the Content-Length estimate.

## Crash/Sanitizer Output (UBSan Report)
```
/src/curl/lib/mime.c:427:12: runtime error: signed integer overflow:
  4 * 3074457345618258603 cannot be represented in type 'curl_off_t' (aka 'long')
    #0 0x... in encoder_base64_size /src/curl/lib/mime.c:427:12
    #1 0x... in mime_size /src/curl/lib/mime.c:1577:12
    #2 0x... in Curl_creader_set_mime /src/curl/lib/mime.c:2121:20
    #3 0x... in main poc_sf06.c:...

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior mime.c:427:12
```

## Reproduction Steps
```bash
# 1. Build curl with UBSan
git clone https://github.com/curl/curl && cd curl
autoreconf -fi
./configure CC=clang CFLAGS='-fsanitize=undefined -g -O0' \
  LDFLAGS='-fsanitize=undefined' --disable-shared --with-openssl
make -j4 && make install

# 2. Compile PoC
clang -fsanitize=undefined -g MIME_FOLDER_070307_SF06_poc.c \
  -I<install>/include <install>/lib/libcurl.a \
  -lssl -lcrypto -lz -o poc_sf06

# 3. Run
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0 ./poc_sf06
```

## Suggested Fix
Add overflow guards in `encoder_base64_size()`:

```c
static curl_off_t encoder_base64_size(curl_mimepart *part)
{
  curl_off_t size = part->datasize;

  if(size <= 0)
    return size;

  /* Guard against overflow: max safe input for 4*(1+(size-1)/3) */
  /* 4*(1+((LLONG_MAX-1)/3)) overflows; cap at CURL_OFF_T_MAX/4*3 */
  if(size > (curl_off_t)0x4000000000000000LL)
    return -1;  /* Signal unknown/too-large size */

  size = 4 * (1 + ((size - 1) / 3));

  /* Similar guard for second computation */
  return size + (2 * ((size - 1) / MAX_ENCODED_LINE_LENGTH));
}
```

Alternatively, use `__builtin_mul_overflow` or unsigned arithmetic with explicit checks.
