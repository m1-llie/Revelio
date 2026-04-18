# vuln-08: Unbounded Recursion in MIME Multipart Read Causes Stack Overflow

## Validation Status (2026-04-17)
- **Latest curl commit**: `70281e3` (haproxy: use correct ip version on client supplied address)
- **curl version**: 8.20.0-DEV
- **Status**: CONFIRMED STILL PRESENT — no depth limit in readback_part/mime_subparts_read
- **Runtime crash confirmed**: YES (ASAN stack-overflow at mime.c:684, depth ~20000 with ASAN, ~9500 in production)
- **Validation image**: `curl-validate:20260417`

### Crash Output (latest build, depth=20000 under ASAN)
```
[SF12] Building 20000-deep nested multipart MIME structure
[SF12] Nested structure ready. Triggering MIME read...
AddressSanitizer:DEADLYSIGNAL
==13==ERROR: AddressSanitizer: stack-overflow on address ...
    #0 __asan_memcpy ...
    #1 readback_bytes /src/curl/lib/mime.c:684:3
    #2 mime_subparts_read /src/curl/lib/mime.c:919:12
    #3 read_part_content /src/curl/lib/mime.c:717:12
    #4 readback_part /src/curl/lib/mime.c:866:14
    #5 mime_subparts_read /src/curl/lib/mime.c:940:12
    ... (recursive chain)
SUMMARY: AddressSanitizer: stack-overflow in readback_bytes
```
Note: ASAN inflates stack frame sizes ~5x. Production threshold is ~9500 levels (8MB default stack).
With `ulimit -s unlimited`, the PoC completes at 9500 levels without crash. Use depth >= 20000 for ASAN builds.

---

# SF12: Unbounded Recursion in MIME Multipart Read Causes Stack Overflow

## Title
Stack exhaustion via deeply nested multipart MIME structures in `mime_subparts_read` / `readback_part`

## CVE-worthy?
**Yes** — exploitable by a client application that accepts attacker-controlled MIME structures or processes untrusted multipart data. Any application using libcurl's MIME API to upload or forward user-controlled nested multipart content is vulnerable to remote DoS via stack exhaustion (crash / process termination).

CWE: CWE-674 (Uncontrolled Recursion), CWE-787 (Out-of-Bounds Write via stack smashing in pathological cases)

## Affected File:Line
- `/src/curl/lib/mime.c:684` — `readback_bytes` (crash point)
- `/src/curl/lib/mime.c:717` — `read_part_content` → `mime_subparts_read` call
- `/src/curl/lib/mime.c:866` — `readback_part` → `read_part_content` call
- `/src/curl/lib/mime.c:940` — `mime_subparts_read` → `readback_part` call

## Root Cause
The MIME read functions `mime_subparts_read` and `readback_part` are mutually recursive with **no depth limit or guard**. For each nesting level of a multipart MIME structure, `readback_part` calls `read_part_content` (MIMESTATE_CONTENT for MIMEKIND_MULTIPART parts), which calls `mime_subparts_read`, which calls `readback_part` for each sub-part. At roughly 9500+ nesting levels (tested; varies with stack size and compiler flags), the 8MB default thread stack is exhausted, causing a SIGSEGV/SIGABRT.

## Crash Output (ASAN Report)
```
AddressSanitizer:DEADLYSIGNAL
=================================================================
==9==ERROR: AddressSanitizer: stack-overflow on address 0x7ffd60690e48
    #0 0x... in __asan_memcpy
    #1 0x... in readback_bytes /src/curl/lib/mime.c:684:3
    #2 0x... in mime_subparts_read /src/curl/lib/mime.c:940:12
    #3 0x... in read_part_content /src/curl/lib/mime.c:717:12
    #4 0x... in readback_part /src/curl/lib/mime.c:866:14
    #5 0x... in mime_subparts_read /src/curl/lib/mime.c:940:12
    #6 0x... in read_part_content /src/curl/lib/mime.c:717:12
    #7 0x... in readback_part /src/curl/lib/mime.c:866:14
    ... [~246+ identical frames]
SUMMARY: AddressSanitizer: stack-overflow .../mime.c:684:3 in readback_bytes
```

## Reproduction Steps
```bash
# 1. Build curl with ASAN
git clone https://github.com/curl/curl && cd curl
autoreconf -fi
./configure CC=clang CFLAGS='-fsanitize=address -g -O0' \
  LDFLAGS='-fsanitize=address' --disable-shared --with-openssl
make -j4 && make install

# 2. Compile PoC
clang -fsanitize=address -g MIME_FOLDER_070307_SF12_poc.c \
  -I<install>/include <install>/lib/libcurl.a \
  -lssl -lcrypto -lz -o poc_sf12

# 3. Trigger (depth 10000 reliably crashes; depth 9500 crashes; depth 9000 does not)
ASAN_OPTIONS=detect_leaks=0 ./poc_sf12 10000
```

## Minimum Depth for Crash
Approximately 9500 nesting levels with ASAN overhead, fewer in production builds with smaller stack allocation.

## Suggested Fix
Add a recursion depth limit in `mime_subparts_read` or `readback_part`. Pass a depth counter through the call chain and return `READ_ERROR` when a threshold (e.g., 100 levels) is exceeded:

```c
/* In read_part_content, add depth parameter */
static size_t read_part_content(curl_mimepart *part, char *buffer,
                                 size_t bufsize, bool *hasread, int depth)
{
  if(depth > MIME_MAX_RECURSION_DEPTH)
    return READ_ERROR;
  ...
  case MIMEKIND_MULTIPART:
    sz = mime_subparts_read_depth(buffer, 1, bufsize, part->arg, hasread, depth + 1);
    break;
  ...
}
```

Or alternatively, convert the recursive traversal to an iterative one using an explicit stack.
