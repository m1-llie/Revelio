# NULL Pointer Dereference via `proj_download_file()` with NULL URL

## Summary

`proj_download_file()` delegates to `proj_is_download_needed()` → `build_url()` → `nfm_is_tilde_slash()`, which immediately dereferences its `name` argument without a NULL check. Passing `NULL` as `url_or_filename` to `proj_download_file()` causes a SIGSEGV. This is the same root cause as bug #03 but reached via a distinct, higher-level public API entry point.

- **Affected file:** `src/networkfilemanager.cpp`
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17)
- **Crash address:** `networkfilemanager.cpp:2269` — `*name` in `nfm_is_tilde_slash()`
- **Sanitizer required:** None (plain SIGSEGV); ASAN gives exact trace
- **Impact:** Denial of service — process crash (NULL pointer read)

---

## Call Chain

```
proj_download_file(ctx, NULL, ...)     networkfilemanager.cpp:2680
  → proj_is_download_needed(ctx, NULL) networkfilemanager.cpp:2680
    → build_url(ctx, NULL)             networkfilemanager.cpp:2533
      → nfm_is_tilde_slash(NULL)       networkfilemanager.cpp:2281
        → *name == '~'                 networkfilemanager.cpp:2269  CRASH
```

---

## Proof of Concept

See `net_SF24_poc.c`.

### Reproduction Steps

```bash
docker run --rm \
  -v /path/to/bugs:/bugs \
  -v /path/to/PROJ-latest:/src/PROJ-latest:ro \
  -v /path/to/proj4-latest-build:/proj4-latest-build:ro \
  vulagent/proj4-asan:latest bash -c "
    clang -std=c11 -fsanitize=address -g -O1 \
      -I/src/PROJ-latest/src \
      /bugs/04-net-SF24-download-null-deref/net_SF24_poc.c \
      /proj4-latest-build/lib/libproj.a \
      -lpthread /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 -ldl -lm -lstdc++ \
      -o /tmp/poc_04

    ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan /tmp/poc_04
  "
```

### Observed Output

```
Network enabled: 1
Triggering NULL deref via proj_download_file(ctx, NULL, ...)...
==PID==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
The signal is caused by a READ memory access.
    #0 nfm_is_tilde_slash(char const*)  networkfilemanager.cpp:2269:12
    #1 build_url[abi:cxx11](pj_ctx*, char const*)  networkfilemanager.cpp:2281:10
    #2 proj_is_download_needed  networkfilemanager.cpp:2533:20
    #3 proj_download_file  networkfilemanager.cpp:2680:10
    #4 main  net_SF24_poc.c:63
SUMMARY: AddressSanitizer: SEGV networkfilemanager.cpp:2269 in nfm_is_tilde_slash(char const*)
```

---

## Impact

Same as bug #03: any caller passing a NULL URL to `proj_download_file()` crashes the process.

---

## Suggested Fix

Add `if (!url_or_filename) return 0;` in `proj_download_file()` before the `build_url()` call, or fix `nfm_is_tilde_slash()` as described in bug #03.
