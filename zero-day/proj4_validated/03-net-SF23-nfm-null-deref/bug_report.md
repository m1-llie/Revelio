# NULL Pointer Dereference in `nfm_is_tilde_slash()` via `proj_is_download_needed()`

## Summary

`nfm_is_tilde_slash()` in `src/networkfilemanager.cpp` immediately dereferences its `name` parameter (`*name`) with no NULL check. It is called unconditionally by `build_url()`, which is called by the public API `proj_is_download_needed()`. Passing `NULL` as `url_or_filename` causes a NULL pointer read (SIGSEGV).

- **Affected file:** `src/networkfilemanager.cpp`
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17)
- **Crash address:** `networkfilemanager.cpp:2269` — `*name` dereference
- **Sanitizer required:** None (plain SIGSEGV); ASAN gives exact trace
- **Impact:** Denial of service — process crash (NULL pointer read)

---

## Vulnerable Code

```c
// src/networkfilemanager.cpp:2268-2270
static bool nfm_is_tilde_slash(const char *name) {
    return *name == '~' && strchr(nfm_dir_chars, name[1]);  // line 2269: dereferences NULL
}

// src/networkfilemanager.cpp:2280-2292 (build_url)
static std::string build_url(pj_ctx *ctx, const char *name) {
    if (nfm_is_tilde_slash(name) || nfm_is_rel_or_absolute_filename(name))  // no NULL check
        ...
}

// public API
int proj_is_download_needed(PJ_CONTEXT *ctx, const char *url_or_filename, int ignore_local_cache) {
    ...
    const auto url(build_url(ctx, url_or_filename));  // passes NULL through
```

---

## Proof of Concept

See `net_SF23_poc.c`.

**Key detail:** the PoC must install custom network callbacks and call `proj_context_set_enable_network(ctx, 1)` to reach `build_url()`. Without these, the function returns early before the vulnerable path.

### Reproduction Steps

```bash
docker run --rm \
  -v /path/to/bugs:/bugs \
  -v /path/to/PROJ-latest:/src/PROJ-latest:ro \
  -v /path/to/proj4-latest-build:/proj4-latest-build:ro \
  vulagent/proj4-asan:latest bash -c "
    clang -std=c11 -fsanitize=address -g -O1 \
      -I/src/PROJ-latest/src \
      /bugs/03-net-SF23-nfm-null-deref/net_SF23_poc.c \
      /proj4-latest-build/lib/libproj.a \
      -lpthread /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 -ldl -lm -lstdc++ \
      -o /tmp/poc_03

    ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan /tmp/poc_03
  "
```

### Observed Output

```
Network enabled: 1
Triggering NULL deref via proj_is_download_needed(ctx, NULL, 0)...
==PID==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
The signal is caused by a READ memory access.
    #0 nfm_is_tilde_slash(char const*)  networkfilemanager.cpp:2269:12
    #1 build_url[abi:cxx11](pj_ctx*, char const*)  networkfilemanager.cpp:2281:10
    #2 proj_is_download_needed  networkfilemanager.cpp:2533:20
    #3 main  net_SF23_poc.c:68
SUMMARY: AddressSanitizer: SEGV networkfilemanager.cpp:2269 in nfm_is_tilde_slash(char const*)
```

---

## Impact

Any caller that passes `NULL` as the URL parameter to `proj_is_download_needed()` crashes the process immediately. This affects applications that perform defensive "is download needed?" checks without first validating the pointer.

---

## Suggested Fix

```diff
 static bool nfm_is_tilde_slash(const char *name) {
+    if (!name) return false;
     return *name == '~' && strchr(nfm_dir_chars, name[1]);
 }
```

Or add the guard in `build_url()` / `proj_is_download_needed()` before calling `build_url()`.
