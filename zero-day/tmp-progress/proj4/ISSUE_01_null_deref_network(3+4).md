NULL pointer dereference in proj_is_download_needed() and proj_download_file() when url_or_filename is NULL


## Summary

Two public API functions crash with a NULL pointer read (SIGSEGV) when `NULL` is passed as the `url_or_filename` parameter. Both share the same root cause: the internal helper `nfm_is_tilde_slash()` dereferences `*name` without a prior NULL check.

**Affected functions:**
- `proj_is_download_needed(PJ_CONTEXT *ctx, const char *url_or_filename, int ignore_local_cache)`
- `proj_download_file(PJ_CONTEXT *ctx, const char *url_or_filename, int ignore_local_cache, PJ_PROGRESS_CB prog_cbk, void *user_data)`

Both are declared in `proj.h` and are part of the documented public API.

**PROJ version:** 9.8.1 (latest release, 2026-04-10); also confirmed on master commit `324ed2119011d74665548afe445eacb99afb9753` (2026-04-17)  
**OS:** Linux x86_64  
**Build:** Clang + AddressSanitizer (`-fsanitize=address -g -O1`)

## Root cause

`nfm_is_tilde_slash()` in `src/networkfilemanager.cpp` dereferences its argument at the very first instruction:

```cpp
// src/networkfilemanager.cpp:2268-2270
static bool nfm_is_tilde_slash(const char *name) {
    return *name == '~' && strchr(nfm_dir_chars, name[1]);  // CRASH: *name when name == NULL
}
```

`build_url()` calls this function unconditionally, with no NULL guard:

```cpp
// src/networkfilemanager.cpp:2280-2292
static std::string build_url(pj_ctx *ctx, const char *name) {
    if (nfm_is_tilde_slash(name) || nfm_is_rel_or_absolute_filename(name))
        ...
}
```

`proj_is_download_needed()` passes its `url_or_filename` argument straight to `build_url()`. `proj_download_file()` calls `proj_is_download_needed()` first, reaching the same crash via a longer call chain:

```
proj_download_file(ctx, NULL, ...)        networkfilemanager.cpp:2680
  → proj_is_download_needed(ctx, NULL)   networkfilemanager.cpp:2680
    → build_url(ctx, NULL)               networkfilemanager.cpp:2533
      → nfm_is_tilde_slash(NULL)         networkfilemanager.cpp:2281
        → *name                          networkfilemanager.cpp:2269  CRASH
```

Compare: `proj_get_area_of_use()` and other API functions do guard their pointer parameters with `if (!obj) return …`. These two network functions do not.

## Proof of Concept

Save the following as `poc_net_null.c`:

```c
#include "proj.h"
#include <stdio.h>

/* Minimal stub callbacks — required to make proj_context_is_network_enabled()
   return true; otherwise both functions return early before reaching build_url(). */
static PROJ_NETWORK_HANDLE *stub_open(
    PJ_CONTEXT *ctx, const char *url,
    unsigned long long offset, size_t size_to_read, void *buffer,
    size_t *out_size_read, size_t error_string_max_size,
    char *out_error_string, void *user_data) { return NULL; }
static size_t stub_read(PJ_CONTEXT *ctx, PROJ_NETWORK_HANDLE *handle,
    unsigned long long offset, size_t size_to_read, void *buffer,
    size_t error_string_max_size, char *out_error_string, void *user_data) { return 0; }
static void stub_close(PJ_CONTEXT *ctx, PROJ_NETWORK_HANDLE *handle, void *user_data) {}
static const char *stub_header(PJ_CONTEXT *ctx, PROJ_NETWORK_HANDLE *handle,
    const char *header_name, void *user_data) { return NULL; }

int main(void) {
    PJ_CONTEXT *ctx = proj_context_create();
    proj_context_set_network_callbacks(ctx, stub_open, stub_close, stub_header, stub_read, NULL);
    proj_context_set_enable_network(ctx, 1);
    printf("Network enabled: %d\n", proj_context_is_network_enabled(ctx));

    printf("Bug A: proj_is_download_needed(ctx, NULL, 0)...\n");
    proj_is_download_needed(ctx, NULL, 0);          /* CRASH here */

    /* Bug B (same root cause, different entry point): */
    printf("Bug B: proj_download_file(ctx, NULL, ...)...\n");
    proj_download_file(ctx, NULL, 0, NULL, NULL);   /* CRASH here */

    proj_context_destroy(ctx);
    return 0;
}
```

### Reproduction steps

**Step 1 — Build PROJ 9.8.1 with AddressSanitizer**:

```bash
cmake -B build \
      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_C_FLAGS="-fsanitize=address -g -O1" \
      -DCMAKE_CXX_FLAGS="-fsanitize=address -g -O1" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
      -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" \
      -DCMAKE_INSTALL_PREFIX="$PWD/install"
cmake --build build -j$(nproc)
cmake --install build
cd ..
```

**Step 2 — Compile and run:**

```bash
clang++ -std=c++17 -fsanitize=address -g -O1 \
    -I proj-9.8.1/install/include \
    poc_net_null.c \
    -L proj-9.8.1/install/lib -lproj \
    -Wl,-rpath,proj-9.8.1/install/lib \
    -o poc_net_null

ASAN_OPTIONS=detect_leaks=0 \
PROJ_DATA=proj-9.8.1/install/share/proj \
./poc_net_null
```

> **Note:** AddressSanitizer is not strictly required — both bugs produce a plain SIGSEGV
> without any sanitizer. ASAN is included here to provide an exact stack trace.

### Observed output (ASAN)

```
Network enabled: 1
Bug A: proj_is_download_needed(ctx, NULL, 0)...
==PID==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
The signal is caused by a READ memory access.
    #0 nfm_is_tilde_slash(char const*)      networkfilemanager.cpp:2269
    #1 build_url(pj_ctx*, char const*)       networkfilemanager.cpp:2281
    #2 proj_is_download_needed               networkfilemanager.cpp:2533
    #3 main                                  poc_net_null.c:22
SUMMARY: AddressSanitizer: SEGV networkfilemanager.cpp:2269 in nfm_is_tilde_slash
```

*(Bug B produces an identical trace with `proj_download_file` at frame #3 and `proj_is_download_needed` at frame #4.)*

## Impact

Any application that passes a NULL URL to either network API function — for example as a result of a failed lookup or an uninitialized pointer — will crash immediately. Both functions are documented as part of the public network-access API and callers may reasonably expect them to handle NULL gracefully (as many other PROJ API functions do).

**Severity estimation:** Medium — CVSS 3.1 base score 6.2 (`AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`). Rises to 7.5 High (`AV:N`) in deployments where the URL parameter is derived from untrusted network input (e.g., a web service that passes user-supplied paths to PROJ).  
**CWE:** [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)


## Suggested fix

A single one-line guard in `nfm_is_tilde_slash()` fixes both entry points:

```diff
 static bool nfm_is_tilde_slash(const char *name) {
+    if (!name) return false;
     return *name == '~' && strchr(nfm_dir_chars, name[1]);
 }
```

Alternatively, add `if (!url_or_filename) return 0;` / `return false;` at the top of `proj_is_download_needed()` and `proj_download_file()` for defence-in-depth.
