# NULL Pointer Dereference in `nfm_is_tilde_slash()` via `proj_is_download_needed()`

> **Filing note:** Report **together with bug #04** in a single GitHub issue — both share
> the identical root cause (`nfm_is_tilde_slash()` dereferences `*name` before NULL check)
> and are fixed by the same one-line patch.  See Issue 1 in `REPORTING_GUIDE.md`.

## Summary

`nfm_is_tilde_slash()` in `src/networkfilemanager.cpp` immediately dereferences its `name` parameter (`*name`) with no NULL check. It is called unconditionally by `build_url()`, which is called by the public API `proj_is_download_needed()`. Passing `NULL` as `url_or_filename` causes a NULL pointer read (SIGSEGV).

- **Affected file:** `src/networkfilemanager.cpp`
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17); latest affected release: PROJ **9.8.1** (2026-04-10)
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

**Step 1 — Build PROJ 9.8.1 with AddressSanitizer** (one-time):

```bash
wget https://download.osgeo.org/proj/proj-9.8.1.tar.gz
tar xf proj-9.8.1.tar.gz && cd proj-9.8.1
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
    03-net-SF23-nfm-null-deref/net_SF23_poc.c \
    -L proj-9.8.1/install/lib -lproj \
    -Wl,-rpath,proj-9.8.1/install/lib \
    -o poc_03

ASAN_OPTIONS=detect_leaks=0 \
PROJ_DATA=proj-9.8.1/install/share/proj \
./poc_03
```

> **Note:** ASAN is not strictly required — the bug produces a plain SIGSEGV without
> any sanitizer.

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

**Severity:** Medium — CVSS 3.1 base score **6.2** (`AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`). Rises to **7.5 High** (`AV:N`) if the URL parameter originates from untrusted network input.  
**CWE:** [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)

---

## Suggested Fix

```diff
 static bool nfm_is_tilde_slash(const char *name) {
+    if (!name) return false;
     return *name == '~' && strchr(nfm_dir_chars, name[1]);
 }
```

Or add the guard in `build_url()` / `proj_is_download_needed()` before calling `build_url()`.
