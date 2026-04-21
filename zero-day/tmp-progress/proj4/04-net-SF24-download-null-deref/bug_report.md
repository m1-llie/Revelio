# NULL Pointer Dereference via `proj_download_file()` with NULL URL

## Summary

`proj_download_file()` delegates to `proj_is_download_needed()` → `build_url()` → `nfm_is_tilde_slash()`, which immediately dereferences its `name` argument without a NULL check. Passing `NULL` as `url_or_filename` to `proj_download_file()` causes a SIGSEGV. This is the same root cause as bug #03 but reached via a distinct, higher-level public API entry point.

- **Affected file:** `src/networkfilemanager.cpp`
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17); latest affected release: PROJ **9.8.1** (2026-04-10)
- **Crash address:** `networkfilemanager.cpp:2269` — `*name` in `nfm_is_tilde_slash()`
- **Sanitizer required:** None (plain SIGSEGV); ASAN gives exact trace
- **Impact:** Denial of service — process crash (NULL pointer read)

---

> **Filing note:** Report **together with bug #03** in a single GitHub issue — both share
> the identical root cause (`nfm_is_tilde_slash()`) and are fixed by the same one-line
> patch.  See Issue 1 in `REPORTING_GUIDE.md`.

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
    04-net-SF24-download-null-deref/net_SF24_poc.c \
    -L proj-9.8.1/install/lib -lproj \
    -Wl,-rpath,proj-9.8.1/install/lib \
    -o poc_04

ASAN_OPTIONS=detect_leaks=0 \
PROJ_DATA=proj-9.8.1/install/share/proj \
./poc_04
```

> **Note:** ASAN is not strictly required — the bug produces a plain SIGSEGV without
> any sanitizer.

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

**Severity:** Medium — CVSS 3.1 base score **6.2** (`AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`). Rises to **7.5 High** (`AV:N`) if the URL parameter originates from untrusted network input.  
**CWE:** [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)

---

## Suggested Fix

Add `if (!url_or_filename) return 0;` in `proj_download_file()` before the `build_url()` call, or fix `nfm_is_tilde_slash()` as described in bug #03.
