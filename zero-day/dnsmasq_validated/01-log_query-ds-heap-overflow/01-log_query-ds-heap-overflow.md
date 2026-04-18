# Heap Buffer Overflow in `log_query()` via Crafted DS Record (DNSSEC)

## Summary

A heap buffer overflow exists in `log_query()` (`src/cache.c`) when dnsmasq processes
a DS record whose algorithm or digest type is unrecognized. An unbounded `sprintf()`
writes 58 bytes into a 46-byte heap buffer — an overflow of 12 bytes — using field
values that are fully legal on the DNS wire. The bug is reachable from the network
via a rogue, poisoned, or MITM-positioned upstream DNS resolver.

- **Severity:** High (heap write overflow, 12 bytes past allocation)
- **Affected versions:** dnsmasq v2.93 (latest as of 2026-04-17); likely earlier
- **Affected file:** `src/cache.c`, function `log_query()`, line 2358
- **Preconditions:** `--dnssec` + `--log-queries` (common in Pi-hole, AdGuard Home)
- **Attacker position:** Network (upstream DNS, MITM, or DNS cache poisoning)

---

## Vulnerable Code

### Overflow site — `src/cache.c:2357–2358`

```c
else if (flags & F_KEYTAG)
    sprintf(daemon->addrbuff, arg,                        /* unbounded */
            addr->log.keytag, addr->log.algo, addr->log.digest);
```

### Buffer allocation — `src/option.c:5967`

```c
daemon->addrbuff = safe_malloc(ADDRSTRLEN);
/* ADDRSTRLEN = INET6_ADDRSTRLEN = 46  (src/dnsmasq.h:171) */
```

### Format string source — `src/dnssec.c:1104`

```c
log_query(F_NOEXTRA | F_KEYTAG | F_UPSTREAM, name, &a,
          "DS for keytag %hu, algo %hu, digest %hu (not supported)", 0);
```

---

## Root Cause

DS record RDATA fields are read as:

```c
GETSHORT(keytag, p);   /* uint16_t — max 65535 (5 decimal digits) */
algo   = *p++;          /* uint8_t  — max   255 (3 decimal digits) */
digest = *p++;          /* uint8_t  — max   255 (3 decimal digits) */

if (!ds_digest_name(digest) || !algo_digest_name(algo))
{
    a.log.keytag = keytag;
    a.log.algo   = algo;
    a.log.digest = digest;
    log_query(..., "DS for keytag %hu, algo %hu, digest %hu (not supported)", 0);
```

With worst-case wire values (`keytag=65535`, `algo=255`, `digest=255`):

| String produced                                                   | Bytes (incl. `\0`) | Buffer |
|-------------------------------------------------------------------|--------------------|--------|
| `DS for keytag 65535, algo 255, digest 255 (not supported)`      | **58**             | 46     |

**Overflow = 12 bytes.**

`algorithm=255` and `digest_type=255` are IANA-unassigned values — they parse
without error but cause `algo_digest_name()` / `ds_digest_name()` to return NULL,
reliably triggering the `(not supported)` branch.

### Other format strings in `dnssec.c` — not affected at wire-maximum values

| Format string                                                    | Max bytes (incl. `\0`) | Overflow? |
|------------------------------------------------------------------|------------------------|-----------|
| `DNSKEY keytag %hu, algo %hu`                                    | 30                     | No        |
| `DNSKEY keytag %hu, algo %hu (not supported)` (algo max=255)    | 46                     | No — exact fit |
| `DS for keytag %hu, algo %hu, digest %hu`                        | 42                     | No        |
| **`DS for keytag %hu, algo %hu, digest %hu (not supported)`**   | **58**                 | **Yes (+12)** |

---

## ASAN Crash Output

Reproduced on 2026-04-17 using `vulagent/dnsmasq:latest` (dnsmasq v2.93, clang 22.0.0git):

```
=================================================================
==13==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7b4981ae007e
WRITE of size 58 at 0x7b4981ae007e thread T0
    #0 in vsprintf  sanitizer_common_interceptors.inc:1732
    #1 in sprintf   sanitizer_common_interceptors.inc:1777
    #2 in main      poc_reproducer.c:64

0x7b4981ae007e is located 0 bytes after 46-byte region [0x7b4981ae0050,0x7b4981ae007e)
allocated by thread T0 here:
    #0 in malloc    asan_malloc_linux.cpp:67
    #1 in main      poc_reproducer.c:44

SUMMARY: AddressSanitizer: heap-buffer-overflow poc_reproducer.c:64 in main
```

Full output: `asan_output_validated.txt`

---

## Proof of Concept

`poc_reproducer.c` directly mirrors the vulnerable code path using the exact buffer
size, format string, and wire-maximum field values.

```sh
clang -fsanitize=address,undefined -g -o poc poc_reproducer.c
ASAN_OPTIONS=detect_leaks=0 ./poc
```

Expected output:
```
Buffer size : 46 bytes
String needs: 58 bytes
Overflow by : 12 bytes

[ASAN crash: heap-buffer-overflow WRITE of size 58]
```

Or run `bash build.sh` for a one-step build and run.

---

## Trigger Conditions

1. dnsmasq compiled with `HAVE_DNSSEC` — **default** on Debian/Ubuntu
   (`apt show dnsmasq-base` lists DNSSEC in compile options)
2. dnsmasq started with `--dnssec` and `--log-queries`
   (standard configuration in Pi-hole, AdGuard Home, and similar setups)
3. An attacker-controlled, poisoned, or MITM upstream DNS server responds to a
   DS query with a record containing:
   - `key_tag = 65535` (or any value; 65535 maximises the formatted string)
   - `algorithm = 255` (IANA Unassigned — causes `algo_digest_name()` → NULL)
   - `digest_type = 255` (IANA Unassigned — causes `ds_digest_name()` → NULL)

---

## Impact

- **Type:** Heap buffer overflow — 12-byte out-of-bounds write
- **Attacker position:** Network (upstream DNS, MITM, or DNS poisoning)
- **Authentication required:** None
- **Worst case:** Heap metadata corruption → controlled heap layout →
  potential remote code execution
- **Realistic case:** dnsmasq process crash / denial of service

**CVSS 3.1 estimate: 7.5 (High)**
`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`
(High complexity: requires attacker influence over upstream DNS responses)

---

## Suggested Fix

Replace the unbounded `sprintf` with `snprintf` at `cache.c:2358`:

```diff
-    sprintf(daemon->addrbuff, arg,
-            addr->log.keytag, addr->log.algo, addr->log.digest);
+    snprintf(daemon->addrbuff, ADDRSTRLEN, arg,
+             addr->log.keytag, addr->log.algo, addr->log.digest);
```

This silently truncates the log message when it exceeds 46 bytes, which is
acceptable for a diagnostic string. Alternatively, increase the `addrbuff`
allocation at `option.c:5967` to at least 64 bytes to accommodate all possible
DNSSEC log strings without truncation:

```diff
-  daemon->addrbuff = safe_malloc(ADDRSTRLEN);
+  daemon->addrbuff = safe_malloc(64);  /* 64 > max DNSSEC log string (58 bytes) */
```

---

## Reporter

Discovered via automated hypothesis generation and ASAN-based validation.
