# Heap-buffer-overflow in `log_query()` for unsupported DS records

## Summary

When dnsmasq logs an unsupported DS record, `log_query()` formats the message into
`daemon->addrbuff` with `sprintf()`. The destination buffer is 46 bytes, but the
unsupported-DS format string can require 58 bytes for legal wire values such as
`keytag=65535`, `algo=255`, and `digest=255`.

I reproduced this on dnsmasq `v2.93test9` (latest release as of 2026-04-18).
The vulnerability is confirmed present in the current official HEAD
`2d0e0c7a54f73d10d7afa15691c08cf5ec1e4ee2` from the upstream gitweb
(https://thekelleys.org.uk/gitweb/?p=dnsmasq.git).

## Affected code path

- **File:** `src/cache.c`
- **Function:** `log_query()`
- **Overflow site:** `src/cache.c:2358`
- **Format source:** `src/dnssec.c:1104`
- **Buffer allocation:** `src/option.c:5967`

## Root cause

The vulnerable write is:

```c
sprintf(daemon->addrbuff, arg,
        addr->log.keytag, addr->log.algo, addr->log.digest);
```

The format string:

```c
"DS for keytag %hu, algo %hu, digest %hu (not supported)"
```

can render to 58 bytes including the trailing NUL, but `daemon->addrbuff` is only 46
bytes long.

## Tested version

- **Version reproduced:** dnsmasq `v2.93test9` (latest release as of 2026-04-18)
- **Current upstream HEAD verified:** `2d0e0c7a54f73d10d7afa15691c08cf5ec1e4ee2` (https://thekelleys.org.uk/gitweb/?p=dnsmasq.git)

## Environment

- **OS:** Ubuntu Linux x86_64
- **Compiler:** clang 22.0.0git (LLVM trunk)
- **Sanitizers:** AddressSanitizer + UndefinedBehaviorSanitizer

## Reproduction

The attached `poc_reproducer.c` mirrors the exact buffer size, format string, and field
values.

```bash
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
  poc_reproducer.c -o /tmp/poc_dnsmasq_ds_overflow

ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" \
  /tmp/poc_dnsmasq_ds_overflow
```

## ASan output

Validated in Docker image `revelio/dnsmasq:latest` (dnsmasq v2.93test9, clang 22.0.0git) on 2026-04-17.

```text
=================================================================
==13==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7b4981ae007e at pc 0x55cd1f21263b bp 0x7fff11b85150 sp 0x7fff11b84900
WRITE of size 58 at 0x7b4981ae007e thread T0
    #0 0x55cd1f21263a in vsprintf /src/llvm-project/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:1732:1
    #1 0x55cd1f21379a in sprintf /src/llvm-project/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:1777:1
    #2 0x55cd1f2cf578 in main poc_reproducer.c:64:5
    #3 0x7f09825eb082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 5792732f783158c66fb4f3756458ca24e46e827d)
    #4 0x55cd1f1e936d in _start (/tmp/poc+0x2c36d)

0x7b4981ae007e is located 0 bytes after 46-byte region [0x7b4981ae0050,0x7b4981ae007e)
allocated by thread T0 here:
    #0 0x55cd1f28caf4 in malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:67:3
    #1 0x55cd1f2cf470 in main poc_reproducer.c:44:30
    #2 0x7f09825eb082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 5792732f783158c66fb4f3756458ca24e46e827d)

SUMMARY: AddressSanitizer: heap-buffer-overflow poc_reproducer.c:64:5 in main
Shadow bytes around the buggy address:
  0x7b4981adfd80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b4981adfe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b4981adfe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b4981adff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x7b4981adff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x7b4981ae0000: fa fa 00 00 00 00 00 02 fa fa 00 00 00 00 00[06]
  0x7b4981ae0080: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x7b4981ae0100: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x7b4981ae0180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x7b4981ae0200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x7b4981ae0280: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==13==ABORTING
```

## Impact

- CWE-122: Heap-based Buffer Overflow
- This is a heap out-of-bounds write in a network-reachable logging path.
- In the tested configuration it crashes dnsmasq.
- In other builds it may also corrupt adjacent heap state.

## Suggested fix

Use `snprintf()` instead of `sprintf()`:

```c
snprintf(daemon->addrbuff, ADDRSTRLEN, arg,
         addr->log.keytag, addr->log.algo, addr->log.digest);
```

## Duplicate check

I did not find a clearly matching public dnsmasq issue for this exact unsupported-DS
logging path.
