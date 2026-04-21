# `populate_fds()` should not write past the fixed `fds[4]` array in DEBUGBUILD

## Description

### I did this
I reproduced the `populate_fds()` overflow pattern from the `DEBUGBUILD` path in `lib/easy.c`. In `wait_or_timeout()`, curl allocates `struct pollfd fds[4]` and then passes that array to `populate_fds()` without a size argument. `populate_fds()` iterates the full socketmonitor list and writes one `pollfd` per entry, so a list longer than four entries writes past the end of `fds`.

The attached `poc.c` mirrors the relevant structs and code from `lib/easy.c` and triggers an AddressSanitizer stack-buffer-overflow on the fifth write.

### I expected the following
The debug-only path should either size the array dynamically or stop writing once the fixed array is full.

### curl/libcurl version
Observed in curl 8.20.0-DEV (`70281e3`) in the `DEBUGBUILD` path around `wait_or_timeout()` / `populate_fds()` in `lib/easy.c`.

### operating system
Linux x86_64

## Reproduction notes
Compile and run the attached `poc.c`:

```bash
clang -fsanitize=address -fno-omit-frame-pointer -g -O1 \
  poc.c -o /tmp/poc_curl_populate_fds

ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" \
  /tmp/poc_curl_populate_fds
```

Observed result:

```text
ERROR: AddressSanitizer: stack-buffer-overflow on address ... thread T0
WRITE of size 4 at ... thread T0
    #0 populate_fds poc.c:85
    #1 vulnerable_wait_or_timeout_body poc.c:104
    #2 main poc.c:139
Address ... is located in stack of thread T0 at offset 64 in frame
    #0 vulnerable_wait_or_timeout_body poc.c:102
  This frame has 1 object(s):
    [32, 64) 'fds' (line 103) <== Memory access at offset 64 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow poc.c:85 in populate_fds
```
