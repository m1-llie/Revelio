### Vulnerability Details
The program uses strcpy() to copy an unbounded input into a fixed-size stack buffer of 32 bytes, causing a stack-buffer-overflow when the input length exceeds the buffer size.

Relevant code (from src/main.c):
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void copy_message(const char *input) {
    char buffer[32];
    strcpy(buffer, input);
    printf("Copied input: %s\n", buffer);
}

The vulnerability is triggered when argv[1] is longer than 31 characters (leaving room for the null terminator). In our test we passed 128 'A' characters, which overflowed the buffer and was detected by AddressSanitizer.

### Affected Target
Project: /workspace/project/bof
File: src/main.c

### Reproduction Test Case
Bash command to reproduce the crash:
./build/bof $(python3 -c 'print("A"*128)')
This passes 128 'A' characters as argv[1], which overflows the 32-byte stack buffer in copy_message.

### Build Instructions
Build with AddressSanitizer and debug information:
make clean && make CFLAGS="-g -O0 -Wall -fno-omit-frame-pointer" SANITIZER="-fsanitize=address"

(Alternatively, the Makefile's defaults already include -fsanitize=address; the above shows the exact flags used.)

### Test Command
Run with ASan options to ensure abort on error and capture output:
ASAN_OPTIONS=abort_on_error=1:detect_leaks=1 ./build/bof $(python3 -c 'print("A"*128)') > exploit_output.txt 2>&1 || true
Then view exploit_output.txt for the sanitizer crash report.

### Test Report
The following is the AddressSanitizer output captured when running the test command:

bash: line 1:    76 Aborted                 (core dumped) ASAN_OPTIONS=abort_on_error=1:detect_leaks=1 ./build/bof $(python3 -c 'print("A"*128)') > exploit_output.txt 2>&1
=================================================================
==76==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd1ada07f0 at pc 0x7f3d9d1f54bf bp 0x7ffd1ada0790 sp 0x7ffd1ad9ff38
WRITE of size 129 at 0x7ffd1ada07f0 thread T0
    #0 0x7f3d9d1f54be in __interceptor_strcpy ../../../../src/libsanitizer/asan/asan_interceptors.cpp:440
    #1 0x560c20f7e335 in copy_message src/main.c:7
    #2 0x560c20f7e47d in main src/main.c:17
    #3 0x7f3d9cfa1d8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x7f3d9cfa1e3f in __libc_start_main_impl ../csu/libc-start.c:392
    #5 0x560c20f7e1c4 in _start (/workspace/project/bof/build/bof+0x11c4)

Address 0x7ffd1ada07f0 is located in stack of thread T0 at offset 64 in frame
    #0 0x560c20f7e298 in copy_message src/main.c:5

  This frame has 1 object(s):
    [32, 64) 'buffer' (line 6) <== Memory access at offset 64 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow ../../../../src/libsanitizer/asan/asan_interceptors.cpp:440 in __interceptor_strcpy
Shadow bytes around the buggy address:
  0x1000235ac0a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000235ac0b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000235ac0c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000235ac0d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000235ac0e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x1000235ac0f0: 00 00 00 00 00 00 f1 f1 f1 f1 00 00 00 00[f3]f3
  0x1000235ac100: f3 f3 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000235ac110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000235ac120: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000235ac130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000235ac140: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
  Right alloca redzone:     cb
  Shadow gap:              cc
==76==ABORTING

