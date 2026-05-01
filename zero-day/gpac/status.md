report via GitHub public Issues:

01-gpac-ipmp-heap-overflow: reported on Apr 7, responded.
Confirmed and fixed; not seen as a security issue due to not a default setting.
Type: CWE-122: Heap-based Buffer Overflow (write).
"In the future if you could provide a poc that goes with an actual gpac (or mp4box) command line instead of a fuzzing harness for easier reproduction of the issue that would be even better.
As for the code that is not guarded by GPAC_MINIMAL_ODF, it seems fairly dead (it's also disabled in the makefile). I agree that it's not very clean but for now I won't fix more issues that require undef-ing this because it's not clear if it's still supposed to be supported.
I still included the fix for this particular issue though, to close it properly."
Link: https://github.com/gpac/gpac/issues/3514.
Fix: https://github.com/sysfce2/gpac/commit/c84397070cd0ebbd68253747a4dbcf1d400fee4a.

02-gpac-elst-infinite-loop: reported on Apr 7, responded.
Confirmed and fixed.
Type: CWE-835: Loop with Unreachable Exit Condition (Infinite Loop).
Link: https://github.com/gpac/gpac/issues/3515.
Fix: https://github.com/sysfce2/gpac/commit/cf6ac48c972eaaee2af270adc3f36615325deb3e.
