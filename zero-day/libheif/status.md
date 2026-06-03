security issues:

01-track-oob-chunk-access: reported via GitHub Security and Quality portal on Apr 20, GHSA-wqjg-4x9g-6cvg.
Type: CWE-125 OUt-of-bounds read.
https://github.com/strukturag/libheif/security/advisories/GHSA-wqjg-4x9g-6cvg
CVE-2026-47254

04-saiz-sampleauxinfo-oob: reported via GitHub Security and Quality portal on Apr 20, GHSA-9hxj-whrv-m7cc.
Type: CWE-125 OUt-of-bounds read; CWE-617 Reachable Assertion.
Duplicate of GHSA-xj92-xjff-h8w3 reported earlier. I'll close this one and add you as an independent reporter on the other one:
https://github.com/strukturag/libheif/security/advisories/GHSA-xj92-xjff-h8w3.
CVE-2026-41071.


05-tild-ntiles-overflow:reported via GitHub Security and Quality portal on Apr 20, GHSA-x6gq-f8qg-rm7w.
Type: CWE-125 OUt-of-bounds read; CWE-190 Integer Overflow or Wraparound.
fixed in https://github.com/strukturag/libheif/commit/0b73cfdf739f4f697cbc166cb1ce871144772d2b.


03-gimi-component-id-overflow:reported via GitHub Security and Quality portal on Apr 20, GHSA-jfgf-gc66-f3xw.
Type: CWE-122 Heap-based Buffer Overflow; CWE-190 Integer Overflow or Wraparound.
fixed.


07-track-api-oob-no-size: reported via GitHub Private Security Advisory portal on Apr 20, GHSA-ggxm-xvfh-454m.
Response: Advisory closed. See this as an API-contract issue rather than a file-driven vulnerability. 
Link: https://github.com/strukturag/libheif/security/advisories/GHSA-ggxm-xvfh-454m.
Type: CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow'); CWE-122 Heap-based Buffer Overflow.
"There is a heif_context_number_of_sequence_tracks() query whose purpose is to tell the caller exactly how large the array should be, and the header comments already required the caller to use them. The overflow is only reachable when a caller ignores that contract; the file contents alone don't control the buffer size.
We considered adding a capacity parameter but decided against it:
A cap parameter invites hardcoded sizes (heif_context_get_track_ids(ctx, buf, 16)) and silent truncation, which is arguably a worse failure mode than a loud crash from a documented contract violation.
The functions are already published, so the change would mean deprecation and requiring replacements, which is more churn than warranted.
We've instead strengthened the API comments to make the precondition and its consequence explicit. Namely, that passing an undersized array is a buffer overflow, not a truncation.
Thanks again; the API comment was added in 4652161(https://github.com/strukturag/libheif/commit/46521618983c795fdb09a412ebb29e917086896a) and attribution to you was added in the commit title."


08-track-release-double-free:reported via GitHub Security and Quality portal on Apr 20, GHSA-pfwf-3248-7j44.
Type: CWE-415 Double Free; CWE-416 Use After Free.
rejected.
