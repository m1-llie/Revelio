security issues:

01-idmanifest-ubsan-shift-overflow: reported via GitHub Private Security Advisory on Apr 20, GHSA-3c67-4wwp-w52m.
Confirmed and fixed. The developer requeted a CVE. Assign CVE-2026-42217. 
https://github.com/AcademySoftwareFoundation/openexr/security/advisories/GHSA-3c67-4wwp-w52m.
Type: CWE-190 Integer Overflow or Wraparound.
Introduced: commit c61ddf27 — 2021-02-14 ("Add idmanifest attribute support", #909)
  Fixed: commit 21eaa33b — 2026-04-21
  Age: ~5 years, 2 months

02-idmanifest-oob-string-prefix: reported via GitHub Private Security Advisory on Apr 20, GHSA-65j8-95g9-jgj4.
Confirmed and fixed. The developer requeted a CVE. Assign CVE-2026-42216.
https://github.com/AcademySoftwareFoundation/openexr/security/advisories/GHSA-65j8-95g9-jgj4.
Type: CWE-125 Out-of-bounds read.
Introduced: commit c61ddf27 — 2021-02-14 ("Add idmanifest attribute support", #909)
  Fixed: commit 48e5f65a — 2026-04-21
  Age: ~5 years, 2 months

03-idmanifest-oob-mapping-vector: reported via public Issue #2379 on Apr 20.
https://github.com/AcademySoftwareFoundation/openexr/issues/2379.
Type: null pointer dereference.
Confirmed by developers that "This seems to be a valid bug as C++ is zero indexed."
Fix: "Corrected index verification to reject index matching the string size because this would be out-of bounds as arrays are zero-indexed." Check https://github.com/AcademySoftwareFoundation/openexr/pull/2392 (Correct index rejection for string access).