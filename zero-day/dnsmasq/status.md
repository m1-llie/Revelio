security issues:
01-log_query-ds-heap-overflow: emailed simon@thekelleys.org.uk on Apr 18.
Responded on Apr 20, confirmed and negotiated with CVE; need self-request a CVE via RedHat.
Fix: https://thekelleys.org.uk/gitweb/?p=dnsmasq.git;a=commit;h=36d081e37477027fd721fea498f3760f529034ad.

Introduced: commit 15379ea — 2015-12-21 (added algo %hu, digest %hu (not supported) to DS log, pushing the format past the 46-byte daemon->addrbuff)
  Fixed: commit 36d081e — 2026-04-21
  Age: ~10 years, 4 months