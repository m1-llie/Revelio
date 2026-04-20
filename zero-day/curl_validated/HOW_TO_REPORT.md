# How to Report curl Findings

Validated date: 2026-04-18
Latest policy checked: [curl vulnerability disclosure policy](https://curl.se/dev/vuln-disclosure.html)

## Current policy points that matter

- Security vulnerabilities should be reported privately on HackerOne.
- curl says all reports, valid or not, are disclosed after handling.
- curl does not offer a bug bounty.
- curl explicitly says these are often **not** security issues:
  - API misuse (must be documented public APIs)
  - debug-only or experimental features that are off by default
  - NULL dereferences and plain crashes
  - busy-loops that eventually end


## Submission format

For private curl security reports, use the structure curl accepts well:

```text
# CWE
# severity
# Proof of Concept
## Summary
## Affected version
## Steps To Reproduce
# Impact
```

For public issues, use a standard maintainer issue style:

```text
## Description
### I did this
### I expected the following
### curl/libcurl version
### operating system
## Reproduction notes
```
