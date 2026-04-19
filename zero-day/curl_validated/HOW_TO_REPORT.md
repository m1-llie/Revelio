# How to Report curl Findings

Validated date: 2026-04-18
Latest policy checked: [curl vulnerability disclosure policy](https://curl.se/dev/vuln-disclosure.html)

## Current policy points that matter

- Security vulnerabilities should be reported privately on HackerOne.
- curl says all reports, valid or not, are disclosed after handling.
- curl does not offer a bug bounty.
- curl explicitly says these are often **not** security issues:
  - API misuse
  - debug-only or experimental features that are off by default
  - NULL dereferences and plain crashes
  - busy-loops that eventually end

## Private security reports

These are the findings that currently make the most sense to keep private first:

1. `vuln-05-ssls-export-uaf`
   - already submitted
   - note: this still has policy risk because SSLS export/import is experimental and off by default
2. `vuln-08-mime-recursion-stack-overflow`
   - best remaining private-report candidate
   - not debug-only, not experimental, and not just a never-ending transfer
3. `vuln-03-certinfo-oob-write`
   - leave as prepared for now
   - strongest argument is memory corruption in release behavior, but acceptance may depend on showing a realistic libcurl-reachable trigger

## Public issues

These are better prepared as normal public bugs under curl's current policy:

- `vuln-01-tls-null-deref-client-cert`
- `vuln-02-tls-privkey-null-deref`
- `vuln-04-easy-stack-overflow`
- `vuln-06-ssls-import-oob-read`
- `vuln-07-ssls-import-null-deref`
- `vuln-09-mime-base64-int-overflow`
- `vuln-10-ws-send-missing-nwritten`

## Why the private/public split changed

- `vuln-06` and `vuln-07` use SSLS import/export, which curl documents as experimental and off by default.
- `vuln-06` also has a likely API-misuse rejection path because `curl_easy_ssls_import()` says `shmac` and `shmac_len` must be given as received during export.
- `vuln-01`, `vuln-02`, and `vuln-07` are primarily NULL-dereference style crashes.
- `vuln-04` is debug-only.
- `vuln-09` is currently a UBSan-detected overflow with no demonstrated memory corruption.
- `vuln-10` is an API-contract bug, not a security issue.

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

## Practical order

1. `vuln-05` is already filed.
2. If you send another private report, send `vuln-08`.
3. `vuln-03` now has a stronger case: calls real `Curl_ssl_init_certinfo()`, documents all 5 backend paths, severity argued as High. Send after `vuln-08`.
4. Use the `PUBLIC_ISSUE.md` drafts for the remaining findings.

## Current repro status

After the latest validation pass on this server (2026-04-18), issue files updated accordingly:

- self-contained from the issue writeup:
  - `vuln-01` — ASan SEGV in EVP_PKEY_copy_parameters, poc.c:44
  - `vuln-02` — ASan SEGV in EVP_PKEY_id, poc.c:41
  - `vuln-04` — ASan stack-buffer-overflow WRITE of size 4 in populate_fds, poc.c:85
- reproduced; issue files now include full crash traces and build notes:
  - `vuln-03` — PoC calls real `Curl_ssl_init_certinfo()` via static libcurl; UBSan + ASan at poc.c:173; links against `libcurl.a`; severity **High**
  - `vuln-05` — ASan heap-use-after-free in Curl_node_next; needs `--enable-ssls-export` (optionally `--without-libpsl`)
  - `vuln-06` — ASan stack-buffer-overflow READ of size 32 in cf_ssl_scache_peer_init; PUBLIC_ISSUE.md now includes full compile recipe
  - `vuln-07` — UBSan null-offset abort in Curl_ssl_session_unpack; issue file now includes `--without-libpsl` note
  - `vuln-08` — ASan stack-overflow in readback_bytes/mime_subparts_read; issue file now includes `--without-libpsl` note
  - `vuln-09` — UBSan signed integer overflow in encoder_base64_size; issue file now includes `--without-libpsl` note
- source-confirmed only:
  - `vuln-10` — source path confirmed in current HEAD; no runtime PoC needed
