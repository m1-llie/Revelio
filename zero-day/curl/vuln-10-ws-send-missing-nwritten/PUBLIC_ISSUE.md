# `curl_ws_send()` leaves `*sent` unchanged on one blocking raw-send path

## Description

### I did this
I traced the blocking raw-send path in `lib/ws.c` and found that `ws_send_raw_blocking()` has no `pnwritten` output parameter, so the surrounding `ws_send_raw()` path can succeed without updating the caller's `*sent` value. In practice, callers using `curl_ws_send()` from inside a callback in raw mode can observe `*sent == 0` even though the bytes were written.

It looks like an API-contract bug in the current `lib/ws.c` logic.

### I expected the following
On success, the blocking raw-send path should report the number of bytes written to the caller just like the non-blocking path does.

### curl/libcurl version
curl 8.20.0-DEV (`70281e3`) in `lib/ws.c`.

### operating system
Linux x86_64

## Reproduction notes
No runtime PoC is needed — the bug is visible by reading `lib/ws.c` in the current source.

The call path is:

```text
curl_ws_send()       — zeroes *pnsent before dispatching
  -> ws_send_raw()
     -> ws_send_raw_blocking()  — succeeds but never writes to pnwritten
```

Confirmed in current HEAD (`lib/ws.c`):
- `curl_ws_send()` initialises `*pnsent = 0` and delegates to `ws_send_raw()`
- In the blocking callback path, `ws_send_raw()` calls `ws_send_raw_blocking()`
- `ws_send_raw_blocking()` has no `pnwritten` output parameter and does not write back through the caller's pointer
- On return, `*pnsent` remains 0 even though bytes were sent
