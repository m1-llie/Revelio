# vuln-10: ws_send_raw_blocking() Missing *pnwritten Update (API Violation)

## Validation Status (2026-04-17)
- **Latest curl commit**: `70281e3` (haproxy: use correct ip version on client supplied address)
- **curl version**: 8.20.0-DEV
- **Status**: CONFIRMED STILL PRESENT — blocking path never sets *pnwritten
- **Runtime crash confirmed**: NO (this is a logic/API contract bug, not a memory safety crash)
- **Source evidence**: `lib/ws.c` `ws_send_raw()` lines ~1743-1758
- **Validation image**: `curl-validate:20260417`

### Source Evidence (latest build)
```c
// ws_send_raw() in lib/ws.c ~1743:
if(Curl_is_in_callback(data)) {
    result = ws_flush(data, ws, TRUE);
    if(result) return result;
    result = ws_send_raw_blocking(data, ws, buffer, buflen);
    // BUG: *pnwritten is NEVER SET HERE
    // ws_send_raw_blocking() has no pnwritten parameter
    // caller's *sent stays at 0 (set by curl_ws_send init at line 1784)
}
```

### Impact
Applications using `curl_ws_send()` in raw mode (`CURLWS_RAW_MODE`) from inside a curl
callback will always observe `*sent == 0` even when all bytes were successfully transmitted.
This violates the documented API contract and can cause infinite retry loops.

---

# WebSocket Vulnerability Hypothesis Analysis - curl latest
## Session: 062847 (claude-haiku-4-5)

Date: 2026-04-17
Source file: `lib/ws.c`
Hypotheses evaluated: 19 (SF01–SF19)
Confirmed bugs: 1 (logic/API contract)
False positives: 18

---

## False Positives

### SF01 – Buffer overflow in ws_dec_read_head() for masked 64-bit payload frames
**Status: FALSE POSITIVE**

The hypothesis claims `head[10]` is insufficient when MASK bit is set (requiring 14 bytes).
However, the decoder is client-side and RFC 6455 mandates servers MUST NOT mask frames.
`ws_dec_read_head()` at line ~395 immediately rejects any masked incoming frame:
```c
if(dec->head[1] & WSBIT_MASK) {
    failf(data, "[WS] masked input frame");
    ws_dec_reset(dec);
    return CURLE_RECV_ERROR;
}
```
The mask decode path is never reached. `head[10]` is exactly the right size for unmasked server frames.

---

### SF02 – NULL pointer dereference in ws_enc_write_payload() with NULL buffer
**Status: FALSE POSITIVE**

`curl_ws_send()` validates at line ~1786:
```c
if(!buffer && buflen) {
    failf(data, "[WS] buffer is NULL when buflen is not");
    return CURLE_BAD_FUNCTION_ARGUMENT;
}
```
NULL buffer is rejected before the encoder is reached.

---

### SF03 – Integer underflow in ws_payload_remain() leading to OOB read
**Status: FALSE POSITIVE**

`ws_payload_remain()` (line 654) explicitly returns -1 on any invalid state:
```c
if((payload_total < 0) || (payload_offset < 0) || (remain < 0))
    return -1;
if(remain < buffered)
    return -1;
```
All callers (`ws_cw_dec_next`, `ws_client_collect`) check for `< 0` and return `CURLE_BAD_FUNCTION_ARGUMENT`.
No wraparound or out-of-bounds read is possible.

---

### SF04 – Oversized PING/PONG/CLOSE frames violating RFC 6455 §5.5
**Status: FALSE POSITIVE**

Explicit per-opcode checks exist in `ws_dec_read_head()` at lines 402–420:
```c
if(dec->frame_flags & CURLWS_PING && dec->head[1] > WS_MAX_CNTRL_LEN) { ... }
if(dec->frame_flags & CURLWS_PONG && dec->head[1] > WS_MAX_CNTRL_LEN) { ... }
if(dec->frame_flags & CURLWS_CLOSE && dec->head[1] > WS_MAX_CNTRL_LEN) { ... }
```
`WS_MAX_CNTRL_LEN = 125`. Frames with payload > 125 (including extended-length encodings
126/127) are rejected. The asymmetry concern in the hypothesis is unfounded.

---

### SF05 – Buffer overflow via unbounded nread in cr_ws_read()
**Status: FALSE POSITIVE**

`ws_enc_write_payload()` at line ~961 clamps to `enc->payload_remain`:
```c
remain = curlx_sotouz_range(enc->payload_remain, 0, SIZE_MAX);
if(remain < len)
    len = remain;
```
`nread` is bounded by the remaining payload. No overflow possible.

---

### SF06 – Buffer overflow via nread > blen in cr_ws_read()
**Status: FALSE POSITIVE**

`Curl_creader_read()` is a libcurl internal API. The framework guarantees nread ≤ blen.
The hypothesis requires a malicious implementation of the reader callback, which is not
an attacker-controlled path for network-facing attack scenarios.

---

### SF07 – Heap buffer overflow via unbounded payload_len in fragmented frames
**Status: FALSE POSITIVE**

`ws_client_collect()` at line ~1511 uses `CURLMIN` to clamp:
```c
DEBUGASSERT(ctx->buflen >= ctx->bufidx);
write_len = CURLMIN(buflen, ctx->buflen - ctx->bufidx);
if(!write_len) {
    ...
    return CURLE_AGAIN;  /* no more space */
}
```
When the caller's buffer is full, `CURLE_AGAIN` is returned and no further writes occur.

---

### SF08 – Integer overflow in update_meta() corrupting bytesleft
**Status: FALSE POSITIVE**

`dec->payload_offset` is only advanced by `nwritten` in `ws_dec_pass_payload()`, where
`nwritten ≤ remain = payload_len - payload_offset`. Therefore `payload_offset` can never
exceed `payload_len`, and the subtraction in `update_meta()` is safe.

---

### SF09 – Buffer overflow in ws_client_collect via unvalidated ctx.bufidx
**Status: FALSE POSITIVE**

Same analysis as SF07. The `DEBUGASSERT` plus `CURLMIN` pattern ensures `bufidx` never
exceeds `buflen`. `CURLE_AGAIN` propagates correctly to stop decoding when space runs out.

---

### SF10 – NULL pointer dereference in ws_cw_dec_next() when WS metadata unregistered
**Status: FALSE POSITIVE**

`ws_cw_write()` at line ~726 checks for NULL `ws` and returns `CURLE_FAILED_INIT`:
```c
ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
if(!ws) {
    failf(data, "[WS] not a websocket transfer");
    return CURLE_FAILED_INIT;
}
```
The NULL `ws` is never passed to `ws_cw_dec_next()`.

---

### SF11 – Integer underflow in update_meta() exposing negative bytesleft
**Status: FALSE POSITIVE**

Same root analysis as SF08. `payload_offset` tracks progress faithfully and never exceeds
`payload_len`. The `bytesleft` value in `recvframe` is always >= 0.

---

### SF12 – Missing bounds validation on nwritten in ws_dec_pass_payload()
**Status: FALSE POSITIVE**

The `nwritten` value is produced by `ws_client_collect` (or `ws_cw_dec_next`), which
returns `write_len = CURLMIN(buflen, ctx->buflen - ctx->bufidx)`. This is always <= inlen.
`Curl_bufq_skip()` is called with a safe value.

---

### SF13 – Negative ws->enc.payload_remain causing integer underflow in cr_ws_read()
**Status: FALSE POSITIVE**

`curlx_sotouz_range(ws->enc.payload_remain, 0, blen)` safely clamps negative values to 0.
The function signature is explicit: negative inputs map to the minimum (0), per
`curlx_sotouz_range` implementation in `lib/curlx/warnless.c`.

---

### SF14 – Uninitialized pnwritten when buflen=0 in ws_send_raw()
**Status: FALSE POSITIVE**

`curl_ws_send()` sets `*pnsent = 0` at line ~1784 unconditionally before any early
returns. When `buflen=0`, `ws_send_raw()` returns early, but `*pnsent` was already
initialized to 0 by the caller.

---

### SF15 – Use-after-free via unchecked buffer_arg pointer in curl_ws_send()
**Status: FALSE POSITIVE (API misuse)**

This requires passing a freed pointer as `buffer_arg` — that is the caller's
responsibility. It is not a vulnerability in curl itself; it is caller undefined behavior.
No memory-safety mitigation is expected for this pattern in C APIs.

---

### SF16 – NULL pointer dereference in curl_ws_recv() with NULL CURL handle
**Status: FALSE POSITIVE**

`GOOD_EASY_HANDLE(data)` at line ~1541 evaluates `(x) && ((x)->magic == ...)`.
The short-circuit `&&` means NULL is handled gracefully; `CURLE_BAD_FUNCTION_ARGUMENT`
is returned.

---

### SF17 – NULL pointer dereference in curl_ws_send() with NULL CURL handle
**Status: FALSE POSITIVE**

Same as SF16 — `GOOD_EASY_HANDLE` at line ~1778 guards against NULL handles.

---

### SF18 – NULL pointer dereference via unchecked reader->ctx in cr_ws_read()
**Status: FALSE POSITIVE**

`cr_ws_read()` is an internal libcurl reader callback, invoked only from the framework
which always constructs the `Curl_creader` with a valid `ctx`. This is not attacker-reachable.

---

## Confirmed Bugs

### SF19 – ws_send_raw_blocking() does not update *pnwritten; caller sees *sent=0 on success (raw mode + callback context)
**Status: REAL BUG — Logic/API contract violation**

**Severity: Low–Medium** (correctness/DoS, not memory safety)

**Root cause:**
When `curl_ws_send()` is called in raw WebSocket mode (`CURLOPT_WS_OPTIONS` with
`CURLWS_RAW_MODE`) from inside a curl callback, `ws_send_raw()` dispatches to
`ws_send_raw_blocking()` which sends all bytes but never writes to `*pnwritten`.
After the call returns, `*sent` is still 0 (as initialized at line ~1784).
The function returns `CURLE_OK` but misreports 0 bytes sent.

**Affected code:**
- `lib/ws.c`: `ws_send_raw()` lines 1729–1763
- `lib/ws.c`: `ws_send_raw_blocking()` lines 1685–1727 (no `*pnwritten` parameter)

**Impact:**
- Applications relying on `*sent` to detect partial sends in raw callback mode will
  enter an infinite retry loop, since they see 0 bytes sent but CURLE_OK.
- `CURL_TRC_WS` trace logging prints an incorrect byte count (0 instead of buflen).
- Not exploitable for memory corruption; DoS (spin loop) is the worst case.

**Reproduction:**
1. Establish a WebSocket connection with `CURLOPT_WS_OPTIONS = CURLWS_RAW_MODE`
2. From within a write/read callback, call `curl_ws_send()`
3. Check `*sent` — it will be 0 despite successful transmission

**Suggested fix:**
In `ws_send_raw()`, when in callback mode, update `*pnwritten` after
`ws_send_raw_blocking()` succeeds:
```c
if(Curl_is_in_callback(data)) {
    result = ws_flush(data, ws, TRUE);
    if(result)
        return result;
    result = ws_send_raw_blocking(data, ws, buffer, buflen);
    if(!result && pnwritten)
        *pnwritten = buflen;  /* blocking send sent everything */
}
```

---

## Summary Table

| ID   | Title (abbreviated)                              | Status         | Severity |
|------|--------------------------------------------------|----------------|----------|
| SF01 | head[10] overflow for masked 64-bit frames       | False positive | —        |
| SF02 | NULL buffer dereference in encoder               | False positive | —        |
| SF03 | ws_payload_remain() underflow → OOB read         | False positive | —        |
| SF04 | Oversized control frames bypass 125-byte limit   | False positive | —        |
| SF05 | nread overflow in cr_ws_read                     | False positive | —        |
| SF06 | nread > blen overflow                            | False positive | —        |
| SF07 | Heap overflow via fragmented frame payload_len   | False positive | —        |
| SF08 | Integer overflow corrupting bytesleft            | False positive | —        |
| SF09 | bufidx overflow in ws_client_collect             | False positive | —        |
| SF10 | NULL ws pointer in ws_cw_dec_next                | False positive | —        |
| SF11 | Negative bytesleft from update_meta              | False positive | —        |
| SF12 | Unvalidated nwritten in ws_dec_pass_payload      | False positive | —        |
| SF13 | Negative payload_remain causes underflow         | False positive | —        |
| SF14 | Uninitialized pnwritten for buflen=0             | False positive | —        |
| SF15 | Use-after-free via freed buffer_arg              | False positive | —        |
| SF16 | NULL CURL handle in curl_ws_recv                 | False positive | —        |
| SF17 | NULL CURL handle in curl_ws_send                 | False positive | —        |
| SF18 | NULL reader->ctx dereference                     | False positive | —        |
| SF19 | ws_send_raw_blocking missing *pnwritten update   | **CONFIRMED**  | Low      |
