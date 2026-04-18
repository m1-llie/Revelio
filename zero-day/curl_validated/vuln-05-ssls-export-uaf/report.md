# vuln-05: Heap-UAF in curl_easy_ssls_export via Iterator Invalidation

## Validation Status (2026-04-17)
- **Latest curl commit**: `70281e3` (haproxy: use correct ip version on client supplied address)
- **curl version**: 8.20.0-DEV
- **Status**: CONFIRMED STILL PRESENT — no locking protection for single-handle export
- **Runtime crash confirmed**: YES (ASAN heap-use-after-free at vtls_scache.c:1214)
- **Validation image**: `curl-validate:20260417`
- **Requires**: `--enable-ssls-export` build flag (present in curl-validate:20260417)

### Crash Output (latest build)
```
[*] Exporting sessions (callback will try to mutate the list)
[CB] Importing new session during export callback (iterator mutation!)
==10==ERROR: AddressSanitizer: heap-use-after-free on address 0x7bf5e1ae0468
READ of size 4 at 0x7bf5e1ae0468 thread T0
    #0 Curl_node_next /src/curl/lib/llist.c:246:3
    #1 Curl_ssl_session_export /src/curl/lib/vtls/vtls_scache.c:1214:11
    #2 main /work05/poc.c:111:11
freed by thread T0 here:
    #0 free ...
    #1 cf_scache_peer_add_session /src/curl/lib/vtls/vtls_scache.c:781:7
    #2 Curl_ssl_session_import /src/curl/lib/vtls/vtls_scache.c:1134:5
    #3 export_callback /work05/poc.c:69:18
    #4 Curl_ssl_session_export /src/curl/lib/vtls/vtls_scache.c:1206:11
SUMMARY: AddressSanitizer: heap-use-after-free in Curl_node_next
```

---

# Bug Report: SC_FOLDER_071047_SF12

## Title
Heap-use-after-free in `curl_easy_ssls_export` via iterator invalidation when export callback calls `curl_easy_ssls_import`

## CVE-worthy?
**Yes.** This is a heap-use-after-free (UAF) in curl's SSL session export API. When the export callback (provided by the application) calls `curl_easy_ssls_import` on the same handle (a natural pattern for session migration workflows), the import evicts old sessions while the export is still iterating the session list. The `Curl_node_next(n)` call at the top of the next iteration accesses the freed session node, causing UAF that can lead to crash or memory corruption.

## Affected File:Line
- `lib/vtls/vtls_scache.c:1214` — `Curl_ssl_session_export` calls `Curl_node_next(n)` on a freed node
- `lib/vtls/vtls_scache.c:1206` — `export_fn` callback invoked while iterating `peer->sessions`
- `lib/vtls/vtls_scache.c:781` — `cf_scache_peer_add_session` frees old sessions during import

## Root Cause
`Curl_ssl_session_export` iterates `peer->sessions` with a while loop, advancing the iterator at the end: `n = Curl_node_next(n)`. However, it invokes the `export_fn` callback at line 1206 while holding the session lock (only if a `CURLSHOPT_SHARE` is in use). Without a share handle (the common case), there is no lock, and the callback can re-enter `curl_easy_ssls_import` on the same handle. When the import adds a new TLS 1.3 session for the same peer, `cf_scache_peer_add_session` may call `Curl_llist_destroy` (via `Curl_node_remove`) to evict old sessions, freeing the node `n` that the export loop will dereference on the next iteration at `Curl_node_next(n)`.

The crash call chain:
1. `Curl_ssl_session_export` starts iterating session 1 (n = session1_node)
2. `export_fn` callback called for session 1
3. Callback calls `curl_easy_ssls_import` → imports session 3
4. Import calls `cf_scache_peer_add_session` → evicts session 1 (since max TLS1.3 sessions is limited)
5. Session 1 is freed
6. Back in export loop: `n = Curl_node_next(n)` → n is now freed → **UAF**

## Crash Output (ASAN)
```
[CB] export callback called for session_key=example.com:443:IMPL-OpenSSL:G
[CB] Importing new session during export callback (iterator mutation!)
[CB] Import during export result: 0
=================================================================
==10==ERROR: AddressSanitizer: heap-use-after-free on address 0x7bc75e9e0078 at pc 0x55a0d720ab92
READ of size 8 at 0x7bc75e9e0078 thread T0
    #0 Curl_node_next /src/curl/lib/llist.c:248:10
    #1 Curl_ssl_session_export /src/curl/lib/vtls/vtls_scache.c:1214:11
    #2 main /work/poc_sf12_iterator.c:111:11

freed by thread T0 here:
    #0 free ...
    #1 cf_scache_peer_add_session /src/curl/lib/vtls/vtls_scache.c:781:7
    #2 Curl_ssl_session_import /src/curl/lib/vtls/vtls_scache.c:1134:5
    #3 export_callback /work/poc_sf12_iterator.c:69:18
    #4 Curl_ssl_session_export /src/curl/lib/vtls/vtls_scache.c:1206:11
SUMMARY: AddressSanitizer: heap-use-after-free /src/curl/lib/llist.c:248:10 in Curl_node_next
```

## Reproduction Steps
1. Build curl with `USE_SSLS_EXPORT=ON` and ASAN.
2. Compile the PoC:
   ```bash
   clang -fsanitize=address -g -O1 SC_FOLDER_071047_SF12_poc.c \
     -I/src/curl/include libcurl.a -lssl -lcrypto -lz -lpthread -o poc_sf12
   ```
3. Run:
   ```bash
   ASAN_OPTIONS=detect_leaks=0 ./poc_sf12
   ```

## Suggested Fix
The fix requires preventing the export callback from mutating the session list while iteration is in progress. Two approaches:

**Option A (Snapshot before iterating):** Before iterating, take a snapshot of the session list (copy node pointers to an array), then release the iteration and call callbacks without holding the active iterator. This avoids UAF at the cost of a small allocation.

**Option B (Advance iterator before calling callback):**
```c
while(n) {
    struct Curl_ssl_session *s = Curl_node_elem(n);
    n = Curl_node_next(n);  /* advance BEFORE callback can free current node */
    /* ... pack and call export_fn ... */
}
```
This safe-iteration pattern is already used in `cf_scache_peer_remove_expired` (lines 507-513) but was missed in `Curl_ssl_session_export`.

**Option C (Document and prevent re-entry):** Document that the export callback MUST NOT call any libcurl session import/export functions, and add a re-entrancy guard (e.g., a `BIT(exporting)` flag in the peer struct) that causes `curl_easy_ssls_import` to return an error if called during an active export iteration.

Option B is the simplest fix.
