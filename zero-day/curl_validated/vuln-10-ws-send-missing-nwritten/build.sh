#!/usr/bin/env bash
# Notes for vuln-10: ws_send_raw_blocking() does not update *pnwritten
# API violation: when curl_ws_send() is called in raw mode from inside a curl callback,
# ws_send_raw() dispatches to ws_send_raw_blocking() which sends all bytes but
# never writes to *pnwritten. Caller always sees *sent=0 on success.
# curl lib/ws.c ~1750 — no crash, logical API contract violation
#
# This vulnerability does NOT have a standalone crash PoC since it requires
# an actual WebSocket server connection. The source code evidence is conclusive:
#
#   ws_send_raw() in ws.c ~1744:
#     if(Curl_is_in_callback(data)) {
#       result = ws_flush(data, ws, TRUE);
#       result = ws_send_raw_blocking(data, ws, buffer, buflen);
#       /* *pnwritten is NEVER SET HERE — stays 0 from curl_ws_send init */
#     }
#
# See report.md for full analysis.
#
# Image: curl-validate:20260417 (curl 8.20.0-DEV, commit 70281e3)
echo "vuln-10 is an API contract violation (not a crash)."
echo "Source-level evidence: lib/ws.c ws_send_raw() blocking path never sets *pnwritten."
echo "See report.md for details."
