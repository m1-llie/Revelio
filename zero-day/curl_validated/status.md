# Security related
vuln-05: reported to HackerOne on Apr 18, curl #3682666. Responded.
Response: experimental functionality, API misuse, a bug and they said will probably make the function return error when called from within a callback.

vuln-08: reported to HackerOne on Apr 19 using will0w, curl #3684603. Responded.
Response: POC is using a private libcurl function, which is not the libcurl API. The threat model is that attacker already has code execution.
After using public API to write poc, still responded with "perhaps a bug, not a security problem."

vuln-03: reported to HackerOne on Apr 19 using h3z, curl #3684614. Responded.
Response: Not a security problem.
The deveoper responded with "if the callers use this function the correct way, it needs no check. Feel free with a PR to improve the internal security."


# Public issues
vuln-01: curl Issue #21366, Responded.
see as API misuse.

vuln-02: curl Issue #21367, Responded.
see as API misuse.

vuln-04: curl Issue #21368, Responded.
see as API misuse.

vuln-06: curl Issue #21369, Responded.
see as API misuse.

vuln-07: curl Issue #21370, Responded.
see as API misuse.

vuln-09: curl Issue #21371, Responded.
see as API misuse.

vuln-10: curl Issue #21372, Responded.
Confirmed and fixed. Commit ebed4aa, ws: fix a blocking curl_ws_send() to report written length correctly. https://github.com/curl/curl/commit/ebed4aaf0136392d8f040de16a29d89777323fb3.
