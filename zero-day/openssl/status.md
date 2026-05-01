bug reported as public issues:

02-pkcs7-negidx-encdat: reported, openssl Issue #30910
Link: https://github.com/openssl/openssl/issues/30910
Type: null pointer dereference.
Confirmed and fixed.
Developers: "This issue is valid.
The same affected code exists in current master and in 3.4/3.5/3.6/4.0 as well.
This is not a security issue since it requires the application to call PKCS7_get_issuer_and_serial with an out-of-range negative index. This function is also specific to legacy signedAndEnveloped PKCS7 handling and there are no internal callers in the current codebase."

03-evp-null-write: reported, openssl Issue #30911
Link: https://github.com/openssl/openssl/issues/30911
Type: null pointer derefence.
No response yet.

05-ec-null-scalar: reported, openssl Issue #30912
Link: https://github.com/openssl/openssl/issues/30912.
NULL scalar despite documented contract.
No response yet.