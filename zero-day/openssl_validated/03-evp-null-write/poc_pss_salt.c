#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
int main(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *genctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(genctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, 1024);
    EVP_PKEY_keygen(genctx, &pkey);
    EVP_PKEY_CTX_free(genctx);
    
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_sign_init(pctx);
    /* GET_RSA_PSS_SALTLEN with NULL p2 */
    int ret = EVP_PKEY_CTX_ctrl(pctx, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_SIGN,
                                 EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, 0, NULL);
    printf("ret=%d (should not reach here)\n", ret);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return 0;
}
