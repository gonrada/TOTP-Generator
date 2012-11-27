

#include "hmac.h"

/**
  *
  *
  */
unsigned char * hmac_sha512(unsigned char * key, int key_len, unsigned char * data, int data_len)
{

    HMAC_CTX ctx;

    unsigned char * result;
    unsigned int result_len = RESULT_LEN;

    result = (unsigned char*) malloc(RESULT_LEN);


    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();

    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key, key_len, EVP_sha512(), NULL);
    HMAC_Update(&ctx, (unsigned char*) &data, data_len);
    HMAC_Final(&ctx, result, &result_len);
    HMAC_CTX_cleanup(&ctx);
    
    return result;
}
