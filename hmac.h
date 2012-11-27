

#ifndef __HMAC_H
#define __HMAC_H

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define RESULT_LEN 64

unsigned char * hmac_sha512(unsigned char * key, int key_len, unsigned char * data, int data_len);

#endif
