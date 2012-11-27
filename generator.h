

#ifndef __GENERATOR_H
#define __GENERATOR_H

#include "hmac.h"

#include <math.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CONFIG_FILE ".totp_conf"
#define PERIOD 30
#define SEED_LEN 64


/**
  *
  *
  */
bool check_configuration(FILE * configFile);

/**
  *
  *
  */
bool generate_config(FILE * configFile);

/**
  *
  * http://www.ioncannon.net/programming/34/howto-base64-encode-with-cc-and-openssl/
  */
char *base64(const unsigned char *input, int length);


#endif
