/**
 * @file
 * @author Sean Easton <gonrada@gmail.com>
 *
 * @section COURSE
 *
 * Course Information: CIS5370 - Fall '12 <br/>
 * Due Date: December 14, 2012 <br/>
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * A C/C++ implementation of a Time-base One-Time Password generator using openssl
 */


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

/*
 *
 */
bool generate_totp(FILE * configFile);


/**
  *
  * http://www.ioncannon.net/programming/34/howto-base64-encode-with-cc-and-openssl/
  */
char *base64(const unsigned char *input, int length);

char *unbase64(unsigned char *input, int length);

#endif

