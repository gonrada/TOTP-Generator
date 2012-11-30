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
 * A easy to user wrapper for the openssl hmac functionality
 */

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
    HMAC_Update(&ctx, data, data_len);
    HMAC_Final(&ctx, result, &result_len);
    HMAC_CTX_cleanup(&ctx);
    
    return result;
}
