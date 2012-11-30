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

#ifndef __HMAC_H
#define __HMAC_H

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define RESULT_LEN 64

unsigned char * hmac_sha512(unsigned char * key, int key_len, unsigned char * data, int data_len);

#endif
