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


#include "generator.h"

int main( int argc, char ** argv)
{
	bool isConfigured = false, invalid = false;
	char choice[2];

	do
	{
		isConfigured = check_configuration();
		if(!isConfigured)
		{
			do
			{
				printf("Valid configuration not found\n");
				printf("1.\tGenerate Config & Shared Secrets\n");
				printf("2.\tRestore Configuration\n");
				printf("option: ");
				scanf("%s", choice);
				if(choice[0] == '1')
				{
					generate_config();
				}
				else if(choice[0] == '2')
				{
					//restoreConfig()
				}
				else
					invalid = true;
			}while(invalid);
		}

	}while(!isConfigured);

	generate_totp();

	return 0;
}

/**
 * @pre
 *    Any preconditions that this method requires
 * @post
 *    Any postconditions that result because of this method
 * @param [0, n-1] paramName
 *    Brief description of parameter
 * @return
 *    Brief description of return value
 * @throw
 *    An EXPLICIT throw specification - including which guarantee it offers (basic, strong, nothrow)
 *    and WHY the various exceptions may be thrown.
 */
bool check_configuration()
{
	FILE * configFile;
	configFile = fopen(CONFIG_FILE, "r");
	if(!configFile)
		return false;
	else
	{
		//TODO		validConfig = check_configfile( configFile)
		//TODO		if(!validConfig)
		//TODO			retval = false
	}

	return true;
}

/**
 * @pre
 *    A valid configuration file was not found.
 * @post
 *    None
 * @return
 *    Will return true upon successfully generating a configuration.
 * @throw
 *    An EXPLICIT throw specification - including which guarantee it offers (basic, strong, nothrow)
 *    and WHY the various exceptions may be thrown.
 */
bool generate_config()
{
	char * seedStr;
	FILE * configFile, * keyFile;
	FILE * seedSrc;
	int i=0;
	unsigned char * seed, * seedB64;
	unsigned char * key, * keyB64;
	unsigned char user_name[64] = {0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D};
	unsigned char user_pass[64] = {0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97};
	unsigned char * user_secret;

	configFile = fopen(CONFIG_FILE, "w+");
	if(!configFile)
	{
		printf("Error opening [%s] for w+",CONFIG_FILE);
		return false;
	}

	seed = (unsigned char *) malloc(SEED_LEN);

	seedSrc = fopen("/dev/urandom", "r");
	if(!seedSrc)
	{
		printf("Error opening [%s] for r","/dev/urandom");
		return false;
	}
	fread( seed, SEED_LEN, 1, seedSrc);

	close(seedSrc);


	seedB64 = base64_encode( seed, SEED_LEN);

	printf("\n%d ",strlen(seedB64));

	fprintf(configFile, "%s\n", seedB64);    
	printf("seed: %s\n", seedB64);

	printf("Enter username: ");
	scanf("%s", user_name);
	fprintf(configFile, "%s\n", user_name);


	printf("Enter password: ");
	scanf("%s", user_pass);

	user_secret = hmac_sha512( user_pass, 64, user_name, 64);

	key = hmac_sha512( user_secret, RESULT_LEN, seed, SEED_LEN);
	keyB64 = base64_encode(key, RESULT_LEN);

	keyFile = fopen(KEY_FILE, "w+");
	fwrite(key, RESULT_LEN, 1, keyFile);

	printf("key: %s\n", keyB64);

	free((void*) seed); 
	free((void*) seedB64);
	free((void*) user_secret);
	free((void*) key);
	free((void*) keyB64);

	fclose(keyFile);
	fclose(configFile);
	return true;
}

/**
 * @pre
 *    Any preconditions that this method requires
 * @post
 *    Any postconditions that result because of this method
 * @param [0, n-1] paramName
 *    Brief description of parameter
 * @return
 *    Will return true upon successfully generating a one-time password.
 * @throw
 *    An EXPLICIT throw specification - including which guarantee it offers (basic, strong, nothrow)
 *    and WHY the various exceptions may be thrown.
 */
bool generate_totp()
{
	FILE * configFile;
	int count, i=0;
	uint32_t bin_code, totp;
	uint64_t data;
	unsigned char * seed, seedB64[90];
	unsigned char * key, *result;
	unsigned char user_name[64] = {0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D};
	unsigned char user_pass[64] = {0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97};
	unsigned char * user_secret;
	/* read in seed from config
	 * read in username from config
	 *
	 * prompt for password
	 *
	 * compute shared key
	 *
	 * data = (uint64_t)floor(time(NULL)/PERIOD)
	 *
	 * result = hmac(key, data)
	 *
	 * DBC = dynamic_truncation()
	 *
	 * TOTP = DBC mod (10 ^ DIGITS)
	 */
	configFile = fopen(CONFIG_FILE, "r");
	if(!configFile)
	{
		printf("Error opening [%s] for r",CONFIG_FILE);
		return false;
	}

	fread( seedB64, 90, 1, configFile);
	seedB64[89] = '\0';
	fscanf(configFile, "%s\n", user_name);
	printf("username: %s\n",user_name);
	printf("Enter password: ");
	scanf("%s",user_pass);

	seed = base64_decode( seedB64, 89);

	user_secret = hmac_sha512( user_pass, 64, user_name, 64);

	key = hmac_sha512( user_secret, RESULT_LEN, seed, SEED_LEN);

	data = (uint64_t) floor( time(NULL)/PERIOD);

	result = hmac_sha512( key, RESULT_LEN, (unsigned char *) &data, sizeof(uint64_t) /* 8 */);

	bin_code = dynamic_truncation( result, RESULT_LEN);

	totp = bin_code % (int) floor(pow(10.0, DIGITS));

	printf("\n\tOne-time Password: %u\n\n", totp);

	return true;
}

/**
 * A wrapper for openssl base64 encode.
 *
 * This wrapper was found online. It did what I needed it to.
 * The source can be found here:
 * http://www.ioncannon.net/programming/34/howto-base64-encode-with-cc-and-openssl/
 *
 * @pre
 *    None
 * @post
 *    The return value must later be freed.
 * @param[in] input A pointer to the input byte stream.
 * @param[in] length Length of the input byte stream.
 * @return
 *    A string with the encoded base64 value.
 */
char * base64_encode(const unsigned char *input, int length)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char *buff = (char *)malloc(bptr->length);
	memcpy(buff, bptr->data, bptr->length-1);
	buff[bptr->length-1] = 0;

	BIO_free_all(b64);

	return buff;
}

/**
 * A wrapper for openssl base64 decode.
 *
 * This wrapper was found online. It did what I needed it to.
 * The source can be found here:
 * http://www.ioncannon.net/programming/34/howto-base64-encode-with-cc-and-openssl/
 *
 * @pre
 *    None
 * @post
 *    The return value must later be freed.
 * @param[in] input A pointer to the input base64 stream.
 * @param[in] length Length of the input base64 stream.
 * @return
 *    A string with the decoded base64 value.
 */
char * base64_decode(unsigned char *input, int length)
{
	BIO *b64, *bmem;

	char *buffer = (char *)malloc(length);
	memset(buffer, 0, length);

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);

	BIO_read(bmem, buffer, length);

	BIO_free_all(bmem);

	return buffer;
}

/**
 * Dynamic Truncation Function.
 * 
 * This function is an implementation of the dynamic trucation functionality
 * specified in RFC4226. This function assumes we are using HMAC_SHA512, which
 * has a 64 byte digest. The input length is required so the specific hmac 
 * being used may be more easily changed.
 *
 * @pre
 *    None
 * @post
 *    None
 * @param[in] input A pointer to the result from the hmac.
 * @param[in] length Length of the input byte stream.
 * @return
 *    The value returned is the dynamic binary code (DBC).
 */
uint32_t dynamic_truncation(const unsigned char *input, int length)
{
	uint32_t bin_code;
	unsigned char offset;

	/* Assume 64 bytes; thus we want the low 6 bits */
	offset = input[length - 1] & 0x3F;
	
	/* We do not want the last byte, and we want a consecutive 4 bytes.
	 * Thus for an input of 64 bytes MAX_OFFSET will be 59.
	 */
	offset = offset % MAX_OFFSET;  

	/* RFC4226; Page 7-8;
	*/    
	bin_code = (input[offset] & 0x7f) << 24
		| (input[offset+1] & 0xff) << 16
		| (input[offset+2] & 0xff) << 8
		| (input[offset+3] & 0xff) ;

	return bin_code;
}
