


#include "generator.h"

int main( int argc, char ** argv)
{
	FILE * configFile;
	bool isConfigured = false, invalid = false;
    char choice[2];

	isConfigured = check_configuration( configFile);

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
				generate_config( configFile);
			}
			else if(choice[0] == '2')
			{
				//restoreConfig()
			}
			else
				invalid = true;
		}while(invalid);
	}
	
//	genPassword()

	return 0;
}


bool check_configuration( FILE * configFile)
{
	
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

bool generate_config(FILE * configFile)
{
    char * seedStr;
	FILE * seedSrc;
	unsigned char * seed, * seedB64;
    unsigned char * key, * keyB64;
    unsigned char user_name[64] = {0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D,0xB7,0x97,0x6A,0x2D};
    unsigned char user_pass[64] = {0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97,0xC5,0xD8,0x34,0x97};
    unsigned char * user_secret;

    configFile = fopen(CONFIG_FILE, "w+");
	if(!configFile)
		return false;

    seed = (unsigned char *) malloc(SEED_LEN);

	seedSrc = fopen("/dev/urandom", "r");
    if(!seedSrc)
        return false;
    fread( seed, SEED_LEN, 1, seedSrc);
    

    seedB64 = base64( seed, SEED_LEN);

    seedStr = (char *) malloc(strlen(seedB64)+7);
    sprintf(seedStr, "seed: %s\n", seedB64);

    fprintf(configFile, "%s", seedStr);    
    printf("%s", seedStr);

    printf("Enter username: ");
    scanf("%s", user_name);
    fprintf(configFile, "user: %s\n", user_name);
   

    printf("Enter password: ");
    scanf("%s", user_pass);

    user_secret = hmac_sha512( user_pass, 64, user_name, 64);

    key = hmac_sha512( user_secret, RESULT_LEN, seed, SEED_LEN);

    printf("key: %s\n", base64(key, RESULT_LEN));

}

char *base64(const unsigned char *input, int length)
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


char *unbase64(unsigned char *input, int length)
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
