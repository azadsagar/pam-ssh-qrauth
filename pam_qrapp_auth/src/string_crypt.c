#include<stdio.h>
#include<openssl/sha.h>
#include<string.h>
#include "string_crypt.h"

void string_crypt(char *dst,const char *src)
{
    unsigned char sha_sum[SHA_DIGEST_LENGTH];
    int i;
    char *b = dst;

    SHA1(src,strlen(src),sha_sum);

    for(i=0;i< SHA_DIGEST_LENGTH;i++){
        sprintf(b,"%02x",sha_sum[i]);
        b+=2;
    }
}