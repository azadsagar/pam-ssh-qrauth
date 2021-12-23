#include<stdio.h>
#include<stdlib.h>

#include "utils.h"

void get_random_string(char *random_str,int length)
{
	FILE *fp = fopen("/dev/urandom","r");

	if(!fp){
		perror("Unble to open urandom device");
		exit(EXIT_FAILURE);
	}

	fread(random_str,length,1,fp);
	fclose(fp);
}