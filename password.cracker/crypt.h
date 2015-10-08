/*
 * =====================================================================================
 *
 *       Filename:  crypt.h
 *
 *    Description:  crypto header
 *					used for crackpw and genpw
 *        Version:  1.0
 *        Created:  Thu, 18.11.2010 - 00:18:04 12:18:04 AM
 *       Revision:  none
 *       Compiler:  gcc -std=c99 -pedantic -Wall -Werror -D_XOPEN_SOURCE=600 -g -lcrypt -pthread
 *
 *         Author:  Ulli Goschler, siulgosc@stud.informatik.uni-erlangen.de
 *
 * =====================================================================================
 */

#ifndef CRYPT_H_INCLUDED
#define CRYPT_H_INCLUDED

#define SALTLENGTH 8

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/evp.h>
#define __USE_GNU
#include <crypt.h>

char* genHash(char *pw, char *saltInput, int method) {
	struct crypt_data crypt;
	char salt[SALTLENGTH + 4] = "$1$";
		if(5 == method)
			salt[1] = '5';
		else if(6 == method)
			salt[1] = '6';
	char *hash = NULL;
	char* p = &salt[2];
	char* password = pw;

	crypt.initialized = 0;

	p++;

	int i = 0;
	while(saltInput[i] != '\0') {
		*p++= saltInput[i++];
		if(i >= SALTLENGTH + 1) {
			fprintf(stderr, "Error: Salt was greater than %d\n", SALTLENGTH);
			exit(EXIT_FAILURE);
		}
	}
	*p++ = '$';
	*p = '\0';
	hash = crypt_r(password, salt, &crypt);
	if(hash == NULL) {
		perror("crypt");
		exit(EXIT_FAILURE);
	}

	return hash;
}

#endif // CRYPT_H_INCLUDED
