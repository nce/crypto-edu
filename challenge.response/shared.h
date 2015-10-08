/*
 * =====================================================================================
 *
 *       Filename: shared.h
 *
 *    Description: Header file for client/server Challenge Response 
 *
 *        Version: 1.0
 *        Created: Thu, 16.12.2010 - 18:38:51
 *  Last modified: Mon, 06.06.2011 - 17:13:12
 *       Revision: none
 *       Compiler: gcc -std=c99 -pedantic -Wall -D_XOPEN_SOURCE=600 -lcrypto 
 *
 *         Author: Ulli Goschler, siulgosc@stud.informatik.uni-erlangen.de
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define RSA_PKCS1_OAEP_PADDING_SIZE 42
#define CLIENTPASSPHRASE "client"
#define SERVERPASSPHRASE "server"
#define AESBUFFSIZE 50

static void dump(unsigned char* hex, int limit) {
	for(int i = 0; i < limit; i++) 
		printf("%X", hex[i]);
	printf("\n");
}

