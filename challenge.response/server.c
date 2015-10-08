/*
 * =====================================================================================
 *
 *       Filename: server.c
 *
 *    Description: A challenge/response implemenation with following AES encryption 
 *
 *	               the Server will challenge the client with a RSA encrypted Nonce (client's public Key)
 *	               the client decrypts it; stores it; and encryptes it again (server's  public Key)
 *	               the server decryptes the messages; compares it with the (created) Nonce
 *	               
 *	               In case of success, the server initiates a AES-256-ofb "session"
 *	               (IV consists of half the "challenge", key the other half)
 *	               the client does same
 *	               pseudo conversation starts
 *
 *	               server binds to specified port, using ipv6/TCP
 *
 *        Version: 1.0
 *        Created: Thu, 16.12.2010 - 19:30:07
 *  Last modified: Mon, 06.06.2011 - 17:18:19
 *       Revision: none
 *       Compiler: gcc -std=c99 -pedantic -Wall -D_XOPEN_SOURCE=600 -lcrypto -O2
 *
 *         Author: Ulli Goschler, ulligoschler@gmail.com
 *
 * =====================================================================================
 */

#include "shared.h"

static void usageError() {
	fprintf(stderr, "Usage: ./server <private-server-key> <public-client-key> <port>\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
	if(argc != 4)
		usageError();

	int port = atoi(argv[3]);
	int sock, sock_opt, accepted_sock, encSize, decSize, encSizeFromClient, decSizeFromClient;
	struct sockaddr_in6 addr;
	socklen_t addr_len;
	FILE *c, *pubKey, *privKey;
		
	RSA *rsaPubKey = NULL;
	RSA *rsaPrivKey = NULL;
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	memset(&addr, 0, sizeof(addr));
	addr.sin6_port = htons(port);
	addr.sin6_family = AF_INET6;

	if(port < 1024 || port > 65535) {
		fprintf(stderr, "Better choose a port between 1024 and 65535\n");
		exit(EXIT_FAILURE);
	}
	
	if(-1 == (sock = socket(AF_INET6, SOCK_STREAM, 0))) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	sock_opt = 1;
	if(-1 == setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(int))) 
		perror("setsockopt");
	if(-1 == bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
		perror("bind");
		exit(EXIT_FAILURE);
	}
	if(-1 == listen(sock, 1)) {
		perror("listen");
		exit(EXIT_FAILURE);
	}
	printf("Listening on port %d ...\n", port);

	for(;;) {
		addr_len = sizeof addr;
		if(-1 == (accepted_sock = accept(sock, (struct sockaddr *) &addr, &addr_len))) {
			perror("accept");
			fprintf(stderr, "Try again\n");
			continue;
		}
			
		if(NULL == (c = fdopen(accepted_sock, "a+"))) {
			perror("fdopen");
			fprintf(stderr, "Try again\n");
			continue;
		}
		printf("Connection established\n");

		/* START WITH RSA */
		
		/* open public Key */
		if(NULL == (pubKey = fopen(argv[2], "r"))) {
			perror("fopen");
			continue;
		}

		/* read public Key */
		if(NULL == (rsaPubKey = PEM_read_RSA_PUBKEY(pubKey, NULL, NULL, NULL))) {
			perror("PEM_read_RSA_PUBKEY");
			continue;
		}
		encSize = RSA_size(rsaPubKey);
		decSize = RSA_size(rsaPubKey) - RSA_PKCS1_OAEP_PADDING_SIZE;
		
		unsigned char decChallenge[decSize];
		unsigned char encChallenge[encSize];
		
		/* create Nonce */
		if(1 != RAND_bytes(decChallenge, decSize)) {
			fprintf(stderr, "RAND_bytes: %s\nTrying pseudo random now\n", ERR_error_string(ERR_get_error(), NULL)); 
			if(1 != RAND_pseudo_bytes(decChallenge, decSize)) {
				fprintf(stderr, "pseudorandomness failed\n");
				continue;
			}
		}
		
		/* encrypt Nonce with client public key */
		if(-1 == RSA_public_encrypt(decSize, decChallenge, encChallenge, rsaPubKey, RSA_PKCS1_OAEP_PADDING)) {
			fprintf(stderr, "RSA_public_encrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));
			continue;
		}
#ifdef DEBUG
		printf("plaintext Challenge generated:\n");
		dump(decChallenge, decSize);
		printf("encrypted Challenge generated:\n");
		dump(encChallenge, encSize);
#endif

		/* challenge the client */
		fwrite(encChallenge, encSize, 1, c);

		
		/* read/open private key */
		if(NULL == (privKey = fopen(argv[1], "r"))) {
			perror("fopen");
			continue;
		}
		if(NULL == (rsaPrivKey = PEM_read_RSAPrivateKey(privKey,NULL, NULL, SERVERPASSPHRASE))) {
			fprintf(stderr, "PEM_read_RSAPrivateKey: %s\n", ERR_error_string(ERR_get_error(), NULL));
			continue;
		}
		encSizeFromClient = RSA_size(rsaPrivKey);
		decSizeFromClient = RSA_size(rsaPrivKey) - RSA_PKCS1_OAEP_PADDING_SIZE;
		unsigned char encChallengeFromClient[encSizeFromClient];
		unsigned char decChallengeFromClient[decSizeFromClient];
		
		/* get encrypted challenge from client */
		fread(encChallengeFromClient, encSizeFromClient, 1, c);

#ifdef DEBUG
		printf("encrypted Challenge received:\n");	
		dump(decChallengeFromClient, encSizeFromClient);
#endif
		/* decrypt the challenge */
		if(0 == RSA_private_decrypt(encSizeFromClient, encChallengeFromClient, decChallengeFromClient, rsaPrivKey, RSA_PKCS1_OAEP_PADDING)) {
			fprintf(stderr, "RSA_public_decrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));
			continue;
		}

		/* check if response matches the created Nonce */
		if(0 != memcmp(decChallenge, decChallengeFromClient, decSize)) {
			fprintf(stderr, "Challenge not successful\n");
			continue;
		}
		printf("Authentication successfull\n");

		/*-----------------------------------------------------------------------------
		 *  challenge successfull
		 *  starting AES
		 *-----------------------------------------------------------------------------*/

		EVP_CIPHER_CTX cctx;
		EVP_CIPHER_CTX_init(&cctx);
		int keylen = decSize/2;
		unsigned char key[keylen];
		unsigned char iv[keylen];
		memcpy(key, decChallenge, keylen); 
		memcpy(iv, decChallenge+keylen, keylen);

		if(0 == EVP_CipherInit_ex(&cctx, EVP_aes_256_ofb(), NULL, key, iv, 1)){
			perror("EVP_CipherInit_ex");
			continue;
		}
		
		int bufLen = AESBUFFSIZE; 
		unsigned char *decBuf = (unsigned char*) malloc(AESBUFFSIZE);
		unsigned char *encBuf = (unsigned char*) malloc(AESBUFFSIZE);
		decBuf = (unsigned char*) "Hello from server!";

		if(0 == EVP_CipherUpdate(&cctx, encBuf, &bufLen, decBuf, bufLen)) {
			EVP_CIPHER_CTX_cleanup(&cctx);
			perror("EVP_CipherUpdate");
			continue;
		}
		EVP_CIPHER_CTX_cleanup(&cctx);

		printf("Send AES message: %s\n", decBuf);
		fwrite(encBuf, bufLen, 1, c);

		bufLen = AESBUFFSIZE;
		if(0 == EVP_CipherInit_ex(&cctx, EVP_aes_256_ofb(), NULL, key, iv, 0)){
			perror("EVP_CipherInit_ex");
			continue;
		}
		encBuf = (unsigned char*) malloc(AESBUFFSIZE);
		decBuf = (unsigned char*) malloc(AESBUFFSIZE);
		fread(encBuf, AESBUFFSIZE, 1, c);
		if(0 == EVP_CipherUpdate(&cctx, decBuf, &bufLen, encBuf, bufLen)) {
			EVP_CIPHER_CTX_cleanup(&cctx);
			perror("EVP_CipherUpdate");
			continue;
		}
		EVP_CIPHER_CTX_cleanup(&cctx);
		printf("Received AES message: %s\n", decBuf);

		fclose(c);
		free(decBuf);
		free(encBuf);
		printf("Good Bye\n");
	}

	return 0;
}

