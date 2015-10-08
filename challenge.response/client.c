/*
 * =====================================================================================
 *
 *       Filename: client.c
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
 *	               client accepts ipv4/ipv6 connection
 *
 *        Version: 1.0
 *        Created: Thu, 16.12.2010 - 17:38:51
 *  Last modified: Fri, 17.12.2010 - 23:41:13
 *       Revision: none
 *       Compiler: gcc -std=c99 -pedantic -Wall -D_XOPEN_SOURCE=600 -lcrypto -O2
 *
 *         Author: Ulli Goschler, ulligoschler@gmail.com
 *
 * =====================================================================================
 */

#include "shared.h"

static void usageError() {
	fprintf(stderr, "Usage: ./client <private-client-key> <public-server-key> <ip> <port>\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
	if(argc != 5)
		usageError();
	
	struct addrinfo hints, *res, *p;
	int sock, gai;
	FILE *s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;    // use tcp socket
	hints.ai_family   = PF_UNSPEC;      // use ipv4 or ipv6
	hints.ai_flags    = AI_ADDRCONFIG;  // use ipv6 if we have interface

	printf("Connecting to %s:%s ...\n", argv[3], argv[4]);

	if(0 != (gai = getaddrinfo(argv[3], argv[4], &hints, &res))) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
		exit(EXIT_FAILURE);
	}
	
	/* as no domain was specified, use both (v4/v6) and check which connects properly */
	for(p = res; p != NULL; p = p->ai_next) {
		sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if(0 == connect(sock, p->ai_addr, p->ai_addrlen)) 
			break;

	}
	if(NULL == p) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
#ifdef DEBUG
	printf("Domain: %d; Type: %d; Protocol: %d\n", p->ai_family, p->ai_socktype, p->ai_protocol);
#endif
	
	/* open network stream for conveniente read/write */
	if(NULL == (s = fdopen(sock, "a+"))) {
		perror("fdopen");
		exit(EXIT_FAILURE);
	}
	
	printf("Connection established\n");

	/* init crypto */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	FILE *privKey, *pubKey;
	RSA *rsaPrivKey = NULL;
	RSA *rsaPubKey = NULL;
	int encSize, decSize, encSizeToServer;

	/* open and read client private key */
	if(NULL == (privKey = fopen(argv[1], "r"))) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}
	if(NULL == (rsaPrivKey = PEM_read_RSAPrivateKey(privKey,NULL, NULL, CLIENTPASSPHRASE))) {
		fprintf(stderr, "PEM_read_RSAPrivateKey: %s\n", ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	encSize = RSA_size(rsaPrivKey);
	decSize = RSA_size(rsaPrivKey) - RSA_PKCS1_OAEP_PADDING_SIZE;

	unsigned char decChallenge[decSize];
	unsigned char encChallenge[encSize];

	/* get the encrypted challenge from server */
	fread(encChallenge, encSize, 1, s);
#ifdef DEBUG
	printf("encrypted Challenge received:\n");
	dump(encChallenge, encSize);
#endif

	/* decrypted challenge from server */
	if(0 == RSA_private_decrypt(encSize, encChallenge, decChallenge, rsaPrivKey, RSA_PKCS1_OAEP_PADDING)) {
		fprintf(stderr, "RSA_public_decrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	unsigned char challenge[decSize];	
	memcpy(challenge, decChallenge, decSize);   // save the decrypted challenge for later
	
	/* encrypting answer to server */
	/* open server public Key */
	if(NULL == (pubKey = fopen(argv[2], "r"))) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}
	if(NULL == (rsaPubKey = PEM_read_RSA_PUBKEY(pubKey, NULL, NULL, NULL))) {
		perror("PEM_read_RSA_PUBKEY");
		exit(EXIT_FAILURE);
	}
	encSizeToServer = RSA_size(rsaPubKey);
	unsigned char encChallengeToServer[encSizeToServer];

	/* encrypt the (decrypted) challenge again, now with server's publickey */
	if(-1 == RSA_public_encrypt(decSize, decChallenge, encChallengeToServer, rsaPubKey, RSA_PKCS1_OAEP_PADDING)) {
		fprintf(stderr, "RSA_public_encrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
#ifdef DEBUG
	printf("plaintext Challenge received:\n");
	dump(decChallenge, decSize);
	printf("encrypted Challenge to Server:\n");
	dump(encChallengeToServer, encSizeToServer);
#endif

	/* send encrypted challenge to server */
	fwrite(encChallengeToServer, encSizeToServer,1, s);

	/*-----------------------------------------------------------------------------
	 *  Challenge Response finished
	 *	    Attention: there is no (client) verification if chall/resp has successfully finished
	 *      in case of failure, client will get stuck...
	 *	
	 *	continuing with AES	
	 *	    IV  consisting of 1/2 of the Challenge
	 *      KEY consisting of the other half 
	 *-----------------------------------------------------------------------------*/

	EVP_CIPHER_CTX cctx;
	EVP_CIPHER_CTX_init(&cctx);
	int keylen = decSize/2;
	unsigned char key[keylen];
	unsigned char iv[keylen];
	memcpy(key, challenge, keylen); 
	memcpy(iv, challenge+keylen, keylen);
	
	/* init AES decrypt context */
	if(0 == EVP_CipherInit_ex(&cctx, EVP_aes_256_ofb(), NULL, key, iv, 0)){
		perror("EVP_CipherInit_ex");
		exit(EXIT_FAILURE);
	}
	unsigned char *decBuf = (unsigned char*) malloc(AESBUFFSIZE);
	unsigned char *encBuf = (unsigned char*) malloc(AESBUFFSIZE);
	
	/* get the "Hello from server!" message */
	fread(encBuf, AESBUFFSIZE, 1, s);
	printf("Authentication successfull\n");
	int bufLen = AESBUFFSIZE;

	/* decrypt the message */
	if(0 == EVP_CipherUpdate(&cctx, decBuf, &bufLen, encBuf, bufLen)) {
		EVP_CIPHER_CTX_cleanup(&cctx);
		perror("EVP_CipherUpdate");
		exit(EXIT_FAILURE);
	}
	EVP_CIPHER_CTX_cleanup(&cctx);

	printf("Received AES message: %s\n", decBuf);

	/* init AES encrypt context */
	bufLen = AESBUFFSIZE;	
	if(0 == EVP_CipherInit_ex(&cctx, EVP_aes_256_ofb(), NULL, key, iv, 1)){
		perror("EVP_CipherInit_ex");
		exit(EXIT_FAILURE);
	}
	/* restore all buffers */
	bufLen = AESBUFFSIZE;	
	decBuf = (unsigned char*) malloc(AESBUFFSIZE);
	encBuf = (unsigned char*) malloc(AESBUFFSIZE);

	/* encrypt and send the client -> server message */
	decBuf = (unsigned char*) "Hello from client.";
	if(0 == EVP_CipherUpdate(&cctx, encBuf, &bufLen, decBuf, bufLen)) {
		EVP_CIPHER_CTX_cleanup(&cctx);
		perror("EVP_CipherUpdate");
		exit(EXIT_FAILURE);
	}
	printf("Send AES message: %s\n", decBuf);
	fwrite(encBuf, bufLen, 1, s);

	/* sending/receiving could continue here */


	/* cleanup */
	EVP_CIPHER_CTX_cleanup(&cctx);
	fclose(s);
	freeaddrinfo(res);

	printf("Connection closed.\n");

	return 0;
}

