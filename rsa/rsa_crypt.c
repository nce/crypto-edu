/*
 * =====================================================================================
 *
 *       Filename: rsa_crypt.c
 *
 *    Description: ATTENTION THIS IS FOR DEMONSTRATION PURPOSE ONLY
 *                 This program may (en|de)crypt a given message (m) by a given (public|private) Key
 *                 enc <m> <e> <n>
 *                 dec <m> <d> <n>
 *                 Keep in mind, this is only designed for integer calculation!
 *
 *        Version: 1.0
 *        Created: Mon, 06.06.2011 - 15:51:14
 *  Last modified: Mon, 06.06.2011 - 16:37:29
 *       Revision: none
 *       Compiler: gcc -std=c99 -pedantic -Wall -D_XOPEN_SOURCE=600 -O2 
 *
 *         Author: Ulli Goschler, ulligoschler@gmail.com
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

static void usageError() {
	fprintf(stderr, "Usage: ./rsa_crypt enc <m> <e> <n>\n       ./rsa_crypt dec <m> <d> <n>\n");
	exit(EXIT_FAILURE);
}

/**
 * Use square and multiply algorithm for calculation of m
 * @param int m the message
 * @param int e the public key exponent
 * @param int n the rsa modulus
 * @returns int the (en|de)crypted message
 */
static uint64_t squareAndMult(uint64_t, uint64_t, uint64_t); 

int main(int argc, char **argv) {
	if(argc < 5)
		usageError();
	
	if(0 == strcmp(argv[1],"enc") || 0 == strcmp(argv[1], "dec")) {
		// there is no difference between en/decoding in our case
		uint64_t m = atoll(argv[2]);
		uint64_t eord = atoll(argv[3]); // e or d
		uint64_t n = atoll(argv[4]);

		// message should be longer than our modulus
	 	if(m > n) {
			fprintf(stderr, "m < n\n");
			exit(EXIT_FAILURE);
		}

		printf("%"PRIu64 "\n",	squareAndMult(m,eord,n));


	} else
		usageError();
	
	return 0;
}

uint64_t squareAndMult(uint64_t x, uint64_t b, uint64_t n) {
	uint64_t z = 1;
  	while (b != 0) {
		while ((b % 2) == 0) {
  	    	b = b / 2;
  	    	x = x*x % n;
  	    }
		b = b - 1;
  	    z = (z * x) % n;
  	}
	return z;
}
