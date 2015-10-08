/*
 * =====================================================================================
 *
 *       Filename: rsa_genkey.c
 *
 *    Description: ATTENTION THIS IS FOR DEMONSTRATION PURPOSE ONLY
 *                 This programm calculates the public/private Keys of two given integers (p,q).
 *                 The public Exponent (e) is chosen near 42. It is recommend, for defeating attacks, it should be chosen near 2^16 + 1 
 *
 *                 p and q should be chosen at random
 *                 n is used as modulus for public and private keys
 *                 e is the public key exponent
 *                 d is the private key exponent
 *
 *        Version: 1.0
 *        Created: Mon, 06.06.2011 - 14:26:54
 *  Last modified: Mon, 06.06.2011 - 15:39:22
 *       Revision: none
 *       Compiler: gcc -std=c99 -pedantic -Wall -D_XOPEN_SOURCE=600 -O2 
 *
 *         Author: Ulli Goschler, ulligoschler@gmail.com
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

typedef enum { FALSE = 0, TRUE } bool;
static void usageError() {
	fprintf(stderr, "Usage: ./rsa_genkey <p> <q>\n");
	exit(EXIT_FAILURE);
}

/**
 * Determines whether the given value is prime or not
 * @param int  
 * @return bool
 */
static bool isPrime(uint64_t);
/**
 * Caclulates the greatest common divisor
 * @param int
 * @param int
 * @return int
 */
static uint64_t gcd(uint64_t, uint64_t);
/**
 * Calculates the extended euclidian algorithm and returns the multiplicative inverse of e mod phi(n) 
 * @param int e 
 * @param int phi
 * @return int 
 */
static uint64_t computeD(uint64_t, uint64_t);

int main(int argc, char **argv) {
	if(argc < 3) 
		usageError();

	uint64_t e = 42;
	uint64_t p = atoll(argv[1]);
	uint64_t q = atoll(argv[2]);

	// check if both given numbers are prime
	if(FALSE == isPrime(p) || FALSE == isPrime(q)) {
		fprintf(stderr, "Both, p and q should be prime numbers\n");
		exit(EXIT_FAILURE);
	}
	
	uint64_t n = p * q;
	uint64_t phi = (p - 1) * (q - 1);
	
	// choose e mutually prime with n
	while(1 != gcd(++e, n)); 
	
	uint64_t d = 0;
	d = computeD(e, phi);
	
	// use c99 type of uint64_t for printing
	printf("Private key (e,n) = (%"PRIu64 ",%"PRIu64")\n", e,n);
	printf("Public  key (d,n) = (%"PRIu64 ",%"PRIu64")\n", d,n);

	return 0;
}

bool isPrime(uint64_t n) {
	if(n < 2) 
		return FALSE;
	for(uint64_t i = 3; i < n; i += 2) {
		if((n % i) == 0) 
			return FALSE;
	}
	return TRUE;
}

uint64_t gcd(uint64_t x, uint64_t y) {
	if(y == 0)
		return x;
	return gcd(y, x%y);
}

uint64_t computeD(uint64_t e, uint64_t phi) {
	for(uint64_t d = 1; d <= phi; d++) {
		if((d * e) % phi == 1)
			return d;
	}
	return -1;
}





