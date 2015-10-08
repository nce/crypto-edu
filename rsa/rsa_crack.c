/*
 * =====================================================================================
 *
 *       Filename: rsa_crack.c
 *
 *    Description: ATTENTION THIS IS FOR DEMONSTRATION PURPOSE ONLY
 *	               This program calculates 'd' (the private key exponent) 
 *	               from given e (public key exponent) and n (the modulus) 
 *
 *        Version: 1.0
 *        Created: Mon, 06.06.2011 - 15:21:26
 *  Last modified: Mon, 06.06.2011 - 16:35:49
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

/**
 * Calculates the extended euclidian algorithm and returns the multiplicative inverse of e mod phi(n) 
 * @param int e 
 * @param int phi
 * @return int 
 */
static uint64_t computeD(uint64_t, uint64_t);

/**
 * Factorizes a given prime number
 * @param int num the prime to factorize
 * @param int* factors pointer to the found factors
 * @param int* exponents pointer to the found exponent
 * @return int number of found factors (2)
 */
static uint64_t factorize(uint64_t, uint64_t*, uint64_t*);

int main(int argc, char **argv) {
	if(argc != 3) {
		fprintf(stderr, "Usage: ./rsa_crack <e> <n>\n");
		exit(EXIT_FAILURE);
	}
	uint64_t e = atoll(argv[1]);
	uint64_t n = atoll(argv[2]);
 	uint64_t fak[2], exp[2];
	
	if(factorize(n,fak,exp) != 2) {
		fprintf(stderr,"Error while factorizing %"PRIu64 "; something went wrong",n);
		exit(EXIT_FAILURE);
	}

	uint64_t phi = (fak[0]-1) * (fak[1]-1);

	printf("Private key (d,n) = (%"PRIu64 ",%"PRIu64")\n", computeD(e,phi),n);

	return 0;
}


uint64_t computeD(uint64_t e, uint64_t phi) {
	for(uint64_t d = 1; d <= phi; d++) {
		if((d * e) % phi == 1)
			return d;
	}
	return -1;
}

uint64_t factorize(uint64_t num, uint64_t* factors, uint64_t* exponents) {
    uint64_t nfactors = 0;
    for (uint64_t i = 2; i*i<= num; i++) {
        if (num % i == 0) {
            factors[nfactors] = i;
            exponents[nfactors] = 0;
            while (num % i == 0) {
                num /= i;
                exponents[nfactors]++;
            }
            nfactors++;
        }
    }
    if (num > 1) {
        factors[nfactors] = num;
        exponents[nfactors++] = 1;
    }
    return nfactors;
}
