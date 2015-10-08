/*
 * =====================================================================================
 *
 *       Filename: crackpw.c
 *
 *    Description: A /etc/shadow password cracker
 *		 Features:  multithreading (macrodefined Threads)
 *					time measurement (roughly in seconds)
 *					wordlist support (wordlist.txt in current folder)
 *					supports md5, sha256, sha512
 *					random passwordsize (macrodefined letters)
 *					different charsets (see the comments)
 *
 *        Version: 1.0
 *        Created: Thu, 18.11.2010 - 00:10:15
 *  Last modified: Sat, 27.11.2010 - 01:38:19
 *       Revision: none
 *       Compiler: gcc -std=c99 -pedantic -Wall -Werror -D_XOPEN_SOURCE=600 -g -lcrypt -pthread
 *
 *         Author: Ulli Goschler, siulgosc@stud.informatik.uni-erlangen.de
 *
 * =====================================================================================
 */

#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>

#include "crypt.h"

#define THREADS 8
#define MINPWLENGTH 4
#define MAXPWLENGTH 4

void crackLoop(int, char*, int, int);
void* threadedIterative4CharCrack(void*);
void* threadedRecursiveCrack(void*);

static void usageError() {
	fprintf(stderr, "Usage: ./crackpw <shadow>\n");
	exit(EXIT_FAILURE);
}

//static char charSet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
//static char charSet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static char charSet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
//static char charSet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}\\|;':\",./<>?`";

static char salt[9];
static char hashToBrute[100];
static sem_t sem;
int charSetCount = 0;

struct threadArgs {
	int threadID;
	int cryptMethod;
};

int main(int argc, char **argv) {
	if(argc < 2)
		usageError();
	/* flag */
	char userNameFound = 0;
	
	FILE *f = NULL;
	char buf[512]; 
	/* username may only be up to 32 characters long */
	char user[33];
	/* time measurement */
	time_t start;
	time_t end;


	if(-1 == sem_init(&sem,0,1)) {
		perror("sem_init");
		exit(EXIT_FAILURE);
	}

	if(NULL == (f = fopen(argv[1], "r"))) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}
	
	int i = 0;
	while(charSet[i++] != '\0') charSetCount++;

	while(fgets(buf, 512, f)) {
		int i = 0;
		while(buf[i] != '\n') {
			if(buf[i] == ':' && !userNameFound) {
				memcpy(user, buf, i);
				user[i] = '\0';
				userNameFound = 1;
			}
			if(buf[i] == '$' && buf[i-1] == ':') {
				 int crypto = atoi(&buf[++i]);
				 //char hash[23]; // md5 hash is 22character 
				 char hash[87]; // sha-512 hash consists of 86 chars
				 char *p = salt;
				 
				 char *h = hashToBrute;
				 *h++ = '$';
				 *h++ = buf[i++]; /* $1 */
				 *h++ = buf[i++]; /* $1$ */

				 while(buf[i] != '$') { /* get the salt, from shadow */
					*h++ = buf[i];		/* fill complete bruteforce string */
					*p++ = buf[i++];	/* fill salt */
				 }
				 *p = '\0';
				 *h++ = '$';

				 p = hash; i++;
				 while(buf[i] != ':') { /* get the hash, from shadow */
					 *h++ = buf[i];
					 *p++ = buf[i++];
				 }
				 *p = '\0';
				 *h = '\0';

				if(1 == crypto) {
					printf("Username: %s; Alogrithm: MD5\n", user);
				} else if (5 == crypto) {
					printf("Username: %s; Alogrithm: SHA-256\n", user);
				} else if (6 == crypto) {
					printf("Username: %s; Alogrithm: SHA-512\n", user);
				} else {
					printf("Invalid Algorithm for User: %s; skipping...\n", user);
					break;
				}
				
				pthread_t threads[THREADS];
				struct threadArgs args[THREADS];

				start = time(NULL);

				for(int i = 0; i < THREADS; i++) {
					args[i].threadID = i;
					args[i].cryptMethod = crypto;
					/* 
					 * choose between iterative or recursive version
					 *	iterative: fixed 4 chars password size
					 *	recursive: macrodefined password length
					 *
					 */
					if(0 != pthread_create(&threads[i], NULL, threadedRecursiveCrack, (void*) &args[i])) {
					//if(0 != pthread_create(&threads[i], NULL, threadedIterative4CharCrack, &args[i])) {
						perror("phtread_create");
						exit(EXIT_FAILURE);
					}
				} 
				
				// open wordlist
				FILE *w = NULL;
				char wbuf[1024];
				if(NULL == (w = fopen("wordlist.txt", "r"))) {
					printf("No wordlist found, skipping wordlist cracking...\n");
				} else {
					int i =0;
					int lock = 1;
					printf("Wordlist cracking enabled\n");
					while(fgets(wbuf, 1024, w)) {
						if(wbuf[0] == '#')
							continue;
					
						// check every 512 lines if another (bruteforcing) thread, has found a solution
						if((i % 512) == 0) {
							sem_getvalue(&sem, &lock);
							if(lock == 0) {
								break;
							}
						}

						// remove trailing \n, which would modify the hash
						wbuf[strlen(wbuf)-1] = '\0';
						
						if(strcmp(genHash(wbuf, salt, crypto)+8, hashToBrute+8) == 0) {
							printf("\tPassword found in wordlist: %s\n", wbuf);
							sem_wait(&sem);
							break;
						}
						i++; 
					}
					fclose(w);
				}
				
				for(int i = 0; i < THREADS; i++) {
					pthread_join(threads[i], NULL);
				}
				sem_post(&sem);

				end = time(NULL);
				printf(" Took %.2f minutes\n", ((double) (end-start))/60);

			} else if(buf[i-1] == ':' &&  buf[i+1] == ':') {
				printf("Skipping %s\n", user);
				break;
			}
			i++;
		}
		userNameFound = 0;

	}
	fclose(f);
	return 0;

}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  threadedRecursiveCrack
 *  Description:  Each Thread (identified by threadID) iterates over a constant initial letter
 *					Thread: 0 -> Axxx
 *				    Thread: 1 -> Bxxx
 *					Thread: 0 -> Cxxx
 *					...
 *					The threads start looping over (macrodefined) MINPWLENGTH letters up to MAXPWLETTERS
 *					a next letter is added, after looping through all combinations of the current letter count.
 *					as in the iterative version, a mutex is used for thread syncronisation
 *
 * Return Value:  ???
 * =====================================================================================
 */
void* threadedRecursiveCrack(void* arg) {
	struct threadArgs *param = arg;
	int threadID = param->threadID;
	int method = param->cryptMethod; 
	char currentString[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	int lock = 1;


	for(int loop = MINPWLENGTH; loop < MAXPWLENGTH+1; loop++) {
		int i = 0;
		while(i < charSetCount) { 
			if((i % THREADS) != threadID) {
				i++;
				continue;
			} 
			currentString[0] = charSet[i];
			crackLoop(1, currentString, loop, method);	
			
			sem_getvalue(&sem, &lock);
			if(lock == 0) {
				pthread_exit(NULL);
			}
			
			i++; 
		}
		/* all chars done; continue with +1 pwlength */
	}
	return 0;
}

void crackLoop(int cycle, char *string, int loopEnd, int method) {
	if(cycle == loopEnd) {
		if(strcmp(genHash(string, salt, method)+8, hashToBrute+8) == 0) {
			printf("\tPassword found: %s\n", string);
			sem_wait(&sem);
		}
		return;	
	} else {
		if(loopEnd - cycle == 2) {
			int lock = 1;
			sem_getvalue(&sem, &lock);
			if(lock == 0) {
				pthread_exit(NULL);
			}
		}
		for(int i = 0; i < charSetCount; i++) {
			string[cycle] = charSet[i];
			crackLoop(cycle + 1, string, loopEnd, method);
			
		}
	}


}
  


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  threadedIterative4CharCrack
 *  Description:  Each Thread (identified by threadID) iterates over a constant initial letter
 *					Thread: 0 -> Axxx
 *				    Thread: 1 -> Bxxx
 *					Thread: 0 -> Cxxx
 *					...
 *					and loops the remaining 3 letters from charSet[0] to charSet[length-1]
 *					if the generatedhash matches the shadow hash, we lock the mutex
 *
 *					each thread checks the mutex state, after changing the initial letter  
 *					if the mutex is locked, a password is found, and the threads exits
 * Return Value:  ???
 * =====================================================================================
 */
void* threadedIterative4CharCrack(void* arg) {
	struct threadArgs *p = arg;
	int threadID = p->threadID;
	int method = p->cryptMethod;
	int i = 0;
	int semLock = 1;

	char currentString[5];
	currentString[4] = '\0';
	while(i < charSetCount) { 
		sem_getvalue(&sem, &semLock);
		if(semLock == 0) {
			pthread_exit(NULL);
		}
		if((i % THREADS) != threadID) {
			i++;
			continue;
		}
		currentString[0] = charSet[i];
		for(int x = 0; x < charSetCount; x++) {
			currentString[1] = charSet[x];
			for(int y = 0; y < charSetCount; y++) {
				currentString[2] = charSet[y];
				for(int z = 0; z < charSetCount; z++) {
					currentString[3] = charSet[z];
					if(strcmp(genHash(currentString, salt, method)+8, hashToBrute+8) == 0) {
						printf("\tPassword found: %s\n", currentString);
						sem_wait(&sem);
						return 0;
					}

				}
			}
		}
		i++;
	}
	return 0;
}
/*  */
