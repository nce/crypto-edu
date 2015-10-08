CC = gcc -std=c99 -pedantic -Wall -D_XOPEN_SOURCE=600 -O2
OBJ = rsa_crypt rsa_genkey rsa_crack
.PHONY: all clean

all: $(OBJ)

rsa_genkey: rsa_genkey.c
	$(CC) -o $@ $<
rsa_crypt: rsa_crypt.c
	$(CC) -o $@ $<
rsa_crack: rsa_crack.c
	$(CC) -o $@ $<

clean:
	rm -f $(OBJ)

