CC = gcc -std=c99 -pedantic -Wall -D_XOPEN_SOURCE=600 -g 
FLAGS = -lcrypto -O2
OBJ = server client
.PHONY: all clean genkey

all: $(OBJ)

genkey:
	# changing the passphrases requires changing them in shared.h too
	openssl genrsa -passout pass:server -out server.priv.pem -aes256 1024
	openssl rsa -passin pass:server -in server.priv.pem -pubout -out server.pub.pem
	openssl genrsa -passout pass:client -out client.priv.pem -aes256 1024
	openssl rsa -passin pass:client -in client.priv.pem -pubout -out client.pub.pem

server: server.c
	$(CC) $(FLAGS) -o $@ $<
client: client.c
	$(CC) $(FLAGS) -o $@ $<	

clean: 
	rm -f $(OBJ)
	rm *pem
