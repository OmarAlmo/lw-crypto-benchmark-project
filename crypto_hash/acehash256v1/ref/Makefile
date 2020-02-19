CC=gcc
NISTGCCFLAGS =-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2
LFLAGS=-lm
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

all: acehash256_1 acehash256bench
#all:myacetest1

acehash256_1:acehash256
#myacetest1:myacetest

acehash256: genkat_hash.c hash.c ace.c
	$(CC) $(NISTGCCFLAGS) -I$(ROOT)../../../crypto_aead/aceae128v1/ref/ -o $@ $^ $(LFLAGS)

acehash256bench: main.c hash.c ace.c
	$(CC) $(NISTGCCFLAGS) -I$(ROOT)../../../crypto_aead/aceae128v1/ref/ -o acehashbenchmark $^ $(LFLAGS)

.PHONY: clean

clean:
	-rm acehash256
	-rm acehashbenchmark
