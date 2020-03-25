CC=gcc
NISTGCCFLAGS=-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2
LFLAGS=-lm
all: aes128_1

aes128_1: aes128

aes128: main.c encrypt.c aes.c gmult.c hmac-sha256.c sha256.c
	$(CC) $(NISTGCCFLAGS) -o $@ $^ $(LFLAGS)


.PHONY: clean

clean:
	-rm aes128
	-rm *.*.*
	-rm *.csv
