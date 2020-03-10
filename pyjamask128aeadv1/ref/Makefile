CC=gcc
NISTGCCFLAGS=-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2
LFLAGS=-lm
all: pyjamask

pyjamask: pyjamask

pyjamask: main.c encrypt.c pyjamask.c
	$(CC) $(NISTGCCFLAGS) -o $@ $^ $(LFLAGS)


# acetestvec: genkat_aead.c encrypt.c ace.c
# 	$(CC) $(NISTGCCFLAGS) -o $@ $^ $(LFLAGS)


.PHONY: clean

clean:
	-rm pyjamask
	-rm *.*.*
	-rm *.csv
