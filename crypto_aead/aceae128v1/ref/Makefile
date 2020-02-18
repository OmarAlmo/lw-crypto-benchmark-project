CC=gcc
NISTGCCFLAGS=-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2
LFLAGS=-lm
all: ace128_1

ace128_1: ace128

ace128: main.c encrypt.c ace.c
	$(CC) $(NISTGCCFLAGS) -o $@ $^ $(LFLAGS)

.PHONY: clean

clean:
	-rm ace128
	-rm *.*.*
	-rm *.csv
