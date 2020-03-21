CC=gcc
NISTGCCFLAGS=-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2
LFLAGS=-lm
all: photon

photon: photon

photon: main.c encrypt.c photon.c
	$(CC) $(NISTGCCFLAGS) -o $@ $^ $(LFLAGS)

.PHONY: clean

clean:
	-rm photon
	-rm *.*.*
	-rm *.csv
