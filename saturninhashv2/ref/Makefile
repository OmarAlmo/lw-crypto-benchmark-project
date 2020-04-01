CC=gcc
NISTGCCFLAGS =-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2
LFLAGS=-lm
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
OBJS=hash.o saturnin.o

all: saturninbench

saturninbench:  main.c hash.c saturnin.c
	$(CC)  main.c -o ./saturninbench

.PHONY: clean

clean :
	-rm $(OBJS)
	-rm *.*.*
	-rm *.csv

