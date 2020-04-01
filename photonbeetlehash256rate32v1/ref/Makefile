CC=gcc
CFLAGES=-std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2
OBJS=genkat_hash.o hash.o photon.o

all: ref photonhash256bench

ref: $(OBJS)
	$(CC) -o ref $(OBJS) $(CFLAGES)

genkat_hash.o: genkat_hash.c
	$(CC) -c genkat_hash.c $(CFLAGES) -I./

hash.o: hash.c
	$(CC) -o hash.o -c hash.c $(CFLAGES) -I../../../

photon.o: photon.c
	$(CC) -c photon.c $(CFLAGES)

photonhash256bench: main.c hash.c photon.c
	$(CC) $(NISTGCCFLAGS) -I$(ROOT)../../photonbeetleaead128rate32v1/ref/  -o photonhashbenchmark $^ $(CFLAGES)

.PHONY : clean

clean :
	rm $(OBJS)
	