CC=gcc
CFLAG=-std=c99 -Wall -pedantic -I..
LIBS=-lcrypto 

all: generator

hmac.o: hmac.h hmac.c
	$(CC) $(CFLAGS) -c hmac.c

generator.o: generator.c generator.h hmac.h
	$(CC) $(CFLAGS) -c generator.c

generator: generator.o hmac.o
	$(CC) $(CFLAGS) -o generator generator.o hmac.o ${LIBS}

clean:
	rm -f *.o *~ core generator

.PHONY : clean all

