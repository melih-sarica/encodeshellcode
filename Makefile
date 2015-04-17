CC=gcc
CFLAGS=-Wall -Wimplicit -pedantic -O2

all:
	$(CC) $(CFLAGS) encodeshellcode.c -o encodeshellcode

clean:
	rm -f encodeshellcode

