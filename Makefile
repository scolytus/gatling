prefix=/usr/local
BINDIR=${prefix}/bin

all: gatling httpbench dl bindbench mmapbench forkbench pthreadbench

CC=gcc
CFLAGS=-pipe -Wall -O -g -I../libowfat/
LDFLAGS=-g -L../libowfat/ -lowfat

gatling: gatling.o
	$(CC) -o $@ gatling.o $(LDFLAGS)

httpbench: httpbench.o
	$(CC) -o $@ httpbench.o $(LDFLAGS)

dl: dl.o
	$(CC) -o $@ dl.o $(LDFLAGS)

bindbench: bindbench.o
	$(CC) -o $@ bindbench.o $(LDFLAGS)

mmapbench: mmapbench.o
	$(CC) -o $@ mmapbench.o $(LDFLAGS)

forkbench: forkbench.o
	$(CC) -o $@ forkbench.o $(LDFLAGS)

pthreadbench: pthreadbench.o
	$(CC) -o $@ pthreadbench.o $(LDFLAGS) -lpthread

gatling.o: version.h

version.h: CHANGES
	(head -1 CHANGES | sed 's/\([^:]*\):/#define VERSION "\1"/') > version.h

%.o: %.c
	$(CC) -c $< -I. $(CFLAGS)

install: gatling
	install -D $(BINDIR)
	install $@ $(BINDIR)

uninstall:
	rm -f $(BINDIR)/gatling

clean:
	rm -f gatling httpbench mmapbench bindbench forkbench dl *.o version.h
