prefix=/usr/local
BINDIR=${prefix}/bin

all: gatling

CC=gcc
CFLAGS=-pipe -Wall -O -g -I../libowfat/
LDFLAGS=-g -L../libowfat/

gatling: gatling.o
	$(CC) -o $@ gatling.o -lowfat $(LDFLAGS)

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
	rm -f gatling *.o version.h
