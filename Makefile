prefix=/usr/local
BINDIR=${prefix}/bin

TARGET=gatling httpbench dl bindbench mmapbench forkbench pthreadbench \
mktestdata manymapbench ioerr forksbench

all: $(TARGET)

CC=gcc
CFLAGS=-pipe -Wall -O -g -I../libowfat/
LDFLAGS=-g -L../libowfat/ -lowfat

gatling: gatling.o libsocket libiconv
	$(CC) -o $@ gatling.o $(LDFLAGS) `cat libsocket libiconv`

httpbench: httpbench.o libsocket
	$(CC) -o $@ httpbench.o $(LDFLAGS) `cat libsocket`

dl: dl.o libsocket
	$(CC) -o $@ dl.o $(LDFLAGS) `cat libsocket`

bindbench: bindbench.o libsocket
	$(CC) -o $@ bindbench.o $(LDFLAGS) `cat libsocket`

mmapbench: mmapbench.o
	$(CC) -o $@ mmapbench.o $(LDFLAGS)

forkbench: forkbench.o
	$(CC) -o $@ forkbench.o $(LDFLAGS)

forksbench: forkbench.o
	$(CC) -static -o $@ forkbench.o $(LDFLAGS)

pthreadbench: pthreadbench.o
	$(CC) -o $@ pthreadbench.o $(LDFLAGS) -lpthread

mktestdata: mktestdata.o
	$(CC) -o $@ mktestdata.o $(LDFLAGS)

manymapbench: manymapbench.o
	$(CC) -o $@ manymapbench.o $(LDFLAGS)

ioerr: ioerr.o libsocket
	$(CC) -o $@ ioerr.o $(LDFLAGS) `cat libsocket`

gatling.o: version.h

version.h: CHANGES
	(head -n 1 CHANGES | sed 's/\([^:]*\):/#define VERSION "\1"/') > version.h

%.o: %.c
	$(CC) -c $< -I. $(CFLAGS)

libsocket: trysocket.c
	if $(DIET) $(CC) $(CFLAGS) -o trysocket trysocket.c >/dev/null 2>&1; then echo ""; else \
	if $(DIET) $(CC) $(CFLAGS) -o trysocket trysocket.c -lsocket >/dev/null 2>&1; then echo "-lsocket"; else \
	if $(DIET) $(CC) $(CFLAGS) -o trysocket trysocket.c -lsocket -lnsl >/dev/null 2>&1; then echo "-lsocket -lnsl"; \
	fi; fi; fi > libsocket
	rm -f trysocket

libiconv: tryiconv.c
	if $(DIET) $(CC) $(CFLAGS) -o tryiconv tryiconv.c >/dev/null 2>&1; then echo ""; else \
	if $(DIET) $(CC) $(CFLAGS) -o tryiconv tryiconv.c -liconv >/dev/null 2>&1; then echo "-liconv"; \
	fi; fi > libiconv
	rm -f tryiconv

install: gatling
	install -D $(BINDIR)
	install $@ $(BINDIR)

uninstall:
	rm -f $(BINDIR)/gatling

clean:
	rm -f $(TARGET) *.o version.h core *.core libsocket libsocketkludge.a
