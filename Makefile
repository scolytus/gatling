prefix=/usr/local
BINDIR=${prefix}/bin
MANDIR=${prefix}/man
man1dir=$(MANDIR)/man1

TARGET=gatling httpbench dl bindbench mmapbench forkbench pthreadbench \
mktestdata manymapbench ioerr bench tlsgatling forksbench cgi

all: $(TARGET)

CC=gcc
CFLAGS=-pipe -Wall -O -I../libowfat/
LDFLAGS=-s -L../libowfat/ -lowfat

gatling: gatling.o libsocket libiconv libcrypt
	$(CC) -o $@ gatling.o $(LDFLAGS) `cat libsocket libiconv libcrypt`

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

cgi: cgi.c
	$(CC) -o $@ cgi.c $(LDFLAGS)

gatling.o: version.h

version.h: CHANGES
	(head -n 1 CHANGES | sed 's/\([^:]*\):/#define VERSION "\1"/') > version.h

%.o: %.c
	$(CC) -c $< -I. $(CFLAGS)

tlsgatling: gatling.c ssl.o libsocket libiconv libcrypt
	-$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS) -lssl -lcrypto $(LDLIBS) `cat libsocket libiconv libcrypt`

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

libcrypt: trycrypt.c
	if $(DIET) $(CC) $(CFLAGS) -o trycrypt trycrypt.c >/dev/null 2>&1; then echo ""; else \
	if $(DIET) $(CC) $(CFLAGS) -o trycrypt trycrypt.c -lcrypt >/dev/null 2>&1; then echo "-lcrypt"; \
	fi; fi > libcrypt
	rm -f trycrypt


install: gatling
	install -d $(BINDIR) $(man1dir)
	install $< $(BINDIR)
	test -f tlsgatling && install tlsgatling $(BINDIR)
	install -m 644 gatling.1 $(man1dir)

uninstall:
	rm -f $(BINDIR)/gatling $(BINDIR)/tlsgatling $(man1dir)/gatling.1

clean:
	rm -f $(TARGET) *.o version.h core *.core libsocket libsocketkludge.a dummy.c libcrypt libiconv

cert: server.pem

rand.dat:
	-dd if=/dev/random of=rand.dat bs=1024 count=1

cakey.key: rand.dat
	openssl genrsa -out cakey.key -rand rand.dat 2048

cakey.csr: cakey.key
	openssl req -new -key cakey.key -out cakey.csr

cakey.pem: cakey.key cakey.csr
	openssl x509 -req -days 1780 -set_serial 1 -in cakey.csr \
	  -signkey cakey.key -out $@

server.pem: cakey.key cakey.pem
	cat cakey.key cakey.pem > server.pem
