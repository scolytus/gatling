#DEBUG=1
ZLIB=1
prefix=/opt/diet
BINDIR=${prefix}/bin
MANDIR=${prefix}/man
man1dir=$(MANDIR)/man1

TARGETS=gatling httpbench bindbench mmapbench forkbench dl \
mktestdata manymapbench ioerr forksbench pthreadbench

all: $(TARGETS)

CC=gcc
CFLAGS=-pipe -Wall
LDFLAGS=

path = $(subst :, ,$(PATH))
diet_path = $(foreach dir,$(path),$(wildcard $(dir)/diet))
ifeq ($(strip $(diet_path)),)
ifneq ($(wildcard /opt/diet/bin/diet),)
DIET=/opt/diet/bin/diet
else
DIET=
endif
else
DIET:=$(strip $(diet_path))
endif

# to build without diet libc support, use $ make DIET=
# see http://www.fefe.de/dietlibc/ for details about the diet libc

ifneq ($(DEBUG),)
CFLAGS+=-g
LDFLAGS+=-g
else
CFLAGS+=-O2 -fomit-frame-pointer
LDFLAGS+=-s
ifneq ($(DIET),)
DIET+=-Os
endif
endif

LDLIBS=-lowfat

ifeq ($(ZLIB),1)
CFLAGS+=-DUSE_ZLIB
LDLIBS+=-lz
endif

libowfat_path = $(strip $(foreach dir,../libowfat*,$(wildcard $(dir)/textcode.h)))
ifneq ($(libowfat_path),)
CFLAGS+=$(foreach fnord,$(libowfat_path),-I$(dir $(fnord)))
LDFLAGS+=$(foreach fnord,$(libowfat_path),-L$(dir $(fnord)))
endif

CC:=$(DIET) $(CC)

pthreadbench: pthreadbench.o
	$(CC) $< -o $@ -I. $(CFLAGS) $(LDFLAGS) $(LDLIBS) -lpthread

forksbench: forkbench.o
	$(CC) -static -o $@ forkbench.o $(LDFLAGS) $(LDLIBS)

gatling.o: version.h

version.h: CHANGES
	(head -n 1 CHANGES | sed 's/\([^:]*\):/#define VERSION "\1"/') > version.h

%.o: %.c
	$(CC) -c $< -o $@ -I. $(CFLAGS)

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

dummy.c:
	touch $@

libsocketkludge.a: libsocket libiconv dummy.o
	ar q $@ dummy.o
	-ranlib $@

LDLIBS+=`cat libsocket libiconv`

$(TARGETS): libsocketkludge.a

install: gatling
	install -d $(BINDIR) $(man1dir)
	install $< $(BINDIR)
	install -m 644 gatling.1 $(man1dir)

uninstall:
	rm -f $(BINDIR)/gatling $(man1dir)/gatling.1

clean:
	rm -f $(TARGETS) *.o version.h core *.core libsocket libsocketkludge.a libiconv
