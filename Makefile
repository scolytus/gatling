#DEBUG=1
prefix=/opt/diet
BINDIR=${prefix}/bin

all: gatling

# comment out the following line if you don't want to build with the
# diet libc (http://www.fefe.de/dietlibc/).
DIET=/opt/diet/bin/diet
CC=gcc
CFLAGS=-pipe -Wall
LDFLAGS=

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

gatling: gatling.o
	$(DIET) $(CC) $(LDFLAGS) -o $@ $^ -lowfat

gatling.o: version.h

version.h: CHANGES
	(head -1 CHANGES | sed 's/\([^:]*\):/#define VERSION "\1"/') > version.h

%.o: %.c
	$(DIET) $(CC) -c $< -o $@ -I. $(CFLAGS)

install: gatling
	install -D $(BINDIR)
	install $@ $(BINDIR)

uninstall:
	rm -f $(BINDIR)/gatling

clean:
	rm -f gatling *.o version.h
