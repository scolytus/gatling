#DEBUG=1
ZLIB=1
prefix=/opt/diet
BINDIR=${prefix}/bin

all: gatling

CC=gcc
CFLAGS=-pipe -Wall
LDFLAGS=

path = $(subst :, ,$(PATH))
diet_path = $(foreach dir,$(path),$(wildcard $(dir)/diet))
ifneq ($(strip $(diet_path)),)
ifeq ($(wildcard /opt/diet/bin/diet),/opt/diet/bin/diet)
DIET=/opt/diet/bin/diet
else
DIET=
endif
else
DIET:=$(diet_path)
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

ifeq ($(ZLIB),1)
CFLAGS+=-DUSE_ZLIB
LDFLAGS+=-lz
endif

gatling: gatling.o
	$(DIET) $(CC) -o $@ $^ -lowfat $(LDFLAGS)

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
