prefix=/opt/diet
BINDIR=${prefix}/bin

all: gatling

# comment out the following line if you don't want to build with the
# diet libc (http://www.fefe.de/dietlibc/).
DIET=/opt/diet/bin/diet #-Os
CC=gcc
CFLAGS=-pipe -Wall -g #-O2 -fomit-frame-pointer

gatling: gatling.o
	$(DIET) $(CC) -o $@ $^ -lowfat

%.o: %.c
	$(DIET) $(CC) -c $< -o $@ -I. $(CFLAGS)

install: gatling
	install -D $(BINDIR)
	install $@ $(BINDIR)

uninstall:
	rm -f $(BINDIR)/gatling

clean:
	rm -f gatling *.o
