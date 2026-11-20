# pe-loader: run 64-bit Windows console programs on Linux.
# LFS-style: make && make check && make install PREFIX=/usr DESTDIR=...

CC      ?= gcc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -Wno-unused-parameter -fno-strict-aliasing
PREFIX  ?= /usr
DESTDIR ?=
MINGW   ?= x86_64-w64-mingw32-gcc

SRC := src/loader.c src/winapi.c
HDR := src/pe.h src/winapi.h

.PHONY: all tests check install install-binfmt uninstall clean

all: pe-loader

pe-loader: $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(SRC)

# The test programs are Windows .exe files, so they need a mingw cross compiler.
tests: tests/hello.exe tests/api.exe

tests/%.exe: tests/%.c
	$(MINGW) -O1 -o $@ $<

check: pe-loader tests
	sh tests/run.sh

install: pe-loader
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 pe-loader $(DESTDIR)$(PREFIX)/bin/pe-loader

# SysVinit boot script that registers .exe files with the kernel (binfmt_misc),
# so ./program.exe runs through pe-loader directly.
install-binfmt:
	install -d $(DESTDIR)/etc/rc.d/init.d
	install -m 754 binfmt/pe-binfmt $(DESTDIR)/etc/rc.d/init.d/pe-binfmt
	for rl in 3 5; do \
	  install -d $(DESTDIR)/etc/rc.d/rc$$rl.d; \
	  ln -sf ../init.d/pe-binfmt $(DESTDIR)/etc/rc.d/rc$$rl.d/S95pe-binfmt; \
	done

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/pe-loader $(DESTDIR)/etc/rc.d/init.d/pe-binfmt
	rm -f $(DESTDIR)/etc/rc.d/rc3.d/S95pe-binfmt $(DESTDIR)/etc/rc.d/rc5.d/S95pe-binfmt

clean:
	rm -f pe-loader tests/*.exe
