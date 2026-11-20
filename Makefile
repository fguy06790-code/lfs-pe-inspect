# lfs-pe-inspect: Windows program support for Linux From Scratch.
#   pe-loader   runs 64-bit Windows console programs (C, no dependencies)
#   pe-inspect  shows what's inside .exe and .dll files (needs Node.js)
#
# LFS-style: make && make check && make install PREFIX=/usr DESTDIR=...

PREFIX  ?= /usr
DESTDIR ?=
BINDIR  := $(DESTDIR)$(PREFIX)/bin
DOCDIR  := $(DESTDIR)$(PREFIX)/share/doc/lfs-pe-inspect

.PHONY: all check install install-binfmt uninstall clean

all:
	$(MAKE) -C loader

check:
	@if command -v node >/dev/null 2>&1; then node --check pe-inspect.js && echo "pe-inspect: syntax OK"; \
	 else echo "pe-inspect: node not installed, skipping its check"; fi
	$(MAKE) -C loader check

install:
	$(MAKE) -C loader install PREFIX=$(PREFIX) DESTDIR=$(DESTDIR)
	install -d $(BINDIR) $(DOCDIR)
	install -m 755 pe-inspect.js $(BINDIR)/pe-inspect
	install -m 644 README.md LICENSE $(DOCDIR)
	install -m 644 loader/README.md $(DOCDIR)/pe-loader.md

install-binfmt:
	$(MAKE) -C loader install-binfmt DESTDIR=$(DESTDIR)

uninstall:
	$(MAKE) -C loader uninstall PREFIX=$(PREFIX) DESTDIR=$(DESTDIR)
	rm -f $(BINDIR)/pe-inspect
	rm -rf $(DOCDIR)

clean:
	$(MAKE) -C loader clean
