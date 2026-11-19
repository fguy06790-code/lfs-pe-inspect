# pe-inspect: read-only inspector for Windows PE files (.exe, .dll)
# LFS-style install: make install PREFIX=/usr DESTDIR=/path/to/staging

PREFIX  ?= /usr
DESTDIR ?=
BINDIR  := $(DESTDIR)$(PREFIX)/bin
DOCDIR  := $(DESTDIR)$(PREFIX)/share/doc/pe-inspect

.PHONY: all check install uninstall

all:
	@echo "Nothing to build. Run 'make check' then 'make install'."

check:
	node --check pe-inspect.js
	@echo "syntax OK"

install:
	install -d $(BINDIR) $(DOCDIR)
	install -m 755 pe-inspect.js $(BINDIR)/pe-inspect
	install -m 644 README.md LICENSE $(DOCDIR)

uninstall:
	rm -f $(BINDIR)/pe-inspect
	rm -rf $(DOCDIR)
