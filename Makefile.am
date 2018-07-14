SUBDIRS = include src tools

if WITH_DOCS
SUBDIRS += docs
endif

SUBDIRS += tests
#SUBDIRS += fuzz

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

# Enable GTK-Doc during make distcheck
#DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc --enable-man

## Install the generated pkg-config file (.pc) into the expected location for
## architecture-dependent package configuration information. Occasionally,
## pkg-config files are also used for architecture-independent data packages,
## in which case the correct install location would be $(datadir)/pkgconfig.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libhsts.pc

EXTRA_DIST = build-aux/config.rpath LICENSE

clean-local:
	rm -rf */*.gc?? */*/*.gc?? libhsts.info lcov

LCOV_INFO=libhsts.info
check-coverage: clean
	if test -z "$(XLIB)"; then \
		CFLAGS=$$CFLAGS" --coverage -O0" LDFLAGS=$$LDFLAGS" --coverage" ./configure --disable-runtime --disable-builtin; \
	else \
		CFLAGS=$$CFLAGS" --coverage -O0" LDFLAGS=$$LDFLAGS" --coverage" ./configure --enable-runtime=$(XLIB) --enable-builtin=$(XLIB); \
	fi
	$(MAKE)
	lcov --capture --initial --directory src --output-file $(LCOV_INFO)
	$(MAKE) check
	lcov --capture --directory src --output-file $(LCOV_INFO)
	genhtml --prefix . $(LCOV_INFO) --legend --title "libhsts" --output-directory=lcov
	@echo
	@echo "You can now view the coverage report with 'xdg-open lcov/index.html'"

fuzz-coverage: clean
	$(MAKE) -C src CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
	$(MAKE) -C fuzz fuzz-coverage CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
	lcov --capture --initial --directory src --directory fuzz --output-file $(LCOV_INFO)
	lcov --capture --directory src --directory fuzz --output-file $(LCOV_INFO)
	genhtml --prefix . --ignore-errors source $(LCOV_INFO) --legend --title "libhsts-fuzz" --output-directory=lcov
	@echo
	@echo "You can now view the coverage report with 'xdg-open lcov/index.html'"

