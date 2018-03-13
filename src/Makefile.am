lib_LTLIBRARIES = libhsts.la

libhsts_la_SOURCES = hsts.c lookup_string_in_fixed_set.c
libhsts_la_CPPFLAGS = -I$(top_srcdir)/include -DHSTS_DISTFILE=\"$(HSTS_DISTFILE)\"
# include ABI version information
libhsts_la_LDFLAGS = -version-info $(LIBHSTS_SO_VERSION)

EXTRA_DIST = hsts-make-dafsa LICENSE.chromium
