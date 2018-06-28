HSTS_FILE = $(srcdir)/hsts.json
DEFS = @DEFS@ -DSRCDIR=\"$(srcdir)\" -DHSTS_FILE=\"$(HSTS_FILE)\" -DHSTS_TESTFILE=\"$(HSTS_TESTFILE)\"
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
LDADD = ../src/libhsts.la
AM_LDFLAGS = -no-install

HSTS_TESTS = test-hsts

check_PROGRAMS = $(HSTS_TESTS)

TESTS_ENVIRONMENT = TESTS_VALGRIND="@VALGRIND_ENVIRONMENT@"
TESTS = $(HSTS_TESTS)

# dafsa.hsts and dafsa_ascii.hsts must be created before any test is executed
# check-local target works in parallel to the tests, so the test suite will likely fail
BUILT_SOURCES = hsts.dafsa hsts_ascii.dafsa
hsts.dafsa: $(HSTS_FILE)
	$(top_srcdir)/src/hsts-make-dafsa --output-format=binary "$(HSTS_FILE)" hsts.dafsa
hsts_ascii.dafsa: $(HSTS_FILE)
	$(top_srcdir)/src/hsts-make-dafsa --output-format=binary --encoding=ascii "$(HSTS_FILE)" hsts_ascii.dafsa

# Download if HSTS source file doesn't exist.
# We include it into the distribution, so no net access needed when building from tarball.
$(HSTS_FILE):
	if ! test -f $(HSTS_FILE); then \
	  wget -O$(HSTS_FILE) https://raw.github.com/chromium/chromium/master/net/http/transport_security_state_static.json && \
	  sed -i 's/^ *\/\/.*$$//g' $(HSTS_FILE); \
	fi

EXTRA_DIST = $(HSTS_FILE) hsts.dafsa hsts_ascii.dafsa

#clean-local:
#	rm -f hsts.dafsa hsts_ascii.dafsa
