[![Build status](https://gitlab.com/rockdaboot/libhsts/badges/master/build.svg)](https://gitlab.com/rockdaboot/libhsts/pipelines)
[![Coverage status](https://gitlab.com/rockdaboot/libhsts/badges/master/coverage.svg)](https://rockdaboot.gitlab.io/libhsts/coverage)

libhsts - C library to access the HSTS preload list
===================================================

The HSTS preload list is a list of domains that support HTTPS.
The list is compiled by Google and is utilised by Chrome, Firefox and others.

With this information, a HTTP client may contact a website without trying
a plain-text HTTP connection first. It prevents interception with redirects
that take place over HTTP. None of the sent data will ever be unencrypted.

A good explananation of HSTS and HSTS preloading has been written by
[Scott Helme - HSTS Preloading](https://scotthelme.co.uk/hsts-preloading/).

The DAFSA code has been taken from [Chromium Project](https://code.google.com/p/chromium/).


API Documentation
-----------------

You find the current API documentation [here](https://rockdaboot.gitlab.io/libhsts/reference/).


Quick API example
-----------------

	#include <stdio.h>
	#include <libhsts.h>

	int main(void)
	{
		const char *domain = "example.com";
		hsts_t *hsts;

		if (hsts_load_file(SRCDIR "/hsts.dafsa", &hsts) == HSTS_SUCCESS) {
			hsts_entry_t *e;

			if (hsts_search(hsts, domain, 0, &e) == HSTS_SUCCESS)
				printf("%s is in the HSTS preload list\n", domain);
			else
				printf("Failed to find %s in the HSTS preload list\n", domain);
		}
		hsts_free(hsts);

		return 0;
	}

Command Line Tool
-----------------

Libhsts comes with a tool 'hsts' that gives you access to most of the
library API via command line.

	$ hsts --help

prints the usage.

Convert HSTS into DAFSA
-----------------------

The [DAFSA](https://en.wikipedia.org/wiki/Deterministic_acyclic_finite_state_automaton) format is a compressed
representation of strings. Here we use it to reduce the whole HSTS to about 350k in size.

The current HSTS Preload list can be retrieved, prepared and generated with:

	$ wget 'https://raw.github.com/chromium/chromium/master/net/http/transport_security_state_static.json'

	$ sed -i 's/^ *\/\/.*$//g' transport_security_state_static.json

	$ src/hsts-make-dafsa --output-format=binary transport_security_state_static.json hsts.dafsa

Test the result (example)

	$ tools/hsts --load-hsts-file hsts.dafsa example.com

License
-------

Libhsts is made available under the terms of the MIT license.<br>
See the LICENSE file that accompanies this distribution for the full text of the license.

src/hsts-make-dafsa and src/lookup_string_in_fixed_set.c are licensed under the term written in
src/LICENSE.chromium.

Building from git
-----------------

You should have python2.7+ installed.

Download project and prepare sources with

		git clone https://gitlab.com/rockdaboot/libhsts
		autoreconf -fi
		./configure
		make
		make check

If you see errors about AX_CHECK_COMPILE_FLAG during `./configure`,
make sure you have the autoconf-archive installed.

E.g. on Debian via `apt-get install autoconf-archive`.

Mailing List
------------

[Mailing List Archive](http://news.gmane.org/gmane.network.dns.libhsts.bugs)

[Mailing List](https://groups.google.com/forum/#!forum/libhsts-bugs)

To join the mailing list send an email to

libhsts-bugs+subscribe@googlegroups.com

and follow the instructions provided by the answer mail.

Or click [join](https://groups.google.com/forum/#!forum/libhsts-bugs/join).
