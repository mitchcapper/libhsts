/*
 * Copyright(c) 2018 Tim Ruehsen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * This file is part of libhsts.
 *
 * Using the libhsts functions via command line
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <libhsts.h>

static void usage(int err, FILE* f)
{
	fprintf(f, "Usage: hsts [options] <domains...>\n");
	fprintf(f, "\n");
	fprintf(f, "Options:\n");
	fprintf(f, "  --version                    show library version information\n");
	fprintf(f, "  --load-hsts-file <filename>  load HSTS data from file (DAFSA format)\n");
	fprintf(f, "  --include-subdomains         check if given domains have the 'include_subdomains' flag\n");
	fprintf(f, "\n");

	exit(err);
}

static void check_and_print(const hsts_t *hsts, const char *domain, int mode)
{
	hsts_entry_t *e;

	if (hsts_search(hsts, domain, 0, &e) != HSTS_SUCCESS) {
		printf("%s: 0\n", domain);
		return ;
	}

	if (mode == 1) {
		printf("%s: 1\n", domain);
	} else if (mode == 2) {
		printf("%s: %d\n", domain, (int) hsts_has_include_subdomains(e));
	}

	hsts_free_entry(e);
}

int main(int argc, const char *const *argv)
{
	int mode = 1;
	const char *const *arg, *hsts_file = NULL;
	hsts_t *hsts = NULL;

	hsts_load_file(hsts_dist_filename(), &hsts);

	for (arg = argv + 1; arg < argv + argc; arg++) {
		if (!strncmp(*arg, "--", 2)) {
			if (!strcmp(*arg, "--include-subdomains"))
				mode = 2;
			else if (!strcmp(*arg, "--load-hsts-file") && arg < argv + argc - 1) {
				hsts_free(hsts);
				if (hsts_file) {
					fprintf(stderr, "Dropped data from %s\n", hsts_file);
					hsts_file = NULL;
				}
				if (hsts_load_file(hsts_file = *(++arg), &hsts) != HSTS_SUCCESS) {
					fprintf(stderr, "Failed to load HSTS data from %s\n\n", hsts_file);
					hsts_file = NULL;
				}
			}
			else if (!strcmp(*arg, "--help")) {
				fprintf(stdout, "`hsts' explores a HSTS preload list\n\n");
				usage(0, stdout);
			}
			else if (!strcmp(*arg, "--version")) {
				printf("hsts %s (0x%06x)\n", PACKAGE_VERSION, hsts_check_version_number(0));
				printf("libhsts %s\n", hsts_get_version());
				printf("\n");
				printf("Copyright (C) 2018 Tim Ruehsen\n");
				printf("License: MIT\n");
				exit(0);
			}
			else if (!strcmp(*arg, "--")) {
				arg++;
				break;
			}
			else {
				fprintf(stderr, "Unknown option '%s'\n", *arg);
				usage(1, stderr);
			}
		} else
			break;
	}

	if (!hsts) {
		fprintf(stderr, "No HSTS data available - aborting\n");
		exit(2);
	}

	if (arg >= argv + argc) {
		char buf[256], *domain;
		size_t len;

		/* read domains from STDIN */
		while (fgets(buf, sizeof(buf), stdin)) {
			for (domain = buf; isspace(*domain); domain++); /* skip leading spaces */
			if (*domain == '#' || !*domain) continue; /* skip empty lines and comments */
			for (len = strlen(domain); len && isspace(domain[len - 1]); len--); /* skip trailing spaces */
			domain[len] = 0;

			check_and_print(hsts, domain, mode);
		}

		hsts_free(hsts);
		exit(0);
	}

	for (; arg < argv + argc; arg++) {
		check_and_print(hsts, *arg, mode);
	}

	hsts_free(hsts);

	return 0;
}
