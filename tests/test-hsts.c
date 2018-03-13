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
 * This file is part of the test suite of libhsts.
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_ALLOCA_H
#	include <alloca.h>
#endif

#include <libhsts.h>

#define countof(a) (sizeof(a)/sizeof(*(a)))

static int
	ok,
	failed;

static void test_hsts(void)
{
	/* punycode generation: idn ?? */
	/* octal code generation: echo -n "??" | od -b */
	static const struct test_data {
		const char
			*domain;
		int
			result;
		int
			include_subdomains_result;
	} test_data[] = {
		{ ".", HSTS_ERR_NOT_FOUND, 0 }, /* special case */
		{ "", HSTS_ERR_NOT_FOUND, 0 },  /* special case */
		{ NULL, HSTS_ERR_INVALID_ARG, 0 },  /* special case */
		{ "adfhoweirh", HSTS_ERR_NOT_FOUND, 0 }, /* unknown TLD */
		{ "adfhoweirh.com", HSTS_ERR_NOT_FOUND, 0 }, /* unknown domain */
		{ "www.tumblr.com", HSTS_SUCCESS, 0 }, /* exists, include_subdomains is FALSE */
		{ "fan.gov", HSTS_SUCCESS, 1 }, /*exists, include_subdomains is TRUE */
	};
	unsigned it;
	int result;
	hsts_t *hsts;

	if (hsts_load_file(SRCDIR "/hsts.dafsa", &hsts) != HSTS_SUCCESS) {
		failed++;
		printf("Failed to load %s/hsts.dafsa\n", SRCDIR);
		return;
	}

	for (it = 0; it < countof(test_data); it++) {
		const struct test_data *t = &test_data[it];
		hsts_entry_t *e;

		result = hsts_search(hsts, t->domain, 0, &e);

		if (result == t->result) {
			ok++;
		} else {
			failed++;
			printf("hsts_search(%s)=%d (expected %d)\n", t->domain, result, t->result);
			if (result == HSTS_SUCCESS)
				hsts_free_entry(e);
			continue;
		}

		if (result != HSTS_SUCCESS) {
			if (t->include_subdomains_result) {
				failed++;
				printf("include_subdomains(%s)=%d (expected 0)\n", t->domain, t->include_subdomains_result);
			}
			continue;
		}

		result = hsts_has_include_subdomains(e);
		if (result == t->include_subdomains_result) {
			ok++;
		} else {
			failed++;
			printf("hsts_has_include_subdomains(%s)=%d (expected %d)\n", t->domain, result, t->include_subdomains_result);
		}

		hsts_free_entry(e);
	}

	hsts_get_version();
	hsts_dist_filename();
	hsts_load_file(NULL, NULL);
	hsts_load_fp(NULL, NULL);

	hsts_free(hsts);
}

int main(int argc, const char * const *argv)
{
	/* if VALGRIND testing is enabled, we have to call ourselves with valgrind checking */
	if (argc == 1) {
		const char *valgrind = getenv("TESTS_VALGRIND");

		if (valgrind && *valgrind) {
			size_t cmdsize = strlen(valgrind) + strlen(argv[0]) + 32;
			char *cmd = alloca(cmdsize);

			snprintf(cmd, cmdsize, "TESTS_VALGRIND="" %s %s", valgrind, argv[0]);
			return system(cmd) != 0;
		}
	}

	test_hsts();

	if (failed) {
		printf("Summary: %d out of %d tests failed\n", failed, ok + failed);
		return 1;
	}

	printf("Summary: All %d tests passed\n", ok + failed);
	return 0;
}
