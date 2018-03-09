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
 * HSTS routines
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#       define GCC_VERSION_AT_LEAST(major, minor) ((__GNUC__ > (major)) || (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#else
#       define GCC_VERSION_AT_LEAST(major, minor) 0
#endif

#if GCC_VERSION_AT_LEAST(2,95)
#  define LIBHSTS_UNUSED __attribute__ ((unused))
#else
#  define LIBHSTS_UNUSED
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <limits.h> /* for UINT_MAX */
#include <langinfo.h>
#include <arpa/inet.h>
#ifdef HAVE_ALLOCA_H
#	include <alloca.h>
#endif

#include <libhsts.h>

struct _hsts_st {
	unsigned char
		*dafsa;
	size_t
		dafsa_size;
	int
		nsuffixes;
	unsigned
		utf8 : 1; /* 1: data contains UTF-8 + punycode encoded rules */
};

/**
 * SECTION:libhsts
 * @short_description: Public Suffix List library functions
 * @title: libhsts
 * @stability: Stable
 * @include: libhsts.h
 *
 * [Public Suffix List](https://publicsuffix.org/) library functions.
 *
 */

#define countof(a) (sizeof(a)/sizeof(*(a)))

#define _HSTS_FLAG_INCLUDE_SUBDIRS (1<<0)
#define _HSTS_FLAG_PLAIN     (1<<4) /* just used for HSTS syntax checking */

struct _hsts_st {
	unsigned char
		*dafsa;
	size_t
		dafsa_size;
	int
		nsuffixes;
	unsigned
		utf8 : 1; /* 1: data contains UTF-8 + punycode encoded rules */
};

static const unsigned char kDafsa[0];
static time_t _hsts_file_time = 0;
static int _hsts_nsuffixes = 0;
static const char _hsts_sha1_checksum[] = "";
static const char _hsts_filename[] = "";

#ifdef HSTS_DISTFILE
static const char _hsts_dist_filename[] = HSTS_DISTFILE;
#else
static const char _hsts_dist_filename[] = "";
#endif

static int _isspace_ascii(const char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int _str_is_ascii(const char *s)
{
	while (*s && *((unsigned char *)s) < 128) s++;

	return !*s;
}

/* prototypes */
int LookupStringInFixedSet(const unsigned char* graph, size_t length, const char* key, size_t key_length);
int GetUtfMode(const unsigned char *graph, size_t length);

static int _hsts_is_hsts(const hsts_t *hsts, const char *domain)
{
	const char *p, *suffix_label;
	int suffix_nlabels;
	int suffix_length;

	/* this function should be called without leading dots, just make sure */
	if (*domain == '.')
		domain++;

	suffix_nlabels = 1;

	for (p = domain; *p; p++) {
		if (*p == '.')
			suffix_nlabels++;
	}

	suffix_label = domain;
	suffix_length = p - suffix_label;

	for (;;) {
		int rc = LookupStringInFixedSet(hsts->dafsa, hsts->dafsa_size, suffix_label, suffix_length);
		if (rc != -1) {
			return 1; // entry found
		}

		if ((suffix_label = strchr(suffix_label, '.'))) {
			suffix_label++;
			suffix_length = strlen(suffix_label);
			suffix_nlabels--;
		} else
			break;
	}

suffix_no:
	return 0;
}

/**
 * hsts_is_hsts:
 * @hsts: HSTS context
 * @domain: Domain string
 *
 * This function checks if @domain is a public suffix by the means of the
 * [Mozilla Public Suffix List](https://publicsuffix.org).
 *
 * For cookie domain checking see hsts_is_cookie_domain_acceptable().
 *
 * International @domain names have to be either in UTF-8 (lowercase + NFKC) or in ASCII/ACE format (punycode).
 * Other encodings likely result in incorrect return values.
 * Use helper function hsts_str_to_utf8lower() for normalization @domain.
 *
 * @hsts is a context returned by either hsts_load_file(), hsts_load_fp() or
 * hsts_builtin().
 *
 * Returns: 1 if domain is a public suffix, 0 if not.
 *
 * Since: 0.1
 */
int hsts_is_hsts(const hsts_t *hsts, const char *domain, UNUSED int flags)
{
	if (!hsts || !domain)
		return 1;

	return _hsts_is_hsts(hsts, domain);
}

/**
 * hsts_load_file:
 * @fname: Name of HSTS file
 *
 * This function loads the public suffixes file named @fname.
 * To free the allocated resources, call hsts_free().
 *
 * The suffixes are expected to be UTF-8 encoded (lowercase + NFKC) if they are international.
 *
 * Returns: Pointer to a HSTS context or %NULL on failure.
 *
 * Since: 0.1
 */
hsts_t *hsts_load_file(const char *fname)
{
	FILE *fp;
	hsts_t *hsts = NULL;

	if (!fname)
		return NULL;

	if ((fp = fopen(fname, "r"))) {
		hsts = hsts_load_fp(fp);
		fclose(fp);
	}

	return hsts;
}

/**
 * hsts_load_fp:
 * @fp: FILE pointer
 *
 * This function loads the public suffixes from a FILE pointer.
 * To free the allocated resources, call hsts_free().
 *
 * The suffixes are expected to be UTF-8 encoded (lowercase + NFKC) if they are international.
 *
 * Returns: Pointer to a HSTS context or %NULL on failure.
 *
 * Since: 0.1
 */
hsts_t *hsts_load_fp(FILE *fp)
{
	hsts_t *hsts;
	_hsts_entry_t suffix, *suffixp;
	char buf[256], *linep, *p;
	int type = 0, is_dafsa;
	_hsts_idna_t *idna;

	if (!fp)
		return NULL;

	if (!(hsts = calloc(1, sizeof(hsts_t))))
		return NULL;

	/* read first line to allow ASCII / DAFSA detection */
	if (!(linep = fgets(buf, sizeof(buf) - 1, fp)))
		goto fail;

	is_dafsa = strlen(buf) == 16 && !strncmp(buf, ".DAFSA@HSTS_", 11);

	if (is_dafsa) {
		void *m;
		size_t size = 65536, n, len = 0;
		int version = atoi(buf + 11);

		if (version != 0)
			goto fail;

		if (!(hsts->dafsa = malloc(size)))
			goto fail;

		memcpy(hsts->dafsa, buf, len);

		while ((n = fread(hsts->dafsa + len, 1, size - len, fp)) > 0) {
			len += n;
			if (len >= size) {
				if (!(m = realloc(hsts->dafsa, size *= 2)))
					goto fail;
				hsts->dafsa = m;
			}
		}

		/* release unused memory */
		if ((m = realloc(hsts->dafsa, len)))
			hsts->dafsa = m;
		else if (!len)
			hsts->dafsa = NULL; /* realloc() just free'd hsts->dafsa */

		hsts->dafsa_size = len;
		hsts->utf8 = !!GetUtfMode(hsts->dafsa, len);

		return hsts;
	}

	idna = _hsts_idna_open();

	/*
	 *  as of 02.11.2012, the list at https://publicsuffix.org/list/ contains ~6000 rules and 40 exceptions.
	 *  as of 19.02.2014, the list at https://publicsuffix.org/list/ contains ~6500 rules and 19 exceptions.
	 */
	hsts->suffixes = _vector_alloc(8*1024, _suffix_compare_array);
	hsts->utf8 = 1; /* we put UTF-8 and punycode rules in the lookup vector */

	do {
		while (_isspace_ascii(*linep)) linep++; /* ignore leading whitespace */
		if (!*linep) continue; /* skip empty lines */

		if (*linep == '/' && linep[1] == '/') {
			if (!type) {
				if (strstr(linep + 2, "===BEGIN ICANN DOMAINS==="))
					type = _HSTS_FLAG_ICANN;
				else if (!type && strstr(linep + 2, "===BEGIN PRIVATE DOMAINS==="))
					type = _HSTS_FLAG_PRIVATE;
			}
			else if (type == _HSTS_FLAG_ICANN && strstr(linep + 2, "===END ICANN DOMAINS==="))
				type = 0;
			else if (type == _HSTS_FLAG_PRIVATE && strstr(linep + 2, "===END PRIVATE DOMAINS==="))
				type = 0;

			continue; /* skip comments */
		}

		/* parse suffix rule */
		for (p = linep; *linep && !_isspace_ascii(*linep);) linep++;
		*linep = 0;

		if (*p == '!') {
			p++;
			suffix.flags = _HSTS_FLAG_EXCEPTION | type;
			hsts->nexceptions++;
		} else if (*p == '*') {
			if (*++p != '.') {
				/* fprintf(stderr, _("Unsupported kind of rule (ignored): %s\n"), p - 1); */
				continue;
			}
			p++;
			/* wildcard *.foo.bar implicitly make foo.bar a public suffix */
			suffix.flags = _HSTS_FLAG_WILDCARD | _HSTS_FLAG_PLAIN | type;
			hsts->nwildcards++;
			hsts->nsuffixes++;
		} else {
			suffix.flags = _HSTS_FLAG_PLAIN | type;
			hsts->nsuffixes++;
		}

		if (_suffix_init(&suffix, p, linep - p) == 0) {
			int index;

			if ((index = _vector_find(hsts->suffixes, &suffix)) >= 0) {
				/* Found existing entry:
				 * Combination of exception and plain rule is ambiguous
				 * !foo.bar
				 * foo.bar
				 *
				 * Allowed:
				 * !foo.bar + *.foo.bar
				 * foo.bar + *.foo.bar
				 *
				 * We do not check here, let's do it later.
				 */

				suffixp = _vector_get(hsts->suffixes, index);
				suffixp->flags |= suffix.flags;
			} else {
				/* New entry */
				suffixp = _vector_get(hsts->suffixes, _vector_add(hsts->suffixes, &suffix));
			}

			if (suffixp) {
				suffixp->label = suffixp->label_buf; /* set label to changed address */
				_add_punycode_if_needed(idna, hsts->suffixes, suffixp);
			}
		}
	} while ((linep = fgets(buf, sizeof(buf), fp)));

	_vector_sort(hsts->suffixes);

	_hsts_idna_close(idna);

	return hsts;

fail:
	hsts_free(hsts);
	return NULL;
}

/**
 * hsts_free:
 * @hsts: HSTS context pointer
 *
 * This function frees the the HSTS context that has been retrieved via
 * hsts_load_fp() or hsts_load_file().
 *
 * Since: 0.1
 */
void hsts_free(hsts_t *hsts)
{
	if (hsts) {
		free(hsts->dafsa);
		free(hsts);
	}
}

/**
 * hsts_dist_filename:
 *
 * This function returns the file name of the distribution/system HSTS data file.
 * This file will be considered by hsts_latest().
 *
 * Return the filename that is set by ./configure --with-hsts-distfile, or an empty string.
 *
 * Returns: String containing a HSTS file name or an empty string.
 *
 * Since: 0.16
 */
const char *hsts_dist_filename(void)
{
	return _hsts_dist_filename;
}

/**
 * hsts_get_version:
 *
 * Get libhsts version.
 *
 * Returns: String containing version of libhsts.
 *
 * Since: 0.2.5
 **/
const char *hsts_get_version(void)
{
#ifdef WITH_LIBICU
	return PACKAGE_VERSION " (+libicu/" U_ICU_VERSION ")";
#elif defined(WITH_LIBIDN2)
	return PACKAGE_VERSION " (+libidn2/" IDN2_VERSION ")";
#elif defined(WITH_LIBIDN)
	return PACKAGE_VERSION " (+libidn/" STRINGPREP_VERSION ")";
#else
	return PACKAGE_VERSION " (no IDNA support)";
#endif
}

/**
 * hsts_check_version_number:
 * @version: Version number (hex) to check against.
 *
 * Check the given version number is at minimum the current library version number.
 * The version number must be a hexadecimal number like 0x000a01 (V0.10.1).
 *
 * Returns: Returns the library version number if the given version number is at least
 * the version of the library, else return 0; If the argument is 0, the function returns
 * the library version number without performing a check.
 *
 * Since: 0.11.0
 **/
int hsts_check_version_number(int version)
{
	if (version) {
		int major = version >> 16;
		int minor = (version >> 8) & 0xFF;
		int patch = version & 0xFF;

		if (major < HSTS_VERSION_MAJOR
			|| (major == HSTS_VERSION_MAJOR && minor < HSTS_VERSION_MINOR)
			|| (major == HSTS_VERSION_MAJOR && minor == HSTS_VERSION_MINOR && patch < HSTS_VERSION_PATCH))
		{
			return 0;
		}
	}

	return HSTS_VERSION_NUMBER;
}
