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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libhsts.h>

#ifndef DOXYGEN_SHOULD_SKIP_THIS

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#  define GCC_VERSION_AT_LEAST(major, minor) ((__GNUC__ > (major)) || (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#else
#  define GCC_VERSION_AT_LEAST(major, minor) 0
#endif

#if GCC_VERSION_AT_LEAST(2,95)
#  define LIBHSTS_UNUSED __attribute__ ((unused))
#else
#  define LIBHSTS_UNUSED
#endif

/* prototypes */
int LookupStringInFixedSet(const unsigned char* graph, size_t length, const char* key, size_t key_length);
int GetUtfMode(const unsigned char *graph, size_t length);

#endif

/**
 * \file
 * \brief HSTS library functions
 * \defgroup libhsts HSTS library functions
 * @{
 */

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

struct _hsts_entry_st {
	int
		flags;
};

#ifdef HSTS_DISTFILE
static const char _hsts_dist_filename[] = HSTS_DISTFILE;
#else
static const char *_hsts_dist_filename[];
#endif

static int _hsts_search(const hsts_t *hsts, const char *domain, int *flags)
{
	const char *p, *suffix_label;
	int suffix_nlabels;
	size_t suffix_length;
	int must_have_include_subdomains;

	/* this function should be called without leading dots, just make sure */
	if (*domain == '.')
		domain++;

	suffix_nlabels = 1;

	for (p = domain; *p; p++) {
		if (*p == '.')
			suffix_nlabels++;
	}

	suffix_label = domain;
	suffix_length = (size_t) (p - suffix_label);
	must_have_include_subdomains = 0;

	for (;;) {
		int rc = LookupStringInFixedSet(hsts->dafsa, hsts->dafsa_size, suffix_label, suffix_length);
		if (rc != -1) {
			if (flags)
				*flags = rc;

			if (must_have_include_subdomains && !(rc & HSTS_FLAG_INCLUDE_SUBDOMAINS))
				return -1; /* found a subdomain without 'include_subdomains' flag */

			return 0; // domain found
		}

		if (!(suffix_label = strchr(suffix_label, '.')))
			break;

		suffix_label++;
		suffix_length = strlen(suffix_label);
		suffix_nlabels--;
		must_have_include_subdomains = 1;
	}

	return -1; // didn't find domain
}

/**
 * \param[in] hsts HSTS data object
 * \param[in] domain Domain input string
 * \param[in] flags Flags, currently unused
 * \param[out] entry Return value on success, else untouched
 *
 * This function searches for \p domain in the given \p hsts object (HSTS data for preloading) and
 * on success returns a data entry in \p entry. If \p domain is a subdomain of a list entry that has the
 * 'include-subdomains' flag set, the function also succeeds.
 *
 * \p entry maybe be %NULL to perform a simple check.
 *
 * International \p domain names have to be in ACE (punycode) format.
 * Other encodings (e.g. UTF-8) result in incorrect return values.
 *
 * \p hsts is a HSTS object returned by either hsts_load_file() or hsts_load_fp().
 *
 * \return %HSTS_SUCCESS if \p domain is has been found, if not %HSTS_ERR_NOT_FOUND.
 *   HSTS_ERR_INVALID_ARG is returned if either \p hsts or \p domain was %NULL.
 *   HSTS_ERR_NO_MEM is returned if a memory allocation failed.
 *
 * Since: 0.0.1
 */
int hsts_search(const hsts_t *hsts, const char *domain, LIBHSTS_UNUSED int flags, hsts_entry_t **entry)
{
	int eflags;

	if (!hsts || !domain)
		return HSTS_ERR_INVALID_ARG;

	if (_hsts_search(hsts, domain, &eflags) == 0) {
		if (entry) {
			hsts_entry_t *e = calloc(1, sizeof(hsts_entry_t));

			if (!e)
				return HSTS_ERR_NO_MEM;

			e->flags = eflags;
			*entry = e;
		}

		return HSTS_SUCCESS;
	}

	return HSTS_ERR_NOT_FOUND;
}

/**
 * \param[in] entry The domain entry to check
 * \return 1 if \p entry has the 'include_subdomain' attribute, 0 if not.
 *
 * This function checks if an \p entry returned from hsts_search() has the 'include_subdomain'
 * attribute or not.
 */
int hsts_has_include_subdomains(const hsts_entry_t *entry)
{
	if (!entry)
		return 0;

	return !!(entry->flags & HSTS_FLAG_INCLUDE_SUBDOMAINS);
}

/**
 * \param[in] fname Name of a HSTS data file
 * \param[out] hsts Returned HSTS data
 *
 * This function loads the HSTS data from a file named \p fname.
 * On success \p hsts will be initialized, else it will be left untouched.
 *
 * The returned \p hsts object can be used with functions like hsts_get_entry().
 * When done you have to free the hsts object by calling hsts_free().
 *
 * @return HSTS_SUCCESS on success, else another hsts_status_t value
 *
 * Since: 0.0.1
 */
hsts_status_t hsts_load_file(const char *fname, hsts_t **hsts)
{
	FILE *fp;
	hsts_status_t rc;

	if (!fname)
		return HSTS_ERR_INVALID_ARG;

	rc = hsts_load_fp(fp = fopen(fname, "rb"), hsts);

	if (fp)
		fclose(fp);

	return rc;
}

/**
 * @param[in] fp FILE pointer of a HSTS data file
 * @param[out] hsts Returned HSTS data
 *
 * This function loads the HSTS data from a file named \p fname.
 * On success \p hsts will be initialized, else it will be left untouched.
 *
 * The returned \p hsts object can be used with functions like hsts_get_entry().
 * When done you have to free the hsts object by calling hsts_free().
 *
 * @return HSTS_SUCCESS on success, else another hsts_status_t value
 *
 * Since: 0.0.1
 */
hsts_status_t hsts_load_fp(FILE *fp, hsts_t **hsts)
{
	hsts_t *_hsts;
	char buf[16];
	int version;
	void *m;
	size_t size, n, len = 0;

	if (!fp)
		return HSTS_ERR_INVALID_ARG;

	if ((n = fread(buf, 1, sizeof(buf), fp)) < sizeof(buf))
		return ferror(fp) ? HSTS_ERR_INPUT_FAILURE : HSTS_ERR_INPUT_TOO_SHORT;

	buf[sizeof(buf) - 1] = 0;

	if (strncmp(buf, ".DAFSA@HSTS_", 12))
		return HSTS_ERR_INPUT_FORMAT;

	if ((version = atoi(buf + 12)) != 0)
		return HSTS_ERR_INPUT_VERSION;

	if (!(_hsts = calloc(1, sizeof(hsts_t))))
		return HSTS_ERR_NO_MEM;

	if (!(_hsts->dafsa = malloc(size = 384 * 1024))) { /* 13.3.2018: the current size is ~340k, avoid reallocs */
		hsts_free(_hsts);
		return HSTS_ERR_NO_MEM;
	}

	while ((n = fread(_hsts->dafsa + len, 1, size - len, fp)) > 0) {
		len += n;
		if (len >= size) {
			if (size >= 20 * 1024 * 1024) {
				/* Apply a random max. file size to avoid overflows / DOS attacks */
				hsts_free(_hsts);
				return HSTS_ERR_INPUT_TOO_LONG;
			}
			if (!(m = realloc(_hsts->dafsa, size *= 2))) {
				hsts_free(_hsts);
				return HSTS_ERR_NO_MEM;
			}
			_hsts->dafsa = m;
		}
	}

	/* release unused memory */
	if ((m = realloc(_hsts->dafsa, len)))
		_hsts->dafsa = m;
	else if (!len)
		_hsts->dafsa = NULL; /* realloc() just free'd hsts->dafsa */
	/* else we go on with the unshrunk data memory */

	_hsts->dafsa_size = len;
	_hsts->utf8 = !!GetUtfMode(_hsts->dafsa, len);

	if (hsts)
		*hsts = _hsts;

	return HSTS_SUCCESS;
}

/**
 * \param[in] entry HSTS entry to be freed
 *
 * This function frees the the HSTS entry that has been retrieved via hsts_search().
 *
 * Since: 0.0.1
 */
void hsts_free_entry(hsts_entry_t *entry)
{
	free(entry);
}

/**
 * \param[in] hsts HSTS data pointer to be freed
 *
 * This function frees the the HSTS data object that has been retrieved via
 * hsts_load_fp() or hsts_load_file().
 *
 * Since: 0.0.1
 */
void hsts_free(hsts_t *hsts)
{
	if (hsts) {
		free(hsts->dafsa);
		free(hsts);
	}
}

/**
 * This function returns the file name of the distribution/system HSTS data file.
 * This file will be considered by hsts_latest().
 *
 * Return the filename that is set by ./configure --with-hsts-distfile, or an empty string.
 *
 * \return String containing a HSTS file name or an empty string.
 *
 * Since: 0.0.1
 */
const char *hsts_dist_filename(void)
{
	return _hsts_dist_filename;
}

/**
 * Get the libhsts version.
 *
 * \return String containing version of libhsts.
 *
 * Since: 0.0.1
 **/
const char *hsts_get_version(void)
{
	return PACKAGE_VERSION;
}

/**
 * \param[in] version Version number (hex) to check against
 *
 * Check the given version number is at minimum the current library version number.
 * The version number must be a hexadecimal number like 0x000a01 (V0.10.1).
 *
 * \return Returns the library version number if the given version number is at least
 * the version of the library, else return 0; If the argument is 0, the function returns
 * the library version number without performing a check.
 *
 * Since: 0.0.1
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

/** @} */
