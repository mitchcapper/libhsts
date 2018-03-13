# hsts-make-dafsa

* [Name](#Name)
* [Synopsis](#Synopsis)
* [Description](#Description)
* [Options](#Options)
* [See Also](#See Also)
* [Copyright](#Copyright)

# <a name="Name"/>Name

  `hsts-make-dafsa` - generate a compact and optimized DAFSA from a HSTS preload file

# <a name="Synopsis"/>Synopsis

  `hsts-make-dafsa [options] <infile> <outfile>`

# <a name="Description"/>Description

  `hsts-make-dafsa` produces C/C++ code or an architecture-independent binary object that represents a Deterministic
  Acyclic Finite State Automaton (DAFSA) from a textual representation of a Public Suffix List.
  Input and output files must be specified on the command line.

  This compact representation enables optimized queries of the list, saving
  both time and space when compared to searches of human-readable representations.

# <a name="Options"/>Options

  The format of the data read and written by hsts-make-dafsa depends on options passed to it.

## `--output-format=[cxx|cxx+|binary]`

  cxx: (default) output is C/C++ code

  cxx+: output is C/C++ code plus statistical assignments (used by libhsts build process)

  binary: output is an architecture-independent binary format

## `--encoding=[utf-8|ascii]`

  utf-8: (default) UTF-8 mode (output contains UTF-8 + punycode)

  ascii: (deprecated) 7-bit ASCII mode (output contains punycode only)

# <a name="See also"/>See also

  https://www.chromium.org/hsts/

  https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security

  https://github.com/rockdaboot/libhsts

# <a name="Copyright"/>Copyright

  `hsts-make-dafsa` was written by Olle Liljenzin as part of the Chromium project and has been modified by Tim Rühsen.
  The code and its documentation is governed by a BSD-style license.
