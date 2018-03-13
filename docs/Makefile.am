EXTRA_DIST = hsts.md hsts-make-dafsa.md DoxygenLayout.xml
DISTCLEANFILES =
LOCAL_DISTCLEAN =
STAMPS =

if WITH_DOXYGEN
man3_MANS =\
 $(builddir)/man/man3/libhsts.3

$(man3_MANS): libhsts.stamp

libhsts.stamp:
	$(DOXYGEN) $(builddir)/libhsts.doxy
	echo > libhsts.stamp

EXTRA_DIST += $(man3_MANS)
STAMPS += libhsts.stamp
LOCAL_DISTCLEAN += html man
endif

if WITH_PANDOC
man1_MANS = \
 $(builddir)/man/man1/hsts.1 \
 $(builddir)/man/man1/hsts-make-dafsa.1

$(man1_MANS): hsts.stamp

hsts.stamp:
	mkdir -p $(builddir)/man/man1
	PANDOC=$(PANDOC) sh $(builddir)/md2man.sh $(srcdir)/hsts.md $(builddir)/man/man1/hsts.1
	$(PANDOC) -s -f markdown -t texinfo -o $(builddir)/hsts.texi $(srcdir)/hsts.md
	$(MAKEINFO) --force -o $(builddir)/hsts.info $(builddir)/hsts.texi
	PANDOC=$(PANDOC) sh $(builddir)/md2man.sh $(srcdir)/hsts-make-dafsa.md $(builddir)/man/man1/hsts-make-dafsa.1
	$(PANDOC) -s -f markdown -t texinfo -o $(builddir)/hsts-make-dafsa.texi $(srcdir)/hsts-make-dafsa.md
	$(MAKEINFO) --force -o $(builddir)/hsts-make-dafsa.info $(builddir)/hsts-make-dafsa.texi
	echo > hsts.stamp

DISTCLEANFILES += hsts.texi hsts.info hsts-make-dafsa.texi hsts-make-dafsa.info
EXTRA_DIST += hsts.info hsts-make-dafsa.info $(man1_MANS)
STAMPS += hsts.stamp
endif

CLEANFILES = $(STAMPS)

all-local: $(STAMPS)

distclean-local:
	rm -rf $(LOCAL_DISTCLEAN)
