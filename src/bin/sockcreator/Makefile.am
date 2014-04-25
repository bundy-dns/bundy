SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib

AM_CXXFLAGS = $(BUNDY_CXXFLAGS)

if USE_STATIC_LINK
AM_LDFLAGS = -static
endif

pkglibexecdir = $(libexecdir)/@PACKAGE@

CLEANFILES = *.gcno *.gcda

man_MANS = bundy-sockcreator.8
DISTCLEANFILES = $(man_MANS)
EXTRA_DIST = $(man_MANS) bundy-sockcreator.xml

if GENERATE_DOCS

bundy-sockcreator.8: bundy-sockcreator.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundy-sockcreator.xml

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

pkglibexec_PROGRAMS = bundy-sockcreator

bundy_sockcreator_SOURCES = sockcreator.cc sockcreator.h main.cc
bundy_sockcreator_LDADD  = $(top_builddir)/src/lib/util/io/libbundy-util-io.la
bundy_sockcreator_LDADD += $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la
