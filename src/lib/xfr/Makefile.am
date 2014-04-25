SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/dns -I$(top_builddir)/src/lib/dns
AM_CPPFLAGS += $(BOOST_INCLUDES)

AM_CXXFLAGS = $(BUNDY_CXXFLAGS)
AM_CXXFLAGS += -Wno-unused-parameter
# see src/lib/cc/Makefile.am

CLEANFILES = *.gcno *.gcda

lib_LTLIBRARIES = libbundy-xfr.la
libbundy_xfr_la_SOURCES = xfrout_client.h xfrout_client.cc
libbundy_xfr_la_LIBADD = $(top_builddir)/src/lib/util/io/libbundy-util-io.la
