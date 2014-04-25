SUBDIRS = . testdata

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += $(BOOST_INCLUDES)
AM_CXXFLAGS=$(BUNDY_CXXFLAGS)

if HAVE_GTEST
noinst_LTLIBRARIES = libbundy-testutils.la

libbundy_testutils_la_SOURCES = srv_test.h srv_test.cc
libbundy_testutils_la_SOURCES += dnsmessage_test.h dnsmessage_test.cc
libbundy_testutils_la_SOURCES += mockups.h
libbundy_testutils_la_CPPFLAGS = $(AM_CPPFLAGS) $(GTEST_INCLUDES)
libbundy_testutils_la_LIBADD  = $(top_builddir)/src/lib/asiolink/libbundy-asiolink.la
libbundy_testutils_la_LIBADD += $(top_builddir)/src/lib/dns/libbundy-dns++.la
endif

EXTRA_DIST = portconfig.h socket_request.h
