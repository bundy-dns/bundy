SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/dns -I$(top_builddir)/src/lib/dns
AM_CPPFLAGS += $(BOOST_INCLUDES)
AM_CPPFLAGS += $(SQLITE_CFLAGS)

AM_CXXFLAGS = $(B10_CXXFLAGS)

CLEANFILES = *.gcno *.gcda

lib_LTLIBRARIES = libresolve.la
libresolve_la_SOURCES = resolve.h
libresolve_la_SOURCES += resolver_interface.h
libresolve_la_SOURCES += resolver_callback.h resolver_callback.cc
libresolve_la_LIBADD = $(top_builddir)/src/lib/dns/libdns++.la
libresolve_la_LIBADD += $(top_builddir)/src/lib/exceptions/libexceptions.la