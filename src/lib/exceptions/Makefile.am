SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CXXFLAGS=$(BUNDY_CXXFLAGS)

lib_LTLIBRARIES = libbundy-exceptions.la
libbundy_exceptions_la_SOURCES = exceptions.h exceptions.cc

CLEANFILES = *.gcno *.gcda

libbundy_exceptions_includedir = $(includedir)/$(PACKAGE_NAME)/exceptions
libbundy_exceptions_include_HEADERS = exceptions.h
