SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += $(BOOST_INCLUDES)
AM_CXXFLAGS = $(BUNDY_CXXFLAGS)

# The core library
lib_LTLIBRARIES = libbundy-acl.la
libbundy_acl_la_SOURCES  = acl.h
libbundy_acl_la_SOURCES += check.h
libbundy_acl_la_SOURCES += ip_check.h ip_check.cc
libbundy_acl_la_SOURCES += logic_check.h
libbundy_acl_la_SOURCES += loader.h loader.cc

libbundy_acl_la_LIBADD = $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la
libbundy_acl_la_LIBADD += $(top_builddir)/src/lib/cc/libbundy-cc.la
libbundy_acl_la_LIBADD += $(top_builddir)/src/lib/util/libbundy-util.la

# DNS specialized one
lib_LTLIBRARIES += libbundy-dnsacl.la

libbundy_dnsacl_la_SOURCES = dns.h dns.cc dnsname_check.h

libbundy_dnsacl_la_LIBADD = libbundy-acl.la
libbundy_dnsacl_la_LIBADD += $(top_builddir)/src/lib/dns/libbundy-dns++.la

CLEANFILES = *.gcno *.gcda
