SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += $(BOOST_INCLUDES)

AM_CXXFLAGS = $(B10_CXXFLAGS)

CLEANFILES = *.gcno *.gcda

lib_LTLIBRARIES = libbundy-auth.la

libbundy_auth_la_SOURCES = rrl_key.h rrl_key.cc
libbundy_auth_la_SOURCES += rrl_response_type.h

libbundy_auth_la_LIBADD = $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la
libbundy_auth_la_LIBADD += $(top_builddir)/src/lib/asiolink/libbundy-asiolink.la
libbundy_auth_la_LIBADD += $(top_builddir)/src/lib/dns/libbundy-dns++.la
libbundy_auth_la_LIBADD += $(top_builddir)/src/lib/log/libbundy-log.la

# notyet:
# nodist_libbundy_auth_la_SOURCES = libauth_messages.h libauth_messages.cc
# BUILT_SOURCES = libauth_messages.h libauth_messages.cc
# libauth_messages.h libauth_messages.cc: Makefile libauth_messages.mes
# 	$(top_builddir)/src/lib/log/compiler/message $(srcdir)/libauth_messages.mes

# EXTRA_DIST = libauth_messages.mes

CLEANFILES += libauth_messages.h libauth_messages.cc
