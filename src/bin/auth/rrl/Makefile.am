SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += -I$(top_srcdir)/src/bin -I$(top_builddir)/src/bin
AM_CPPFLAGS += $(BOOST_INCLUDES)

AM_CXXFLAGS = $(B10_CXXFLAGS)

CLEANFILES = *.gcno *.gcda

noinst_LTLIBRARIES = libauth_rrl.la

libauth_rrl_la_SOURCES = rrl_key.h rrl_key.cc

nodist_libauth_rrl_la_SOURCES = auth_rrl_messages.h auth_rrl_messages.cc

EXTRA_DIST  = rdata_serialization_priv.cc

BUILT_SOURCES = auth_rrl_messages.h auth_rrl_messages.cc
auth_rrl_messages.h auth_rrl_messages.cc: Makefile auth_rrl_messages.mes
	$(top_builddir)/src/lib/log/compiler/message $(srcdir)/auth_rrl_messages.mes

EXTRA_DIST += auth_rrl_messages.mes
CLEANFILES += auth_rrl_messages.h auth_rrl_messages.cc
