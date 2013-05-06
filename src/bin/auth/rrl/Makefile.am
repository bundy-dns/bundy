SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += -I$(top_srcdir)/src/bin -I$(top_builddir)/src/bin
AM_CPPFLAGS += $(BOOST_INCLUDES)

AM_CXXFLAGS = $(B10_CXXFLAGS)

CLEANFILES = *.gcno *.gcda

noinst_LTLIBRARIES = libauth_rrl.la

libauth_rrl_la_SOURCES = rrl.h rrl.cc
libauth_rrl_la_SOURCES += rrl_key.h rrl_key.cc
libauth_rrl_la_SOURCES += rrl_entry.h rrl_entry.cc
libauth_rrl_la_SOURCES += rrl_table.h rrl_table.cc
libauth_rrl_la_SOURCES += rrl_name_pool.h rrl_name_pool.cc
libauth_rrl_la_SOURCES += logger.h logger.cc
libauth_rrl_la_SOURCES += rrl_response_type.h
libauth_rrl_la_SOURCES += rrl_rate.h
libauth_rrl_la_SOURCES += rrl_result.h

nodist_libauth_rrl_la_SOURCES = auth_rrl_messages.h auth_rrl_messages.cc

EXTRA_DIST  = rdata_serialization_priv.cc

BUILT_SOURCES = auth_rrl_messages.h auth_rrl_messages.cc
auth_rrl_messages.h auth_rrl_messages.cc: Makefile auth_rrl_messages.mes
	$(top_builddir)/src/lib/log/compiler/message $(srcdir)/auth_rrl_messages.mes

EXTRA_DIST += auth_rrl_messages.mes
CLEANFILES += auth_rrl_messages.h auth_rrl_messages.cc
