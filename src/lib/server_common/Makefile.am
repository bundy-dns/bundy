SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += $(BOOST_INCLUDES)
AM_CXXFLAGS = $(BUNDY_CXXFLAGS)

# Some versions of GCC warn about some versions of Boost regarding
# missing initializer for members in its posix_time.
# https://svn.boost.org/trac/boost/ticket/3477
# But older GCC compilers don't have the flag.
AM_CXXFLAGS += $(WARNING_NO_MISSING_FIELD_INITIALIZERS_CFLAG)

if USE_CLANGPP
# clang++ complains about unused function parameters in some boost header
# files.
AM_CXXFLAGS += -Wno-unused-parameter
endif

lib_LTLIBRARIES = libbundy-server-common.la
libbundy_server_common_la_SOURCES = client.h client.cc
libbundy_server_common_la_SOURCES += keyring.h keyring.cc
libbundy_server_common_la_SOURCES += portconfig.h portconfig.cc
libbundy_server_common_la_SOURCES += logger.h logger.cc
libbundy_server_common_la_SOURCES += socket_request.h socket_request.cc
nodist_libbundy_server_common_la_SOURCES = server_common_messages.h
nodist_libbundy_server_common_la_SOURCES += server_common_messages.cc
libbundy_server_common_la_LIBADD = $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la
libbundy_server_common_la_LIBADD += $(top_builddir)/src/lib/asiolink/libbundy-asiolink.la
libbundy_server_common_la_LIBADD += $(top_builddir)/src/lib/cc/libbundy-cc.la
libbundy_server_common_la_LIBADD += $(top_builddir)/src/lib/config/libbundy-cfgclient.la
libbundy_server_common_la_LIBADD += $(top_builddir)/src/lib/log/libbundy-log.la
libbundy_server_common_la_LIBADD += $(top_builddir)/src/lib/acl/libbundy-acl.la
libbundy_server_common_la_LIBADD += $(top_builddir)/src/lib/dns/libbundy-dns++.la
libbundy_server_common_la_LIBADD += $(top_builddir)/src/lib/util/io/libbundy-util-io.la
BUILT_SOURCES = server_common_messages.h server_common_messages.cc
server_common_messages.h server_common_messages.cc: s-messages

s-messages: server_common_messages.mes
	$(top_builddir)/src/lib/log/compiler/message $(top_srcdir)/src/lib/server_common/server_common_messages.mes
	touch $@

EXTRA_DIST = server_common_messages.mes

CLEANFILES = *.gcno *.gcda server_common_messages.h server_common_messages.cc s-messages
