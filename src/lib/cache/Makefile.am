SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += $(BOOST_INCLUDES) $(MULTITHREADING_FLAG)
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/util -I$(top_builddir)/src/lib/util
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/dns -I$(top_builddir)/src/lib/dns
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/nsas -I$(top_builddir)/src/lib/nsas
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/cache -I$(top_builddir)/src/lib/cache
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

lib_LTLIBRARIES = libbundy-cache.la
libbundy_cache_la_SOURCES  = resolver_cache.h resolver_cache.cc
libbundy_cache_la_SOURCES  += message_cache.h message_cache.cc
libbundy_cache_la_SOURCES  += message_entry.h message_entry.cc
libbundy_cache_la_SOURCES  += rrset_cache.h rrset_cache.cc
libbundy_cache_la_SOURCES  += rrset_entry.h rrset_entry.cc
libbundy_cache_la_SOURCES  += cache_entry_key.h cache_entry_key.cc
libbundy_cache_la_SOURCES  += rrset_copy.h rrset_copy.cc
libbundy_cache_la_SOURCES  += local_zone_data.h local_zone_data.cc
libbundy_cache_la_SOURCES  += message_utility.h message_utility.cc
libbundy_cache_la_SOURCES  += logger.h logger.cc
nodist_libbundy_cache_la_SOURCES = cache_messages.cc cache_messages.h

BUILT_SOURCES = cache_messages.cc cache_messages.h

cache_messages.cc cache_messages.h: s-messages

s-messages: cache_messages.mes
	$(top_builddir)/src/lib/log/compiler/message $(top_srcdir)/src/lib/cache/cache_messages.mes
	touch $@

CLEANFILES = *.gcno *.gcda cache_messages.cc cache_messages.h s-messages

EXTRA_DIST = cache_messages.mes
