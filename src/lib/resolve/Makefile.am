SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/dns -I$(top_builddir)/src/lib/dns
AM_CPPFLAGS += $(BOOST_INCLUDES)

AM_CXXFLAGS = $(BUNDY_CXXFLAGS)

# Define rule to build logging source files from message file
resolve_messages.h resolve_messages.cc: s-messages

s-messages: resolve_messages.mes
	$(top_builddir)/src/lib/log/compiler/message $(top_srcdir)/src/lib/resolve/resolve_messages.mes
	touch $@

# Tell Automake that the nsasdef.{cc,h} source files are created in the build
# process, so it must create these before doing anything else.  Although they
# are a dependency of the library (so will be created from the message file
# anyway), there is no guarantee as to exactly _when_ in the build they will be
# created.  As the .h file is included in other sources file (so must be
# present when they are compiled), the safest option is to create it first.
BUILT_SOURCES = resolve_messages.h resolve_messages.cc

CLEANFILES = *.gcno *.gcda resolve_messages.cc resolve_messages.h s-messages

lib_LTLIBRARIES = libbundy-resolve.la
libbundy_resolve_la_SOURCES = resolve.h resolve.cc
libbundy_resolve_la_SOURCES += resolve_log.h resolve_log.cc
libbundy_resolve_la_SOURCES += resolver_interface.h
libbundy_resolve_la_SOURCES += resolver_callback.h resolver_callback.cc
libbundy_resolve_la_SOURCES += response_classifier.cc response_classifier.h
libbundy_resolve_la_SOURCES += recursive_query.cc recursive_query.h

nodist_libbundy_resolve_la_SOURCES = resolve_messages.h resolve_messages.cc

libbundy_resolve_la_LIBADD = $(top_builddir)/src/lib/dns/libbundy-dns++.la
libbundy_resolve_la_LIBADD += $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la
libbundy_resolve_la_LIBADD += $(top_builddir)/src/lib/log/libbundy-log.la
libbundy_resolve_la_LIBADD += $(top_builddir)/src/lib/asiodns/libbundy-asiodns.la
libbundy_resolve_la_LIBADD += $(top_builddir)/src/lib/nsas/libbundy-nsas.la

# The message file should be in the distribution.
EXTRA_DIST = resolve_messages.mes

# Note: the ordering matters: -Wno-... must follow -Wextra (defined in
# BUNDY_CXXFLAGS)
libbundy_resolve_la_CXXFLAGS = $(AM_CXXFLAGS)
libbundy_resolve_la_CPPFLAGS = $(AM_CPPFLAGS)
