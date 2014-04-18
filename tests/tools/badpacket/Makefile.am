SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/log -I$(top_builddir)/src/lib/log
AM_CPPFLAGS += $(BOOST_INCLUDES)

AM_CXXFLAGS = $(BUNDY_CXXFLAGS)

if USE_STATIC_LINK
AM_LDFLAGS = -static
endif

CLEANFILES = *.gcno *.gcda

noinst_PROGRAMS  = badpacket
badpacket_SOURCES  = badpacket.cc
badpacket_SOURCES += command_options.cc command_options.h
badpacket_SOURCES += header_flags.h
badpacket_SOURCES += option_info.cc option_info.h
badpacket_SOURCES += scan.cc scan.h
badpacket_SOURCES += version.h

badpacket_CXXFLAGS = $(AM_CXXFLAGS)

badpacket_LDADD  = $(top_builddir)/src/lib/asiodns/libbundy-asiodns.la
badpacket_LDADD += $(top_builddir)/src/lib/dns/libbundy-dns++.la
badpacket_LDADD += $(top_builddir)/src/lib/asiolink/libbundy-asiolink.la
badpacket_LDADD += $(top_builddir)/src/lib/log/libbundy-log.la
badpacket_LDADD += $(top_builddir)/src/lib/util/libbundy-util.la
badpacket_LDADD += $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la
