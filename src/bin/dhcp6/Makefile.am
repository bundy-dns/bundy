SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += -I$(top_srcdir)/src/bin -I$(top_builddir)/src/bin
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/cc -I$(top_builddir)/src/lib/cc
AM_CPPFLAGS += $(BOOST_INCLUDES)

AM_CXXFLAGS = $(BUNDY_CXXFLAGS)
if USE_CLANGPP
# Disable unused parameter warning caused by some Boost headers when compiling with clang
AM_CXXFLAGS += -Wno-unused-parameter
endif

if USE_STATIC_LINK
AM_LDFLAGS = -static
endif

pkglibexecdir = $(libexecdir)/@PACKAGE@

CLEANFILES = spec_config.h dhcp6_messages.h dhcp6_messages.cc s-messages

man_MANS = bundy-dhcp6.8
DISTCLEANFILES = $(man_MANS)
EXTRA_DIST = $(man_MANS) bundy-dhcp6.xml dhcp6.spec

if GENERATE_DOCS

bundy-dhcp6.8: bundy-dhcp6.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ \
        http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl \
        $(srcdir)/bundy-dhcp6.xml

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

spec_config.h: spec_config.h.pre
	$(SED) -e "s|@@LOCALSTATEDIR@@|$(localstatedir)|" spec_config.h.pre >$@

dhcp6_messages.h dhcp6_messages.cc: s-messages

s-messages: dhcp6_messages.mes
	$(top_builddir)/src/lib/log/compiler/message $(top_srcdir)/src/bin/dhcp6/dhcp6_messages.mes
	touch $@

BUILT_SOURCES = spec_config.h dhcp6_messages.h dhcp6_messages.cc

pkglibexec_PROGRAMS = bundy-dhcp6

bundy_dhcp6_SOURCES  = main.cc
bundy_dhcp6_SOURCES += ctrl_dhcp6_srv.cc ctrl_dhcp6_srv.h
bundy_dhcp6_SOURCES += config_parser.cc config_parser.h
bundy_dhcp6_SOURCES += dhcp6_log.cc dhcp6_log.h
bundy_dhcp6_SOURCES += dhcp6_srv.cc dhcp6_srv.h

nodist_bundy_dhcp6_SOURCES = dhcp6_messages.h dhcp6_messages.cc
EXTRA_DIST += dhcp6_messages.mes

bundy_dhcp6_LDADD  = $(top_builddir)/src/lib/asiolink/libbundy-asiolink.la
bundy_dhcp6_LDADD += $(top_builddir)/src/lib/cc/libbundy-cc.la
bundy_dhcp6_LDADD += $(top_builddir)/src/lib/config/libbundy-cfgclient.la
bundy_dhcp6_LDADD += $(top_builddir)/src/lib/dhcp/libbundy-dhcp++.la
bundy_dhcp6_LDADD += $(top_builddir)/src/lib/dhcp_ddns/libbundy-dhcp_ddns.la
bundy_dhcp6_LDADD += $(top_builddir)/src/lib/dhcpsrv/libbundy-dhcpsrv.la
bundy_dhcp6_LDADD += $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la
bundy_dhcp6_LDADD += $(top_builddir)/src/lib/log/libbundy-log.la
bundy_dhcp6_LDADD += $(top_builddir)/src/lib/util/libbundy-util.la
bundy_dhcp6_LDADD += $(top_builddir)/src/lib/hooks/libbundy-hooks.la

bundy_dhcp6dir = $(pkgdatadir)
bundy_dhcp6_DATA = dhcp6.spec
