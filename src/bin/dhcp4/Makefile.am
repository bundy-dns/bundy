SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += -I$(top_srcdir)/src/bin -I$(top_builddir)/src/bin
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

CLEANFILES  = *.gcno *.gcda spec_config.h dhcp4_messages.h dhcp4_messages.cc s-messages

man_MANS = bundy-dhcp4.8
DISTCLEANFILES = $(man_MANS)
EXTRA_DIST = $(man_MANS) bundy-dhcp4.xml dhcp4.spec

if GENERATE_DOCS
bundy-dhcp4.8: bundy-dhcp4.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ \
        http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl \
	$(srcdir)/bundy-dhcp4.xml

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

spec_config.h: spec_config.h.pre
	$(SED) -e "s|@@LOCALSTATEDIR@@|$(localstatedir)|" spec_config.h.pre >$@

dhcp4_messages.h dhcp4_messages.cc: s-messages

s-messages: dhcp4_messages.mes
	$(top_builddir)/src/lib/log/compiler/message $(top_srcdir)/src/bin/dhcp4/dhcp4_messages.mes
	touch $@

BUILT_SOURCES = spec_config.h dhcp4_messages.h dhcp4_messages.cc

pkglibexec_PROGRAMS = bundy-dhcp4

bundy_dhcp4_SOURCES  = main.cc
bundy_dhcp4_SOURCES += ctrl_dhcp4_srv.cc ctrl_dhcp4_srv.h
bundy_dhcp4_SOURCES += config_parser.cc config_parser.h
bundy_dhcp4_SOURCES += dhcp4_log.cc dhcp4_log.h
bundy_dhcp4_SOURCES += dhcp4_srv.cc dhcp4_srv.h

nodist_bundy_dhcp4_SOURCES = dhcp4_messages.h dhcp4_messages.cc
EXTRA_DIST += dhcp4_messages.mes

bundy_dhcp4_LDADD  = $(top_builddir)/src/lib/dhcp/libbundy-dhcp++.la
bundy_dhcp4_LDADD += $(top_builddir)/src/lib/dhcp_ddns/libbundy-dhcp_ddns.la
bundy_dhcp4_LDADD += $(top_builddir)/src/lib/util/libbundy-util.la
bundy_dhcp4_LDADD += $(top_builddir)/src/lib/dhcpsrv/libbundy-dhcpsrv.la
bundy_dhcp4_LDADD += $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la
bundy_dhcp4_LDADD += $(top_builddir)/src/lib/asiolink/libbundy-asiolink.la
bundy_dhcp4_LDADD += $(top_builddir)/src/lib/log/libbundy-log.la
bundy_dhcp4_LDADD += $(top_builddir)/src/lib/config/libbundy-cfgclient.la
bundy_dhcp4_LDADD += $(top_builddir)/src/lib/cc/libbundy-cc.la
bundy_dhcp4_LDADD += $(top_builddir)/src/lib/hooks/libbundy-hooks.la

bundy_dhcp4dir = $(pkgdatadir)
bundy_dhcp4_DATA = dhcp4.spec
