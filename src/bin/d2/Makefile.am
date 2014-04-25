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

CLEANFILES  = *.gcno *.gcda spec_config.h d2_messages.h d2_messages.cc s-messages

man_MANS = bundy-dhcp-ddns.8
DISTCLEANFILES = $(man_MANS)
EXTRA_DIST = $(man_MANS) bundy-dhcp-ddns.xml dhcp-ddns.spec

if GENERATE_DOCS
bundy-dhcp-ddns.8: bundy-dhcp-ddns.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ \
        http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl \
	$(srcdir)/bundy-dhcp-ddns.xml

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

spec_config.h: spec_config.h.pre
	$(SED) -e "s|@@LOCALSTATEDIR@@|$(localstatedir)|" spec_config.h.pre >$@

d2_messages.h d2_messages.cc: s-messages

s-messages: d2_messages.mes
	$(top_builddir)/src/lib/log/compiler/message $(top_srcdir)/src/bin/d2/d2_messages.mes
	touch $@

BUILT_SOURCES = spec_config.h d2_messages.h d2_messages.cc

pkglibexec_PROGRAMS = bundy-dhcp-ddns

bundy_dhcp_ddns_SOURCES  = main.cc
bundy_dhcp_ddns_SOURCES += d2_asio.h
bundy_dhcp_ddns_SOURCES += d2_log.cc d2_log.h
bundy_dhcp_ddns_SOURCES += d2_process.cc d2_process.h
bundy_dhcp_ddns_SOURCES += d_controller.cc d_controller.h
bundy_dhcp_ddns_SOURCES += d2_controller.cc d2_controller.h
bundy_dhcp_ddns_SOURCES += d_cfg_mgr.cc d_cfg_mgr.h
bundy_dhcp_ddns_SOURCES += d2_config.cc d2_config.h
bundy_dhcp_ddns_SOURCES += d2_cfg_mgr.cc d2_cfg_mgr.h
bundy_dhcp_ddns_SOURCES += d2_queue_mgr.cc d2_queue_mgr.h
bundy_dhcp_ddns_SOURCES += d2_update_message.cc d2_update_message.h
bundy_dhcp_ddns_SOURCES += d2_update_mgr.cc d2_update_mgr.h
bundy_dhcp_ddns_SOURCES += d2_zone.cc d2_zone.h
bundy_dhcp_ddns_SOURCES += dns_client.cc dns_client.h
bundy_dhcp_ddns_SOURCES += labeled_value.cc labeled_value.h
bundy_dhcp_ddns_SOURCES += nc_add.cc nc_add.h
bundy_dhcp_ddns_SOURCES += nc_remove.cc nc_remove.h
bundy_dhcp_ddns_SOURCES += nc_trans.cc nc_trans.h
bundy_dhcp_ddns_SOURCES += state_model.cc state_model.h

nodist_bundy_dhcp_ddns_SOURCES = d2_messages.h d2_messages.cc
EXTRA_DIST += d2_messages.mes

bundy_dhcp_ddns_LDADD = $(top_builddir)/src/lib/log/libbundy-log.la
bundy_dhcp_ddns_LDADD += $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la
bundy_dhcp_ddns_LDADD += $(top_builddir)/src/lib/cc/libbundy-cc.la
bundy_dhcp_ddns_LDADD += $(top_builddir)/src/lib/asiodns/libbundy-asiodns.la
bundy_dhcp_ddns_LDADD += $(top_builddir)/src/lib/asiolink/libbundy-asiolink.la
bundy_dhcp_ddns_LDADD += $(top_builddir)/src/lib/config/libbundy-cfgclient.la
bundy_dhcp_ddns_LDADD += $(top_builddir)/src/lib/dhcp_ddns/libbundy-dhcp_ddns.la
bundy_dhcp_ddns_LDADD += $(top_builddir)/src/lib/dhcp/libbundy-dhcp++.la
bundy_dhcp_ddns_LDADD += $(top_builddir)/src/lib/dhcpsrv/libbundy-dhcpsrv.la
bundy_dhcp_ddns_LDADD += $(top_builddir)/src/lib/dns/libbundy-dns++.la
bundy_dhcp_ddns_LDADD += $(top_builddir)/src/lib/util/libbundy-util.la
bundy_dhcp_ddns_LDADD += $(top_builddir)/src/lib/hooks/libbundy-hooks.la

bundy_dhcp_ddnsdir = $(pkgdatadir)
bundy_dhcp_ddns_DATA = dhcp-ddns.spec
