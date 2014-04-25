SUBDIRS = . tests bench

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += -I$(top_srcdir)/src/bin -I$(top_builddir)/src/bin
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/dns -I$(top_builddir)/src/lib/dns
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/cc -I$(top_builddir)/src/lib/cc
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/asiodns
AM_CPPFLAGS += -I$(top_builddir)/src/lib/asiodns
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/asiolink
AM_CPPFLAGS += -I$(top_builddir)/src/lib/asiolink
AM_CPPFLAGS += $(BOOST_INCLUDES)

AM_CXXFLAGS = $(BUNDY_CXXFLAGS)

if USE_STATIC_LINK
AM_LDFLAGS = -static
endif

pkglibexecdir = $(libexecdir)/@PACKAGE@

CLEANFILES  = *.gcno *.gcda
CLEANFILES += resolver.spec spec_config.h
CLEANFILES += resolver_messages.cc resolver_messages.h s-messages

man_MANS = bundy-resolver.8
DISTCLEANFILES = $(man_MANS)
EXTRA_DIST = $(man_MANS) bundy-resolver.xml resolver_messages.mes

if GENERATE_DOCS

bundy-resolver.8: bundy-resolver.xml
	@XSLTPROC@ --novalid --xinclude --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $(srcdir)/bundy-resolver.xml

else

$(man_MANS):
	@echo Man generation disabled.  Creating dummy $@.  Configure with --enable-generate-docs to enable it.
	@echo Man generation disabled.  Remove this file, configure with --enable-generate-docs, and rebuild BUNDY > $@

endif

resolver.spec: resolver.spec.pre
	$(SED) -e "s|@@LOCALSTATEDIR@@|$(localstatedir)|" resolver.spec.pre >$@

spec_config.h: spec_config.h.pre
	$(SED) -e "s|@@LOCALSTATEDIR@@|$(localstatedir)|" spec_config.h.pre >$@

# Define rule to build logging source files from message file
resolver_messages.h resolver_messages.cc: s-messages

s-messages: resolver_messages.mes
	$(top_builddir)/src/lib/log/compiler/message $(top_srcdir)/src/bin/resolver/resolver_messages.mes
	touch $@

BUILT_SOURCES = spec_config.h resolver_messages.cc resolver_messages.h

pkglibexec_PROGRAMS = bundy-resolver
bundy_resolver_SOURCES = resolver.cc resolver.h
bundy_resolver_SOURCES += resolver_log.cc resolver_log.h
bundy_resolver_SOURCES += response_scrubber.cc response_scrubber.h
bundy_resolver_SOURCES += $(top_builddir)/src/bin/auth/common.h
bundy_resolver_SOURCES += main.cc
bundy_resolver_SOURCES += common.cc common.h

nodist_bundy_resolver_SOURCES = resolver_messages.cc resolver_messages.h


bundy_resolver_LDADD =  $(top_builddir)/src/lib/dns/libbundy-dns++.la
bundy_resolver_LDADD += $(top_builddir)/src/lib/config/libbundy-cfgclient.la
bundy_resolver_LDADD += $(top_builddir)/src/lib/cc/libbundy-cc.la
bundy_resolver_LDADD += $(top_builddir)/src/lib/util/libbundy-util.la
bundy_resolver_LDADD += $(top_builddir)/src/lib/acl/libbundy-dnsacl.la
bundy_resolver_LDADD += $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la
bundy_resolver_LDADD += $(top_builddir)/src/lib/asiodns/libbundy-asiodns.la
bundy_resolver_LDADD += $(top_builddir)/src/lib/asiolink/libbundy-asiolink.la
bundy_resolver_LDADD += $(top_builddir)/src/lib/log/libbundy-log.la
bundy_resolver_LDADD += $(top_builddir)/src/lib/server_common/libbundy-server-common.la
bundy_resolver_LDADD += $(top_builddir)/src/lib/cache/libbundy-cache.la
bundy_resolver_LDADD += $(top_builddir)/src/lib/nsas/libbundy-nsas.la
bundy_resolver_LDADD += $(top_builddir)/src/lib/resolve/libbundy-resolve.la
bundy_resolver_LDFLAGS = -pthread

# TODO: config.h.in is wrong because doesn't honor pkgdatadir
# and can't use @datadir@ because doesn't expand default ${prefix}
bundy_resolverdir = $(pkgdatadir)
bundy_resolver_DATA = resolver.spec
