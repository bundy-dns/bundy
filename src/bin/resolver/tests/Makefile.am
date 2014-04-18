AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += -I$(top_builddir)/src/lib/dns -I$(top_srcdir)/src/bin
AM_CPPFLAGS += -I$(top_builddir)/src/lib/cc
AM_CPPFLAGS += -I$(top_builddir)/src/bin/resolver
AM_CPPFLAGS += -DTEST_DATA_DIR=\"$(top_srcdir)/src/lib/testutils/testdata\"
AM_CPPFLAGS += -DTEST_DATA_BUILDDIR=\"$(abs_top_builddir)/src/lib/testutils/testdata\"
AM_CPPFLAGS += $(BOOST_INCLUDES)

AM_CXXFLAGS = $(BUNDY_CXXFLAGS)

if USE_STATIC_LINK
AM_LDFLAGS = -static
endif

CLEANFILES = *.gcno *.gcda

TESTS_ENVIRONMENT = \
        $(LIBTOOL) --mode=execute $(VALGRIND_COMMAND)

TESTS =
if HAVE_GTEST
TESTS += run_unittests

run_unittests_SOURCES = $(top_srcdir)/src/lib/dns/tests/unittest_util.h
run_unittests_SOURCES += $(top_srcdir)/src/lib/dns/tests/unittest_util.cc
run_unittests_SOURCES += ../resolver.h ../resolver.cc
run_unittests_SOURCES += ../resolver_log.h ../resolver_log.cc
run_unittests_SOURCES += ../response_scrubber.h ../response_scrubber.cc
run_unittests_SOURCES += resolver_unittest.cc
run_unittests_SOURCES += resolver_config_unittest.cc
run_unittests_SOURCES += response_scrubber_unittest.cc
run_unittests_SOURCES += run_unittests.cc

nodist_run_unittests_SOURCES = ../resolver_messages.h ../resolver_messages.cc

run_unittests_CPPFLAGS = $(AM_CPPFLAGS) $(GTEST_INCLUDES)
run_unittests_LDFLAGS  = $(AM_LDFLAGS)  $(GTEST_LDFLAGS)

run_unittests_LDADD  = $(GTEST_LDADD)
run_unittests_LDADD += $(top_builddir)/src/lib/testutils/libbundy-testutils.la
run_unittests_LDADD += $(top_builddir)/src/lib/dns/libbundy-dns++.la
run_unittests_LDADD += $(top_builddir)/src/lib/asiodns/libbundy-asiodns.la
run_unittests_LDADD += $(top_builddir)/src/lib/asiolink/libbundy-asiolink.la
run_unittests_LDADD += $(top_builddir)/src/lib/config/libbundy-cfgclient.la
run_unittests_LDADD += $(top_builddir)/src/lib/acl/libbundy-dnsacl.la
run_unittests_LDADD += $(top_builddir)/src/lib/cc/libbundy-cc.la
run_unittests_LDADD += $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la
run_unittests_LDADD += $(top_builddir)/src/lib/log/libbundy-log.la
run_unittests_LDADD += $(top_builddir)/src/lib/server_common/libbundy-server-common.la
run_unittests_LDADD += $(top_builddir)/src/lib/resolve/libbundy-resolve.la
run_unittests_LDADD += $(top_builddir)/src/lib/cache/libbundy-cache.la
run_unittests_LDADD += $(top_builddir)/src/lib/nsas/libbundy-nsas.la
run_unittests_LDADD += $(top_builddir)/src/lib/acl/libbundy-acl.la
run_unittests_LDADD += $(top_builddir)/src/lib/util/libbundy-util.la
run_unittests_LDADD += $(top_builddir)/src/lib/util/unittests/libutil_unittests.la

# Note the ordering matters: -Wno-... must follow -Wextra (defined in
# BUNDY_CXXFLAGS
run_unittests_CXXFLAGS = $(AM_CXXFLAGS)
if USE_GXX
run_unittests_CXXFLAGS += -Wno-unused-parameter
endif
endif

noinst_PROGRAMS = $(TESTS)
