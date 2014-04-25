AM_CPPFLAGS = -I$(top_builddir)/src/lib -I$(top_srcdir)/src/lib
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
run_unittests_SOURCES = run_unittests.cc
run_unittests_SOURCES += acl_test.cc
run_unittests_SOURCES += check_test.cc
run_unittests_SOURCES += dns_test.cc
run_unittests_SOURCES += ip_check_unittest.cc
run_unittests_SOURCES += dnsname_check_unittest.cc
run_unittests_SOURCES += loader_test.cc
run_unittests_SOURCES += logcheck.h
run_unittests_SOURCES += creators.h
run_unittests_SOURCES += logic_check_test.cc
run_unittests_SOURCES += sockaddr.h

run_unittests_CPPFLAGS = $(AM_CPPFLAGS) $(GTEST_INCLUDES)
run_unittests_LDFLAGS = $(AM_LDFLAGS) $(GTEST_LDFLAGS)

run_unittests_LDADD = $(GTEST_LDADD)
run_unittests_LDADD += $(top_builddir)/src/lib/util/unittests/libutil_unittests.la
run_unittests_LDADD += $(top_builddir)/src/lib/acl/libbundy-acl.la
run_unittests_LDADD += $(top_builddir)/src/lib/util/libbundy-util.la
run_unittests_LDADD += $(top_builddir)/src/lib/cc/libbundy-cc.la
run_unittests_LDADD += $(top_builddir)/src/lib/dns/libbundy-dns++.la
run_unittests_LDADD += $(top_builddir)/src/lib/log/libbundy-log.la
run_unittests_LDADD += $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la
run_unittests_LDADD += $(top_builddir)/src/lib/acl/libbundy-dnsacl.la
endif

noinst_PROGRAMS = $(TESTS)
