AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += $(BOOST_INCLUDES)

AM_CXXFLAGS = $(B10_CXXFLAGS)

CLEANFILES = *.gcno *.gcda

TESTS_ENVIRONMENT = $(LIBTOOL) --mode=execute $(VALGRIND_COMMAND)

# Do not define global tests, use check-local so
# environment can be set (needed for dynamic loading)
TESTS =
if HAVE_GTEST
TESTS += run_unittests

run_unittests_SOURCES = run_unittests.cc
run_unittests_SOURCES += rrl_key_unittest.cc
run_unittests_SOURCES += rrl_timestamps_unittest.cc
run_unittests_SOURCES += rrl_name_pool_unittest.cc

run_unittests_CPPFLAGS = $(AM_CPPFLAGS) $(GTEST_INCLUDES)
run_unittests_LDFLAGS = $(AM_LDFLAGS) $(GTEST_LDFLAGS)
run_unittests_LDADD = $(top_builddir)/src/lib/dns/libbundy-dns++.la
run_unittests_LDADD += $(top_builddir)/src/lib/util/unittests/libutil_unittests.la
run_unittests_LDADD += $(top_builddir)/src/lib/auth/libbundy-auth.la

run_unittests_LDADD += $(GTEST_LDADD)
endif
noinst_PROGRAMS = $(TESTS)
