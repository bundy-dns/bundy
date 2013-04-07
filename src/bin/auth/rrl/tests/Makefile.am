#SUBDIRS = testdata .

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += -I$(top_srcdir)/src/bine -I$(top_builddir)/src/bin
AM_CPPFLAGS += $(BOOST_INCLUDES)

AM_CXXFLAGS = $(B10_CXXFLAGS)

if USE_STATIC_LINK
AM_LDFLAGS = -static
# Some test cases cannot work with static link.  To selectively disable such
# tests we signal it via a definition.
AM_CPPFLAGS += -DUSE_STATIC_LINK=1
endif

CLEANFILES = *.gcno *.gcda

TESTS_ENVIRONMENT = \
        $(LIBTOOL) --mode=execute $(VALGRIND_COMMAND)

# Do not define global tests, use check-local so
# environment can be set (needed for dynamic loading)
TESTS =
if HAVE_GTEST

noinst_PROGRAMS = run_unittests

run_unittests_SOURCES = run_unittests.cc
run_unittests_SOURCES += rrl_key_unittest.cc
run_unittests_SOURCES += rrl_entry_unittest.cc
run_unittests_SOURCES += rrl_timestamps_unittest.cc
run_unittests_SOURCES += rrl_table_unittest.cc

run_unittests_CPPFLAGS = $(AM_CPPFLAGS) $(GTEST_INCLUDES)
run_unittests_LDFLAGS = $(AM_LDFLAGS) $(GTEST_LDFLAGS)
run_unittests_LDADD = $(top_builddir)/src/lib/asiolink/libb10-asiolink.la
run_unittests_LDADD += $(top_builddir)/src/lib/dns/libb10-dns++.la
run_unittests_LDADD += $(top_builddir)/src/lib/log/libb10-log.la
run_unittests_LDADD += $(top_builddir)/src/lib/util/unittests/libutil_unittests.la
run_unittests_LDADD += ../libauth_rrl.la

run_unittests_LDADD += $(GTEST_LDADD)
run_unittests_LDADD += $(SQLITE_LIBS)

check-local:
	B10_FROM_BUILD=${abs_top_builddir} ./run_unittests

endif
