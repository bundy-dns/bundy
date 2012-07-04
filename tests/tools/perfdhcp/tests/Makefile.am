SUBDIRS = .

AM_CPPFLAGS = -I$(top_builddir)/src/lib -I$(top_srcdir)/src/lib
AM_CPPFLAGS += $(BOOST_INCLUDES)
AM_CXXFLAGS = $(B10_CXXFLAGS)

if USE_STATIC_LINK
AM_LDFLAGS = -static
endif

CLEANFILES = *.gcno *.gcda

TESTS_ENVIRONMENT = \
        $(LIBTOOL) --mode=execute $(VALGRIND_COMMAND)

TESTS =
if HAVE_GTEST
TESTS += run_unittests
run_unittests_SOURCES  = run_unittests.cc
run_unittests_SOURCES += command_options_unittest.cc
run_unittests_SOURCES += perf_pkt6_unittest.cc
run_unittests_SOURCES += perf_pkt4_unittest.cc
run_unittests_SOURCES += localized_option_unittest.cc
run_unittests_SOURCES += $(top_builddir)/tests/tools/perfdhcp/command_options.cc
run_unittests_SOURCES += $(top_builddir)/tests/tools/perfdhcp/pkt_transform.cc
run_unittests_SOURCES += $(top_builddir)/tests/tools/perfdhcp/perf_pkt6.cc
run_unittests_SOURCES += $(top_builddir)/tests/tools/perfdhcp/perf_pkt4.cc

run_unittests_CPPFLAGS = $(AM_CPPFLAGS) $(GTEST_INCLUDES)
run_unittests_LDFLAGS  = $(AM_LDFLAGS)  $(GTEST_LDFLAGS)

if USE_CLANGPP
# Disable unused parameter warning caused by some of the
# Boost headers when compiling with clang.
run_unittests_CXXFLAGS = -Wno-unused-parameter
endif

run_unittests_LDADD  = $(GTEST_LDADD)
run_unittests_LDADD += $(top_builddir)/src/lib/util/libutil.la
run_unittests_LDADD += $(top_builddir)/src/lib/exceptions/libexceptions.la
run_unittests_LDADD += $(top_builddir)/src/lib/asiolink/libasiolink.la
run_unittests_LDADD += $(top_builddir)/src/lib/dhcp/libdhcp++.la
run_unittests_LDADD += $(top_builddir)/src/lib/util/unittests/libutil_unittests.la
endif

noinst_PROGRAMS = $(TESTS)