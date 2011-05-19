SUBDIRS = .

AM_CPPFLAGS = -I$(top_builddir)/src/lib -I$(top_srcdir)/src/lib
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/util -I$(top_builddir)/src/lib/util
AM_CPPFLAGS += -I$(top_srcdir)/src/lib/exceptions -I$(top_builddir)/src/lib/exceptions
AM_CPPFLAGS += $(BOOST_INCLUDES)
AM_CXXFLAGS = $(B10_CXXFLAGS)

if USE_STATIC_LINK
AM_LDFLAGS = -static
endif

CLEANFILES = *.gcno *.gcda

TESTS =
if HAVE_GTEST
TESTS += run_unittests
run_unittests_SOURCES  =
run_unittests_SOURCES += filename_unittest.cc
run_unittests_SOURCES += strutil_unittest.cc
run_unittests_SOURCES += run_unittests.cc
run_unittests_SOURCES += base32hex_unittest.cc
run_unittests_SOURCES += base64_unittest.cc
run_unittests_SOURCES += hex_unittest.cc
run_unittests_SOURCES += sha1_unittest.cc
run_unittests_SOURCES += buffer_unittest.cc
run_unittests_SOURCES += time_utilities_unittest.cc
run_unittests_SOURCES += random_number_generator_unittest.cc
run_unittests_SOURCES += lru_list_unittest.cc
run_unittests_SOURCES += io_utilities_unittest.cc
run_unittests_SOURCES += qid_gen_unittest.cc

run_unittests_CPPFLAGS = $(AM_CPPFLAGS) $(GTEST_INCLUDES)
run_unittests_LDFLAGS = $(AM_LDFLAGS) $(GTEST_LDFLAGS)

run_unittests_LDADD  = $(GTEST_LDADD)
run_unittests_LDADD += $(top_builddir)/src/lib/util/libutil.la
run_unittests_LDADD += $(top_builddir)/src/lib/exceptions/libexceptions.la
endif

noinst_PROGRAMS = $(TESTS)