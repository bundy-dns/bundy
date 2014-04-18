SUBDIRS = . tests example

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += $(BOOST_INCLUDES)
AM_CXXFLAGS = $(BUNDY_CXXFLAGS)

CLEANFILES = *.gcno *.gcda

noinst_LTLIBRARIES = libbundy-bench.la
libbundy_bench_la_SOURCES = benchmark_util.h benchmark_util.cc
EXTRA_DIST = benchmark.h
