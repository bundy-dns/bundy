AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += -I$(top_srcdir)/src/bin -I$(top_builddir)/src/bin
AM_CPPFLAGS += $(BOOST_INCLUDES)

AM_CXXFLAGS = $(BUNDY_CXXFLAGS)

if USE_STATIC_LINK
AM_LDFLAGS = -static
endif

CLEANFILES = *.gcno *.gcda

noinst_PROGRAMS = query_bench
query_bench_SOURCES = query_bench.cc
query_bench_SOURCES += ../query.h  ../query.cc
query_bench_SOURCES += ../auth_srv.h ../auth_srv.cc
query_bench_SOURCES += ../auth_config.h ../auth_config.cc
query_bench_SOURCES += ../statistics.h ../statistics.cc ../statistics_items.h
query_bench_SOURCES += ../auth_log.h ../auth_log.cc
query_bench_SOURCES += ../datasrc_config.h ../datasrc_config.cc

nodist_query_bench_SOURCES = ../auth_messages.h ../auth_messages.cc

query_bench_LDADD = $(top_builddir)/src/lib/dns/libbundy-dns++.la
query_bench_LDADD += $(top_builddir)/src/lib/util/libbundy-util.la
query_bench_LDADD += $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la
query_bench_LDADD += $(top_builddir)/src/lib/bench/libbundy-bench.la
query_bench_LDADD += $(top_builddir)/src/lib/datasrc/libbundy-datasrc.la
query_bench_LDADD += $(top_builddir)/src/lib/config/libbundy-cfgclient.la
query_bench_LDADD += $(top_builddir)/src/lib/cc/libbundy-cc.la
query_bench_LDADD += $(top_builddir)/src/lib/xfr/libbundy-xfr.la
query_bench_LDADD += $(top_builddir)/src/lib/log/libbundy-log.la
query_bench_LDADD += $(top_builddir)/src/lib/nsas/libbundy-nsas.la
query_bench_LDADD += $(top_builddir)/src/lib/asiolink/libbundy-asiolink.la
query_bench_LDADD += $(top_builddir)/src/lib/server_common/libbundy-server-common.la
query_bench_LDADD += $(top_builddir)/src/lib/asiodns/libbundy-asiodns.la
query_bench_LDADD += $(top_builddir)/src/lib/util/threads/libbundy-threads.la
query_bench_LDADD += $(SQLITE_LIBS)

