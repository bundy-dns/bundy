SUBDIRS = . tests
AM_CXXFLAGS = $(BUNDY_CXXFLAGS)

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += $(BOOST_INCLUDES) $(MULTITHREADING_FLAG)

lib_LTLIBRARIES = libbundy-threads.la
libbundy_threads_la_SOURCES  = sync.h sync.cc
libbundy_threads_la_SOURCES += thread.h thread.cc
libbundy_threads_la_LIBADD  = $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la
libbundy_threads_la_LIBADD += $(PTHREAD_LDFLAGS)

CLEANFILES = *.gcno *.gcda
