SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += -DLOCKFILE_DIR=\"${localstatedir}/${PACKAGE_NAME}\"
AM_CPPFLAGS += $(BOOST_INCLUDES)

AM_CXXFLAGS = $(BUNDY_CXXFLAGS)

CLEANFILES = *.gcno *.gcda

noinst_LTLIBRARIES = libbundy-log_interprocess.la

libbundy_log_interprocess_la_SOURCES = interprocess_sync.h
libbundy_log_interprocess_la_SOURCES += interprocess_sync_file.h
libbundy_log_interprocess_la_SOURCES += interprocess_sync_file.cc
libbundy_log_interprocess_la_SOURCES += interprocess_sync_null.h
libbundy_log_interprocess_la_SOURCES += interprocess_sync_null.cc

libbundy_log_interprocess_la_LIBADD  = $(top_builddir)/src/lib/util/threads/libbundy-threads.la

EXTRA_DIST  = README
