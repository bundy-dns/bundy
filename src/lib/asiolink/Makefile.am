SUBDIRS = . tests

AM_CPPFLAGS = -I$(top_srcdir)/src/lib -I$(top_builddir)/src/lib
AM_CPPFLAGS += $(BOOST_INCLUDES)

AM_CXXFLAGS = $(BUNDY_CXXFLAGS)

CLEANFILES = *.gcno *.gcda

# This is a wrapper library.

# The ASIO header files have some code fragments that would hit
# gcc's unused-parameter warning, which would make the build fail
# with -Werror (our default setting).

lib_LTLIBRARIES = libbundy-asiolink.la

libbundy_asiolink_la_LDFLAGS = -no-undefined -version-info 1:0:1

libbundy_asiolink_la_SOURCES  = asiolink.h
libbundy_asiolink_la_SOURCES += dummy_io_cb.h
libbundy_asiolink_la_SOURCES += interval_timer.cc interval_timer.h
libbundy_asiolink_la_SOURCES += io_address.cc io_address.h
libbundy_asiolink_la_SOURCES += io_asio_socket.h
libbundy_asiolink_la_SOURCES += io_endpoint.cc io_endpoint.h
libbundy_asiolink_la_SOURCES += io_error.h
libbundy_asiolink_la_SOURCES += io_message.h
libbundy_asiolink_la_SOURCES += io_service.h io_service.cc
libbundy_asiolink_la_SOURCES += io_socket.h io_socket.cc
libbundy_asiolink_la_SOURCES += simple_callback.h
libbundy_asiolink_la_SOURCES += tcp_endpoint.h
libbundy_asiolink_la_SOURCES += tcp_socket.h
libbundy_asiolink_la_SOURCES += udp_endpoint.h
libbundy_asiolink_la_SOURCES += udp_socket.h
libbundy_asiolink_la_SOURCES += local_socket.h local_socket.cc

# Note: the ordering matters: -Wno-... must follow -Wextra (defined in
# BUNDY_CXXFLAGS)
libbundy_asiolink_la_CXXFLAGS = $(AM_CXXFLAGS)
libbundy_asiolink_la_CPPFLAGS = $(AM_CPPFLAGS)
libbundy_asiolink_la_LIBADD = $(top_builddir)/src/lib/exceptions/libbundy-exceptions.la

# IOAddress is sometimes used in user-library code
libbundy_asiolink_includedir = $(pkgincludedir)/asiolink
libbundy_asiolink_include_HEADERS = io_address.h
