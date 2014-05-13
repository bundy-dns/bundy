dnl @synopsis AX_SQLITE3_FOR_BUNDY
dnl
dnl Test for the sqlite3 library and program, intended to be used within
dnl BUNDY, and to test BUNDY.
dnl
dnl We use pkg-config to look for the sqlite3 library, so the sqlite3
dnl development package with the .pc file must be installed.
dnl
dnl This macro sets SQLITE_CFLAGS and SQLITE_LIBS. It also sets
dnl SQLITE3_PROGRAM to the path of the sqlite3 program, if it is found
dnl in PATH.

AC_DEFUN([AX_SQLITE3_FOR_BUNDY], [

# A special workaround for MacOS X + Homebrew: some latest versions of the OS
# have its own sqlite3 without its developer tools (header files and library),
# so Homebrew installs its own sqlite3 under an uncommon path that pkg-config
# do not search by default.  System specific hack like this is bad, but we
# don't want to force users to struggle for purism.
SAVED_PKG_CONFIG_PATH=$PKG_CONFIG_PATH
if test -d /usr/local/opt/sqlite/lib/pkgconfig; then
  PKG_CONFIG_PATH=/usr/local/opt/sqlite/lib/pkgconfig:${SAVED_PKG_CONFIG_PATH}
  export PKG_CONFIG_PATH
fi

PKG_CHECK_MODULES(SQLITE, sqlite3 >= 3.3.9,
    [have_sqlite="yes"
dnl Determine the SQLite version, used mainly for config.report.
CPPFLAGS_SAVED="$CPPFLAGS"
CPPFLAGS="${CPPFLAGS} $SQLITE_CFLAGS"
AC_MSG_CHECKING([SQLite version])
cat > conftest.c << EOF
#include <sqlite3.h>
AUTOCONF_SQLITE_VERSION=SQLITE_VERSION
EOF

SQLITE_VERSION=`$CPP $CPPFLAGS conftest.c | grep '^AUTOCONF_SQLITE_VERSION=' | $SED -e 's/^AUTOCONF_SQLITE_VERSION=//' -e 's/"//g' 2> /dev/null`
if test -z "$SQLITE_VERSION"; then
  SQLITE_VERSION="unknown"
fi
$RM -f conftest.c
AC_MSG_RESULT([$SQLITE_VERSION])

CPPFLAGS="$CPPFLAGS_SAVED"
    ],have_sqlite="no (sqlite3 not detected)")

# Check for sqlite3 program
AC_PATH_PROG(SQLITE3_PROGRAM, sqlite3, no)
AM_CONDITIONAL(HAVE_SQLITE3_PROGRAM, test "x$SQLITE3_PROGRAM" != "xno")

# TODO: check for _sqlite3.py module

PKG_CONFIG_PATH=$SAVED_PKG_CONFIG_PATH

])dnl AX_SQLITE3_FOR_BUNDY
