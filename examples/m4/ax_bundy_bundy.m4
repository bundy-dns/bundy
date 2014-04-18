dnl @synopsis AX_BUNDY_BUNDY
dnl
dnl @summary figure out how to build C++ programs using ISC BUNDY libraries
dnl
dnl If no path to the installed BUNDY header files or libraries is given
dnl via the --with-bundy-include  or --with-bundy-lib option, the macro
dnl searchs under /usr/local/{include, lib}, /usr/pkg/{include, lib},
dnl /opt/{include, lib}, /opt/local/{include, lib} directories, respectively.
dnl
dnl This macro calls:
dnl
dnl   AC_SUBST(BUNDY_CPPFLAGS)
dnl   AC_SUBST(BUNDY_LDFLAGS)
dnl   AC_SUBST(BUNDY_COMMON_LIB)
dnl   AC_SUBST(BUNDY_DNS_LIB)
dnl
dnl If this macro finds CPPFLAGS, LDFLAGS or COMMON_LIB unavailable, it treats
dnl that as a fatal error.
dnl Checks for other BUNDY module libraries are option, as not all
dnl applications need all libraries.  The main configure.ac can handle any
dnl missing library as fatal by checking whether the corresponding
dnl BUNDY_xxx_LIB is defined.
dnl
dnl In addition, it sets the BUNDY_RPATH variable to a usable linker option
dnl to embed the path to the BUNDY library to the programs that are to be
dnl linked with the library.  If the developer wants to use the option,
dnl it can be used as follows:
dnl if test "x$BUNDY_RPATH" != "x"; then
dnl     LDFLAGS="$LDFLAGS $BUNDY_RPATH"
dnl fi

AC_DEFUN([AX_BUNDY_BUNDY], [
AC_REQUIRE([AX_BOOST_INCLUDE])
AC_REQUIRE([AX_BUNDY_RPATH])
AC_LANG_SAVE
AC_LANG([C++])

# Check for BUNDY common headers

AC_ARG_WITH(bundy-include,
  AS_HELP_STRING([--with-bundy-include=PATH],
  [specify a path to BUNDY header files]),
    bundy_inc_path="$withval", bundy_inc_path="no")
# If not specified, try some common paths.
if test "$bundy_inc_path" = "no"; then
   for d in /usr/local /usr/pkg /opt /opt/local
   do
	if test -f $d/include/util/buffer.h; then
	   bundy_inc_path=$d
	   break
	fi
   done
fi
CPPFLAGS_SAVED="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $BOOST_CPPFLAGS" # boost headers will be used in buffer.h
if test "${bundy_inc_path}" != "no"; then
   BUNDY_CPPFLAGS="-I${bundy_inc_path}"
   CPPFLAGS="$CPPFLAGS $BUNDY_CPPFLAGS"
fi
AC_CHECK_HEADERS([util/buffer.h],,
  AC_MSG_ERROR([Missing a commonly used BUNDY header file]))
CPPFLAGS="$CPPFLAGS_SAVED"
AC_SUBST(BUNDY_CPPFLAGS)

# Check for BUNDY libraries
CPPFLAGS_SAVED="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $BOOST_CPPFLAGS $BUNDY_CPPFLAGS"

AC_ARG_WITH(bundy-lib,
  AS_HELP_STRING([--with-bundy-lib=PATH],
  [specify a path to BUNDY library files]),
    bundy_lib_path="$withval", bundy_lib_path="no")
if test $bundy_lib_path != "no"; then
   bundy_lib_dirs=$bundy_lib_path
else
   # If not specified, try some common paths.
   bundy_lib_dirs="/usr/local/lib /usr/pkg/lib /opt/lib /opt/local/lib"
fi

# make sure we have buildable libraries
AC_MSG_CHECKING([for BUNDY common library])
BUNDY_COMMON_LIB="-lbundy-util -lbundy-exceptions"
LDFLAGS_SAVED="$LDFLAGS"
LDFLAGS_CHECK_COMMON="$LDFLAGS $BUNDY_LDFLAGS"
LIBS_SAVED="$LIBS"
LIBS="$LIBS $BUNDY_COMMON_LIB"
for d in $bundy_lib_dirs
do
  LDFLAGS="$LDFLAGS_CHECK_COMMON -L$d"
  AC_TRY_LINK([
#include <util/buffer.h>
],[
bundy::util::OutputBuffer buffer(0);
], [BUNDY_LDFLAGS="-L${d}"
    if test "x$BUNDY_RPATH_FLAG" != "x"; then
       BUNDY_RPATH="${BUNDY_RPATH_FLAG}${d}"
    fi
    ])
  if test "x$BUNDY_LDFLAGS" != "x"; then
     break
  fi
done
if test "x$BUNDY_LDFLAGS" != "x"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
  AC_MSG_ERROR([unable to find required BUNDY libraries])
fi

# restore LIBS once at this point
LIBS="$LIBS_SAVED"

AC_SUBST(BUNDY_LDFLAGS)
AC_SUBST(BUNDY_COMMON_LIB)

# Check per-module BUNDY libraries

# DNS library
AC_MSG_CHECKING([for BUNDY DNS library])
LIBS="$LIBS $BUNDY_COMMON_LIB -lbundy-dns++"
AC_TRY_LINK([
#include <dns/rrtype.h>
],[
bundy::dns::RRType rrtype(1);
], [BUNDY_DNS_LIB="-lbundy-dns++"
    AC_MSG_RESULT(yes)],
   [AC_MSG_RESULT(no)])
LIBS="$LIBS_SAVED"
AC_SUBST(BUNDY_DNS_LIB)

# Restore other flags
CPPFLAGS="$CPPFLAGS_SAVED"
LDFLAGS="$LDFLAGS_SAVED"

AC_LANG_RESTORE
])dnl AX_BUNDY_BUNDY
