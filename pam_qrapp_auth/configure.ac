AC_PREREQ(2.61)
AC_INIT(pam_qrapp_auth, 0.0.1, azadsagar@hotmail.com)
AC_CONFIG_SRCDIR([src/pam_qrapp_auth.c])
AC_CONFIG_AUX_DIR([build])
AC_CONFIG_MACRO_DIR([build])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR
LT_INIT


# Checks for libraries.
AC_CHECK_LIB([pam], [pam_get_item], [], [exit 1])
AC_CHECK_LIB([qrencode], [QRcode_encodeData], [], [exit 1])
AC_CHECK_LIB([websockets], [lws_service], [], [exit 1])

# Checks for header files.
AC_CHECK_HEADERS([sys/fsuid.h])
AC_CHECK_FUNCS([ \
        explicit_bzero \
        setfsuid \
        setfsgid \
])

AC_CHECK_HEADERS_ONCE([security/pam_appl.h])
# On Solaris at least, <security/pam_modules.h> requires <security/pam_appl.h>
# to be included first
AC_CHECK_HEADER([security/pam_modules.h], [], [], \
		[#ifdef HAVE_SECURITY_PAM_APPL_H
		# include <security/pam_appl.h>
		#endif
		])
AC_CHECK_LIB([pam], [pam_get_user], [:])
AS_IF([test "x$ac_cv_header_security_pam_modules_h" = "xno" \
       -o "x$ac_cv_lib_pam_pam_get_user" = "xno"], [
  AC_MSG_ERROR([Unable to find the PAM library or the PAM header files])
])

AC_MSG_CHECKING([whether certain PAM functions require const arguments])
AC_LANG_PUSH(C)
# Force test to bail if const isn't needed
AC_LANG_WERROR
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
	#include <security/pam_appl.h>
	#include <security/pam_modules.h>
]],[[
	const void **item = 0;
	int dummy = 0;
	/*
	 * since pam_handle_t is opaque on at least some platforms, give it
	 * a non-NULL dummy value
	 */
	 const pam_handle_t *ph = (const pam_handle_t *)&dummy;
	(void) pam_get_item(ph, 0, item);
]])],[AC_DEFINE([PAM_CONST], [const], \
	[Define if certain PAM functions require const arguments])
		AC_MSG_RESULT([yes])],
	[AC_DEFINE([PAM_CONST], [], \
	[Prevent certain PAM functions from using const arguments])
	AC_MSG_RESULT([no])])


	AC_MSG_CHECKING(whether compiler understands -Wall)
	old_CFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS -Wall"
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
	  AC_MSG_RESULT(yes),
	  AC_MSG_RESULT(no)
	  CFLAGS="$old_CFLAGS")

AC_LANG_POP(C)



AC_SEARCH_LIBS([dlopen], [dl])
# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([pam_syslog vsyslog])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT

echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
