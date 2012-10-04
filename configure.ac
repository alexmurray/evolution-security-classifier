AC_INIT([evolution-security-classifier],[0.1])
AC_CONFIG_SRCDIR(src)

AM_INIT_AUTOMAKE
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

dnl ******************************
dnl Compiler Warning Flags
dnl ******************************
AS_COMPILER_FLAGS(WARNING_FLAGS,
	"-DPANGO_DISABLE_DEPRECATED
	-DGDK_PIXBUF_DISABLE_DEPRECATED
	-DGDK_DISABLE_DEPRECATED
	-DG_DISABLE_SINGLE_INCLUDES
	-DGTK_DISABLE_SINGLE_INCLUDES
	-DGSEAL_ENABLE
	-Wall -Wextra
	-Wno-missing-field-initializers
	-Wno-sign-compare
	-Wno-unused-parameter
	-Wdeclaration-after-statement
	-Werror-implicit-function-declaration
	-Wformat-security -Winit-self
	-Wmissing-declarations -Wmissing-include-dirs
	-Wmissing-noreturn -Wnested-externs -Wpointer-arith
	-Wredundant-decls -Wundef -Wwrite-strings")
AC_SUBST(WARNING_FLAGS)

CFLAGS="$CFLAGS $WARNING_FLAGS"
#LDFLAGS="$LDFLAGS -Wl,--no-undefined"

AC_CANONICAL_HOST

AM_MAINTAINER_MODE

dnl make sure we keep ACLOCAL_FLAGS around for maintainer builds to work
AC_SUBST(ACLOCAL_AMFLAGS, "\${ACLOCAL_FLAGS}")

IT_PROG_INTLTOOL([0.35.0])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CXX
#AC_PROG_CXXCPP
AC_SEARCH_LIBS([strerror],[cposix])
AC_HEADER_STDC
AC_DISABLE_STATIC([])
LT_INIT

GNOME_COMPILE_WARNINGS

GLIB_GSETTINGS

dnl base packages and versions
LIBGLIB_REQUIRED=2.30.2
LIBGTK_REQUIRED=3.0.0
EVOLUTION_REQUIRED=3.4.0

PKG_CHECK_MODULES(SECURITY_CLASSIFIER_EPLUGIN,
[  glib-2.0 >= $LIBGLIB_REQUIRED dnl
   gtk+-3.0 >= $LIBGTK_REQUIRED dnl
   libevolution-utils >= $EVOLUTION_REQUIRED dnl
   evolution-plugin-3.0 >= $EVOLUTION_REQUIRED dnl
   evolution-shell-3.0 >= $EVOLUTION_REQUIRED dnl
   libebook-1.2 dnl
])

dnl get the plugin and error install paths
PKG_PROG_PKG_CONFIG
PLUGIN_DIR=`$PKG_CONFIG --variable=plugindir evolution-plugin-3.0 2>/dev/null`
AC_SUBST(PLUGIN_DIR)
ERROR_DIR=`$PKG_CONFIG --variable=errordir evolution-plugin-3.0 2>/dev/null`
AC_SUBST(ERROR_DIR)

dnl I18n stuff
AC_PATH_PROG(GETTEXT, gettext, no)
if test "x$GETTEXT" = "xno"; then
	AC_MSG_ERROR(Package gettext not installed)
fi

GETTEXT_PACKAGE=evolution-security-classifier
AC_SUBST(GETTEXT_PACKAGE)
AM_GLIB_GNU_GETTEXT
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [definition of GETTEXT_PACKAGE])
AM_GLIB_DEFINE_LOCALEDIR(GNOMELOCALEDIR)
LOCALEDIR=$localedir
AC_SUBST(LOCALEDIR)

SOEXT='.so'
AC_SUBST(SOEXT)

# Generated files from automake
AC_CONFIG_FILES([
	Makefile
	data/Makefile
	src/Makefile
	po/Makefile.in
])

AC_OUTPUT
