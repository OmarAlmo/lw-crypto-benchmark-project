# AES Crypt
# Copyright (C) 2007, 2008, 2009, 2013
# Copyright (C) 2013, 2014 Alon Bar-Lev <alon.barlev@gmail.com>
#
# This software is licensed as "freeware."  Permission to distribute
# this software in source and binary forms is hereby granted without a
# fee.  THIS SOFTWARE IS PROVIDED 'AS IS' AND WITHOUT ANY EXPRESSED OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
# THE AUTHOR SHALL NOT BE HELD LIABLE FOR ANY DAMAGES RESULTING FROM
# THE USE OF THIS SOFTWARE, EITHER DIRECTLY OR INDIRECTLY, INCLUDING,
# BUT NOT LIMITED TO, LOSS OF DATA OR DATA BEING RENDERED INACCURATE.
#

AC_PREREQ(2.60)

AC_INIT([aescrypt], [3.0.11_master])
AC_DEFINE([AESCRYPT_VERSION_RESOURCE], [3,0,11,0], [Version in windows resource format])
PACKAGE_RPM_RELEASE=1
AC_SUBST([PACKAGE_RPM_RELEASE])

AC_CONFIG_AUX_DIR([.])
AM_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([src/aescrypt.c])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AM_PROG_CC_C_O
AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

AC_ARG_ENABLE(
	[gui],
	[AS_HELP_STRING([--disable-gui], [disable gui usage @<:@default=yes@:>@])],
	,
	[enable_gui="yes"]
)

AC_ARG_ENABLE(
	[iconv],
	[AS_HELP_STRING([--disable-iconv], [disable iconv usage @<:@default=yes@:>@])],
	,
	[enable_iconv="yes"]
)

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict], [enable strict compiler warnings (debugging option) @<:@default=no@:>@])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic], [enable pedantic compiler warnings (debugging option) @<:@default=no@:>@])],
	,
	[enable_pedantic="no"]
)

case "$host" in
	*-mingw*)
		CPPFLAGS="${CPPFLAGS} -DWINDOWS_LEAN_AND_MEAN"
		WINDOWS=yes
		;;
esac

AC_PROG_INSTALL
AC_PROG_MAKE_SET

#
# Libtool
#
ifdef(
	[LT_INIT],
	[
		LT_INIT([win32-dll])
		LT_LANG([Windows Resource])
	],
	[
		AC_LIBTOOL_WIN32_DLL
		AC_LIBTOOL_RC
		AC_PROG_LIBTOOL
	]
)

AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T

if test "${enable_iconv}" = "yes"; then
	AC_DEFINE([ENABLE_ICONV], [1], [Enable iconv usage])
	AC_SEARCH_LIBS(
		[iconv],
		[iconv],
	)
fi

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes"
	CFLAGS="${CFLAGS} -pedantic"
	test "${WINDOWS}" != "yes" && CFLAGS="${CFLAGS} -ansi"
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
fi

AC_DEFINE_UNQUOTED([PACKAGE_DATE], ["$(date -u)"], [build date])

AC_SUBST([applicationsdir], ["\$(datarootdir)/applications"])
AC_SUBST([iconsdir], ["\$(datarootdir)/icons/${PACKAGE_NAME}"])

AM_CONDITIONAL([ENABLE_GUI], [test "${enable_gui}" = "yes"])
AM_CONDITIONAL([WINDOWS], [test "${WINDOWS}" = "yes"])

AC_CONFIG_FILES([
	Makefile
	aescrypt.spec
	src/Makefile
	gui/Makefile
	man/Makefile
])
AC_OUTPUT

