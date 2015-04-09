AC_PREREQ([2.59])
AC_INIT([isaac], [0.1], [kaian@irontec.com], [isaac], [http://www.irontec.com/])
AM_INIT_AUTOMAKE([1.9])
AM_INIT_AUTOMAKE([subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_HEADERS([config.h])
AC_COPYRIGHT("Irontec S.L.")

# Define _GNU_SOURCE etc.
m4_ifdef([AC_USE_SYSTEM_EXTENSIONS], [AC_USE_SYSTEM_EXTENSIONS])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_EGREP
AC_LANG(C)
AM_PROG_CC_C_O
 
#######################################################################
# Check for other REQUIRED libraries

AC_CHECK_LIB([dl], [dlopen], [], [
    AC_MSG_ERROR(No libdl library found.)
])

AC_CHECK_LIB([pthread], [pthread_create], [], [
    AC_MSG_ERROR(No libpthread library found.)
])

AC_CHECK_LIB([config], [config_init], [], [
    AC_MSG_ERROR(libconfig library is required to compile Isaac.)
])

AC_CHECK_LIB([edit], [history], [], [
    AC_MSG_ERROR(libedit library is required to compile Isaac.)
])

#### LUA Support
AC_ARG_WITH([lua],
    AS_HELP_STRING([--with-lua], [Enable LUA modules support]),
    [AC_SUBST(WITH_OPENSSL, $withval)],
    [AC_SUBST(WITH_OPENSSL, no)]
)

AS_IF([test "x$WITH_LUA" == "xyes"], [
	AC_CHECK_LIB([lua5.1], [luaL_openlibs], [], [
	    AC_MSG_ERROR([ You need to have lua installed to compile isaac with lua support])
	])
	AC_DEFINE([WITH_LUA],[],[Compile With Lua compatibility])
], [])

AM_CONDITIONAL([WITH_LUA], [test "x$WITH_LUA" == "xyes"])

AC_SUBST([isaac_moddir],[${libdir}/isaac])
AC_SUBST([isaac_confdir],[${sysconfdir}/isaac])
AC_SUBST([isaac_statedir],[${localstatedir}/run])

######################################################################
# Print Logo
AC_ARG_ENABLE(logo,
    AC_HELP_STRING(--disable-logo, [Disable Irontec Logo from Summary menu]),
    [ enable_logo=$enableval],
    [ enable_logo=yes])

AS_IF([test "x$enable_logo" == "xyes"], [
    echo ''
    echo ' ██╗██████╗  ██████╗ ███╗   ██╗████████╗███████╗ ██████╗'
    echo ' ██║██╔══██╗██╔═══██╗████╗  ██║╚══██╔══╝██╔════╝██╔════╝'
    echo ' ██║██████╔╝██║   ██║██╔██╗ ██║   ██║   █████╗  ██║     '
    echo ' ██║██╔══██╗██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██║     '
    echo ' ██║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗╚██████╗'
    echo ' ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝ ╚═════╝'
    echo ''
])

AC_MSG_NOTICE()
AC_MSG_NOTICE( ====================================================== )
AC_MSG_NOTICE(   Isaac configure finished                             )
AC_MSG_NOTICE(  ----------------------------------------------------  )
AC_MSG_NOTICE( ====================================================== )
AC_MSG_NOTICE()


AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([modules/Makefile])
AC_CONFIG_FILES([conf/Makefile])
AC_CONFIG_FILES([extra/Makefile])
AC_CONFIG_FILES([extra/mon/Makefile])
AC_CONFIG_FILES([ivozng/Makefile])

AC_OUTPUT
