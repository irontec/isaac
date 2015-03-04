AC_PREREQ([2.59])
AC_INIT([isaac], [0.1], [kaian@irontec.com], [isaac], [http://www.irontec.com/])
AM_INIT_AUTOMAKE([1.9])
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
 
#######################################################################
# Check for other REQUIRED libraries

AC_CHECK_LIB([dl], [dlopen], [], [
    AC_MSG_ERROR(No libdl library found.)
])

AC_CHECK_LIB([pthread], [pthread_create], [], [
    AC_MSG_ERROR(No libpthread library found.)
])

AC_CHECK_LIB([config], [config_init], [], [
    AC_MSG_ERROR(libconfig library is required to comile Isaac.)
])

AC_CHECK_LIB([edit], [history], [], [
    AC_MSG_ERROR(libedit library is required to comile Isaac.)
])

####
#### LUA Support
####
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

### AC_DEFINE([CONFDIR],  	[${sysconfdir}/isaac], [Configuration files directory])
### AC_DEFINE([CFILE], 		[${sysconfdir}/isaac/isaac.conf], [Isaac configuration file])
### AC_DEFINE([MODDIR], 	[${libdir}/isaac], [Loadable modules directory])
### AC_DEFINE([PIDFILE], 	[${localstatedir}/run/isaac.pid], [Pid file location])
### AC_DEFINE([CLI_SOCKET],	[${localstatedir}/run/isaac.sock], [CLI socket file location])

# Set directories and files
# AC_SUBST([isaacconfdir],[${sysconfdir}/isaac])
# AC_SUBST([isaaccfile],[${isaacconfdir}/isaac.conf])
# AC_SUBST([isaacinitdir],[${sysconfdir}/init.d/])
# AC_SUBST([isaac_moddir],[${libdir}/isaac])
# AC_SUBST([isaacmondir],[${libdir}/mon/mon.d])
# AC_SUBST([isaacmonalertdir],[${libdir}/mon/alert.d])
# AC_SUBST([isaacpid],[${localstatedir}/run/isaac.pid])
# AC_SUBST([isaacsock],[${localstatedir}/run/isaac.sock])

######################################################################

if test "x${silent}" != "xyes" ; then
    echo
    echo '             OZZZO                 ' 
    echo '             OZZZO                 ' 
    echo '         .:  OZZZO  :.             ' 
    echo '       :DDD. OZZZO  DDD~           ' 
    echo '     :DDDDD. OZZZO  DDDDD:         ' 
    echo '    DDDDDDD. OZZZO  DDDDDDD.       ' 
    echo '  .DDDDDD    OZZZO   .DDDDDD.      ' 
    echo '  ODDDD?.    OZZZO    .~DDDDZ.     ' 
    echo '  DDDDD.     OZZZO      8DDDD      ' 
    echo ' ,DDDD.      .....       DDDD,     ' 
    echo ' ~DDDD                   DDDD+     ' 
    echo ' :DDDD.                  DDDD,     ' 
    echo '  DDDDD                 8DDDD.     ' 
    echo '  ODDDD?               ~DDDDZ      ' 
    echo '  .DDDDDD.           .DDDDDD.      ' 
    echo '   .DDDDDD8.       .8DDDDDD        ' 
    echo '    .:DDDDDDDDDDDDDDDDDDD:.        ' 
    echo '      .~DDDDDDDDDDDDDDD~.          ' 
    echo '         .:DDDDDDDDD,.             ' 
    echo
fi


AC_MSG_NOTICE()
AC_MSG_NOTICE( ====================================================== )
AC_MSG_NOTICE(   Isaac configure finished                             )
AC_MSG_NOTICE(  ----------------------------------------------------  )
AC_MSG_NOTICE( ====================================================== )
AC_MSG_NOTICE()


AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([apps/Makefile])
AC_CONFIG_FILES([conf/Makefile])
AC_CONFIG_FILES([mon/Makefile])

AC_OUTPUT
