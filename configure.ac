AC_PREREQ([2.6])
AC_INIT([Isaac], [0.1], [kaian@irontec.com])
AM_INIT_AUTOMAKE([-Werror foreign])
#AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects])

AC_COPYRIGHT("Irontec")
AC_REVISION("$Revision: 188")

# Define _GNU_SOURCE etc.
AC_USE_SYSTEM_EXTENSIONS

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

#######################################################################
# Check for REQUIRED header files
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h stdint.h stdlib.h string.h sys/file.h sys/socket.h sys/time.h syslog.h unistd.h])

#######################################################################
# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero inet_ntoa gethostbyname gettimeofday socket strcasecmp strchr strcspn strdup strerror strncasecmp strstr])

# Program defines
AC_DEFINE_UNQUOTED([APP_NAME], ["${PACKAGE_NAME}"], [Application name])
AC_DEFINE_UNQUOTED([APP_LNAME], ["Isaac - Ivozng Simplified Asterisk AMI Connector"], [Long name of the package])
AC_DEFINE_UNQUOTED([APP_VERSION], ["${PACKAGE_VERSION}"], [Application version])

# Set directories and files
AC_SUBST([isaacconfdir],[${sysconfdir}/isaac])
AC_SUBST([isaaccfile],[${isaacconfdir}/isaac.conf])
AC_SUBST([isaacinitdir],[${sysconfdir}/init.d/])
AC_SUBST([isaacmoddir],[${libdir}/isaac])
AC_SUBST([isaacmondir],[${libdir}/mon/mon.d])
AC_SUBST([isaacmonalertdir],[${libdir}/mon/alert.d])
AC_SUBST([isaacpid],[${localstatedir}/run/isaac.pid])
AC_SUBST([isaacsock],[${localstatedir}/run/isaac.sock])


######################################################################
# DOXYGEN SUPPORT
######################################################################
#DX_HTML_FEATURE([ON])
#DX_CHM_FEATURE([OFF])
#DX_CHI_FEATURE([OFF])
#DX_MAN_FEATURE([OFF])
#DX_RTF_FEATURE([OFF])
#DX_XML_FEATURE([OFF])
#DX_PDF_FEATURE([OFF])
#DX_PS_FEATURE([OFF])
#DX_INIT_DOXYGEN([$PACKAGE_NAME],[Doxyfile])

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


AC_MSG_NOTICE
AC_MSG_NOTICE( ====================================================== )
AC_MSG_NOTICE(   Isaac configure finished                             )
AC_MSG_NOTICE(  ----------------------------------------------------  )
AC_MSG_NOTICE( ====================================================== )
AC_MSG_NOTICE


AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_CONFIG_FILES([apps/Makefile])
AC_CONFIG_FILES([conf/Makefile])
AC_CONFIG_FILES([mon/Makefile])

AC_OUTPUT
