AC_PREREQ([2.6])
AC_INIT([Isaac], [0.1], [kaian@irontec.com])
AM_INIT_AUTOMAKE([-Werror foreign])
#AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS([config.h])

AC_COPYRIGHT("Irontec")
AC_REVISION("$Revision: 188")

# Set directories
AC_SUBST([isaacconfdir],['$(sysconfdir)/isaac/'])
AC_SUBST([isaacinitdir],['$(sysconfdir)/init.d/'])
AC_SUBST([isaaclibdir], ['$(libdir)/isaac'])

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
#AC_CHECK_LIB([edit], [main])

AC_CHECK_LIB([dl], [dlopen], [], [
    AC_MSG_ERROR(No libdl library found.)
])

AC_CHECK_LIB([pthread], [pthread_create], [], [
    AC_MSG_ERROR(No libpthread library found.)
])

AC_CHECK_LIB([config], [config_init], [], [
    AC_MSG_ERROR(libconfig library is required to comile Isaac.)
])


#######################################################################
# Check for REQUIRED header files
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h stdint.h stdlib.h string.h sys/file.h sys/socket.h sys/time.h syslog.h unistd.h])

#AC_CHECK_HEADER([iniparser.h], [], [
#    AC_MSG_ERROR([iniparser must be installed to compile])
#])

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
AC_DEFINE_UNQUOTED([CLI_SOCKET], "/var/run/isaac.sock", [Define Unix socket for Command Line Interface])
AC_DEFINE_UNQUOTED([PIDFILE], "/var/run/isaac.pid", [Define program pidfile])
AC_DEFINE_UNQUOTED([CFILE],"/etc/isaac.conf", [Define program configuration file])
AC_DEFINE_UNQUOTED([PACKAGE_LNAME], "Isaac - Ivozng Simplified Asterisk AMI Connector", [Long name of the package])

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

AC_OUTPUT
