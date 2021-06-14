cmake_minimum_required(VERSION 3.0)
project(isaac VERSION 0.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)

include_directories(ivozng)
include_directories(modules)
include_directories(src)
include(GNUInstallDirs)

######################################################################
# Main binary
add_executable(isaac
        src/app.c
        src/cfg.c
        src/cli.c
        src/filter.c
        src/log.c
        src/main.c
        src/manager.c
        src/module.c
        src/pidfile.c
        src/remote.c
        src/server.c
        src/session.c
        src/util.c
        )

######################################################################
add_definitions(-D_GNU_SOURCE)
add_definitions(-D_XOPEN_SOURCE_EXTENDED)

######################################################################
set(CLI_SOCKET ${CMAKE_INSTALL_FULL_RUNSTATEDIR}/isaac.sock)
set(MODDIR ${CMAKE_INSTALL_FULL_LIBDIR}/isaac/)
set(CONFDIR ${CMAKE_INSTALL_FULL_SYSCONFDIR}/isaac)

######################################################################
# Use pkg-config when possible
find_package(PkgConfig REQUIRED)

pkg_check_modules(GLIB REQUIRED glib-2.0>=2.42)
include_directories(${GLIB_INCLUDE_DIRS})
link_libraries(${GLIB_LIBRARIES})

# libconfig
pkg_check_modules(LIBCONFIG REQUIRED libconfig)
include_directories(${LIBCONFIG_INCLUDE_DIRS})
target_link_libraries(isaac ${LIBCONFIG_LIBRARIES})

# libedit
pkg_check_modules(LIBEDIT REQUIRED libedit)
include_directories(${LIBEDIT_INCLUDE_DIRS})
target_link_libraries(isaac ${LIBEDIT_LIBRARIES})

# pthreads
find_package(Threads REQUIRED)
target_link_libraries(isaac ${CMAKE_THREAD_LIBS_INIT})

# ldl
target_link_libraries(isaac ${CMAKE_DL_LIBS})

# For module extern variables
add_compile_options(-rdynamic)

######################################################################
# Ivozng Modules
add_library(app_login MODULE ivozng/app_login.c)
add_library(app_acd MODULE ivozng/app_acd.c)
add_library(app_status MODULE ivozng/app_status.c)
add_library(app_ping MODULE ivozng/app_ping.c)
add_library(app_utils MODULE ivozng/app_utils.c)
add_library(app_call MODULE ivozng/app_call.c)
add_library(app_queue MODULE ivozng/app_queue.c)
add_library(app_classic MODULE ivozng/app_classic.c)
add_library(app_conference MODULE ivozng/app_conference.c)


SET(ISAAC_MODULES
        app_login
        app_acd
        app_status
        app_ping
        app_utils
        app_call
        app_queue
        app_classic
        app_conference
        )

set_target_properties(${ISAAC_MODULES} PROPERTIES PREFIX "")
set_target_properties(${ISAAC_MODULES} PROPERTIES LINK_OPTIONS "-Wl,-E")
set_property(TARGET ${ISAAC_MODULES} PROPERTY POSITION_INDEPENDENT_CODE ON)

######################################################################
# odbc
pkg_check_modules(ODBC QUIET odbc)
if(ODBC_FOUND)
    include_directories(${ODBC_INCLUDE_DIRS})
    target_link_libraries(app_login ${ODBC_LIBRARIES})
else()
    target_link_libraries(app_login -lodbc)
endif()


######################################################################
# Install files
install(TARGETS isaac DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY conf/ DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/isaac)
install(TARGETS ${ISAAC_MODULES} DESTINATION ${CMAKE_INSTALL_LIBDIR}/isaac/)
install(FILES ivozng/acd.php DESTINATION ${CMAKE_INSTALL_LIBDIR}/isaac/)

######################################################################
configure_file(
        ${PROJECT_SOURCE_DIR}/src/config.h.cmake
        ${PROJECT_SOURCE_DIR}/src/config.h
)
