appsdir=@isaacmoddir@
appsCFLAGS=-I@top_srcdir@/include -fPIC -g -Wall -Werror
appsLDFLAGS=-shared -Wl

app_login_PROGRAMS = app_login.so
app_login_so_SOURCES = app_login.c
app_login_so_CFLAGS = $(appsCFLAGS) 
app_login_so_LDFLAGS = $(appsLDFLAGS) -lodbc
app_logindir = $(appsdir)

app_acd_PROGRAMS = app_acd.so
app_acd_so_SOURCES = app_acd.c
app_acd_so_CFLAGS = $(appsCFLAGS) -DACDCONF=\"@isaacconfdir@/acd.conf\"
app_acd_so_LDFLAGS = $(appsLDFLAGS)
app_acd_so_DATA = acd.php
app_acddir = $(appsdir)
app_acd_sodir = $(appsdir)

app_status_PROGRAMS = app_status.so
app_status_so_SOURCES = app_status.c
app_status_so_CFLAGS = $(appsCFLAGS)
app_status_so_LDFLAGS = $(appsLDFLAGS)
app_statusdir = $(appsdir)

app_ping_PROGRAMS = app_ping.so
app_ping_so_SOURCES = app_ping.c
app_ping_so_CFLAGS = $(appsCFLAGS)
app_ping_so_LDFLAGS = $(appsLDFLAGS)
app_pingdir = $(appsdir)

app_help_PROGRAMS = app_help.so
app_help_so_SOURCES = app_help.c
app_help_so_CFLAGS = $(appsCFLAGS)
app_help_so_LDFLAGS = $(appsLDFLAGS)
app_helpdir = $(appsdir)

app_call_PROGRAMS = app_call.so
app_call_so_SOURCES = app_call.c
app_call_so_CFLAGS = $(appsCFLAGS) -DCALLCONF=\"@isaacconfdir@/call.conf\"
app_call_so_LDFLAGS = $(appsLDFLAGS)
app_calldir = $(appsdir)

res_lua_PROGRAMS = res_lua.so
res_lua_so_SOURCES = res_lua.c
res_lua_so_CFLAGS = $(appsCFLAGS) -I/usr/include/lua5.1 -DMODDIR=\"@isaacmoddir@\" 
res_lua_so_LDFLAGS = $(appsLDFLAGS) -llua5.1
res_lua_so_DATA = test.lua 
res_lua_sodir = $(appsdir)
res_luadir = $(appsdir)

#app_debug_PROGRAMS = app_debug.so
#app_debug_so_SOURCES = app_debug.c
#app_debug_so_CFLAGS = $(appsCFLAGS)
#app_debug_so_LDFLAGS = $(appsLDFLAGS)
#app_debugdir = $(appsdir)

