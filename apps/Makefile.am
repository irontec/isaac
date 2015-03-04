AM_CFLAGS= \
	-I@top_srcdir@/include

AM_LDFLAGS= \
	-shared -Wl,-E

app_login_PROGRAMS = app_login.so
app_login_so_SOURCES = app_login.c
app_login_so_LDFLAGS = -lodbc
app_logindir = @isaac_moddir@

app_acd_PROGRAMS = app_acd.so
app_acd_so_SOURCES = app_acd.c
app_acd_so_CFLAGS = -DACDCONF=\"@isaac_confdir@/acd.conf\"
app_acd_so_DATA = acd.php
app_acddir = @isaac_moddir@
app_acd_sodir = @isaac_moddir@

app_status_PROGRAMS = app_status.so
app_status_so_SOURCES = app_status.c
app_statusdir = @isaac_moddir@

app_ping_PROGRAMS = app_ping.so
app_ping_so_SOURCES = app_ping.c
app_pingdir = @isaac_moddir@

app_utils_PROGRAMS = app_utils.so
app_utils_so_SOURCES = app_utils.c
app_utils_so_CFLAGS = $(appsCFLAGS)
app_utils_so_LDFLAGS = $(appsLDFLAGS)
app_utilsdir = @isaac_moddir@

app_call_PROGRAMS = app_call.so
app_call_so_SOURCES = app_call.c
app_call_so_CFLAGS = -DCALLCONF=\"@isaacconfdir@/call.conf\"
app_calldir = @isaac_moddir@

app_queue_PROGRAMS = app_queue.so
app_queue_so_SOURCES = app_queue.c
app_queuedir = @isaac_moddir@

if WITH_LUA
res_lua_PROGRAMS = res_lua.so
res_lua_so_SOURCES = res_lua.c
res_lua_so_CFLAGS = $(appsCFLAGS) -I/usr/include/lua5.1 -DMODDIR=\"@isaacmoddir@\" 
res_lua_so_LDFLAGS = $(appsLDFLAGS) -llua5.1
res_luadir = $(appsdir)
endif

app_classic_PROGRAMS = app_classic.so
app_classic_so_SOURCES = app_classic.c
app_classicdir = @isaac_moddir@
