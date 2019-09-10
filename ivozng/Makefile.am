AM_CFLAGS= \
	-fPIC -g \
	-Wno-unused-result \
	-Wall \
	-I@top_srcdir@/src \
	-DMODDIR=\"@isaac_moddir@\" \
	-DCONFDIR=\"@isaac_confdir@\"
	
AM_LDFLAGS= \
	-shared -Wl,-E

app_login_PROGRAMS = app_login.so
app_login_so_SOURCES = app_login.c
app_login_so_LDFLAGS = -lodbc $(AM_LDFLAGS)
app_logindir = @isaac_moddir@

app_acd_PROGRAMS = app_acd.so
app_acd_so_SOURCES = app_acd.c
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
app_utilsdir = @isaac_moddir@

app_call_PROGRAMS = app_call.so
app_call_so_SOURCES = app_call.c
app_calldir = @isaac_moddir@

app_queue_PROGRAMS = app_queue.so
app_queue_so_SOURCES = app_queue.c
app_queuedir = @isaac_moddir@

if WITH_LUA
res_lua_PROGRAMS = res_lua.so
res_lua_so_SOURCES = res_lua.c
res_lua_so_CFLAGS = -I/usr/include/lua5.1 $(AM_CFLAGS)
res_lua_so_LDFLAGS = $(AM_LDFLAGS) -llua5.1
res_luadir = $(appsdir)
endif

app_classic_PROGRAMS = app_classic.so
app_classic_so_SOURCES = app_classic.c
app_classicdir = @isaac_moddir@

app_conference_PROGRAMS = app_conference.so
app_conference_so_SOURCES = app_conference.c
app_conferencedir = @isaac_moddir@
