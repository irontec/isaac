AM_CFLAGS= \
	-I@top_srcdir@/include \
	-DMODDIR=\"@isaac_moddir@\" \
	-DPIDFILE=\"@isaac_statedir@/isaac.pid\" \
	-DCFILE=\"@isaac_confdir@/isaac.conf\" \
	-DCLI_SOCKET=\"@isaac_statedir@/isaac.sock\"

bin_PROGRAMS = isaac
isaac_SOURCES = isaac.c manager.c filter.c session.c server.c app.c module.c log.c pidfile.c cli.c remote.c util.c
isaac_CPPFLAGS = -Wl,-E -Wall -Werror -g 
isaac_LDFLAGS = -rdynamic 

if WITH_LUA
isaac_LDFLAGS += -llua5.1
endif
