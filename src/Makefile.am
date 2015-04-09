AM_CFLAGS= \
	-DMODDIR=\"@isaac_moddir@\" \
	-DCONFDIR=\"@isaac_confdir@\" \
	-DCLI_SOCKET=\"@isaac_statedir@/isaac.sock\" \
	-Wl,-E -Wall -Werror -g 

bin_PROGRAMS = isaac
isaac_SOURCES = main.c cfg.c manager.c filter.c session.c app.c module.c log.c cli.c remote.c util.c server.c
isaac_LDFLAGS = -rdynamic

if WITH_LUA
isaac_LDFLAGS += -llua5.1
endif
