bin_PROGRAMS = isaac
isaac_SOURCES = isaac.c manager.c filter.c session.c server.c app.c module.c log.c pidfile.c cli.c remote.c util.c
isaac_CPPFLAGS = -Wl,-E -Wall -Werror -g -DMODDIR=\"@isaacmoddir@\" -DPIDFILE=\"@isaacpid@\" -DCLI_SOCKET=\"@isaacsock@\" -DCFILE=\"@isaaccfile@\" -I@top_srcdir@/include
isaac_LDFLAGS = -rdynamic -llua5.1
