AM_CFLAGS= \
    -fPIC -g \
    -Wno-unused-result \
    -Wall \
    -I@top_srcdir@/src \
    -DMODDIR=\"@isaac_moddir@\" \
    -DCONFDIR=\"@isaac_confdir@\"
    
AM_LDFLAGS= \
    -shared -Wl,-E

app_redirect_PROGRAMS = app_redirect.so
app_redirect_so_SOURCES = app_redirect.c
app_redirectdir = @isaac_moddir@
