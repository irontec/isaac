#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "app.h"
#include "session.h"
#include "log.h"

/* Application List */
app_t *apps = NULL;
/* Application List Mutex */
pthread_mutex_t apps_lock;

int application_register(const char *name, int(*execute)(session_t *sess, const char *args))
{

    // Check if another application is registered with the same name 
    if (application_find(name)) {
        isaac_log(LOG_ERROR, "Another application exists with name %s\n", name);
        return -1;
    }

    app_t *app = malloc(sizeof(app_t));
    app->name = strdup(name);
    app->execute = execute;

    pthread_mutex_lock(&apps_lock);
    app->next = apps;
    apps = app;
    pthread_mutex_unlock(&apps_lock);

    isaac_log(LOG_VERBOSE_3, "Registered application '\e[1;36m%s\e[0m'\n", name);

    return 0;
}

app_t *application_find(const char *name)
{

    pthread_mutex_lock(&apps_lock);
    app_t *app = apps;
    while (app) {
        if (!strcasecmp(app->name, name)) break;
        app = app->next;
    }
    pthread_mutex_unlock(&apps_lock);

    return app;
}

int application_run(app_t *app, session_t *sess, const char *args)
{
    if (!app || !app->execute) {
        return -1;
    }
    return app->execute(sess, args);
}

const char *apperr2str(int apperr)
{
    switch (apperr) {
    case NOT_AUTHENTICATED:
        return "SESSION NOT AUTHENTICATED";
    case UNKOWN_ACTION:
        return "UNKOWN ACTION";
    case INVALID_ARGUMENTS:
        return "INVALID ARGUMENT LIST";
    case INVALID_FORMAT:
        return "INVALID MESSAGE FORMAT";
    default:
        return NULL;
    }
}
