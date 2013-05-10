/*****************************************************************************
 ** Isaac -- Ivozng simplified Asterisk AMI Connector
 **
 ** Copyright (C) 2013 Irontec S.L.
 ** Copyright (C) 2013 Ivan Alonso (aka Kaian)
 **
 ** This program is free software: you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, either version 3 of the License, or
 ** (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **
 *****************************************************************************/
/**
 * \file app.c
 * \author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * \brief Source code for funtions defined in app.h
 */
#include "config.h"
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

int application_unregister(const char *name){
    app_t *cur, *prev;
    pthread_mutex_lock(&apps_lock);
    cur = apps;
    prev = NULL;
    while(cur){
        if (!strcasecmp(name, cur->name)){
            isaac_log(LOG_VERBOSE_3, "Unegistered application '\e[1;36m%s\e[0m'\n", cur->name);
            if (prev)
                prev->next = cur->next;
            else
                apps = cur->next;
            // \todo Free application memory
        }
        prev = cur;
        cur = cur->next;
    }
    pthread_mutex_unlock(&apps_lock);
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

int application_count()
{
    int appcnt = 0;
    pthread_mutex_lock(&apps_lock);
    app_t *app = apps;
    while (app) {
        appcnt++;
        app = app->next;
    }
    pthread_mutex_unlock(&apps_lock);

    return appcnt;
}
