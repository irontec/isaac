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
 * @file app.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source code for funtions defined in app.h
 */
#include "config.h"
#include "app.h"
#include "log.h"
#include "util.h"

//! Registered application List
app_t *apps = NULL;
//! Registered application List Mutex
pthread_mutex_t apps_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

int
application_register(const char *name, int
(*execute)(session_t *sess, app_t *app, const char *args))
{
    // Check if another application is registered with the same name 
    if (application_find(name)) {
        isaac_log(LOG_ERROR, "Another application exists with name %s\n", name);
        return -1;
    }

    // Allocate memory for application structure
    app_t *app = malloc(sizeof(app_t));
    app->name = strdup(name);
    app->execute = execute;

    // Add the new application to the applications list
    pthread_mutex_lock(&apps_lock);
    app->next = apps;
    apps = app;
    pthread_mutex_unlock(&apps_lock);

    // Some debug logging
    isaac_log(LOG_VERBOSE_3, "Registered application '\e[1;36m%s\e[0m'\n", name);
    return 0;
}

int
application_unregister(const char *name)
{
    app_t *cur, *prev = NULL;
    pthread_mutex_lock(&apps_lock);
    // Loop through applications list till we find given application name
    for (cur = apps; cur; prev = cur, cur = cur->next) {
        if (!strcasecmp(name, cur->name)) {
            isaac_log(LOG_VERBOSE_3, "Unegistered application '\e[1;36m%s\e[0m'\n", cur->name);
            // Remove from applications list
            if (prev) {
                prev->next = cur->next;
            } else {
                apps = cur->next;
            }
            // Free allocated memory
            isaac_free(cur->name);
            isaac_free(cur);
            break;
        }
    }
    pthread_mutex_unlock(&apps_lock);
    return 0;
}

app_t *
application_find(const char *name)
{
    app_t *cur = NULL;
    pthread_mutex_lock(&apps_lock);
    // Loop through applications list till we find given application name
    for (cur = apps; cur; cur = cur->next) {
        if (!strcasecmp(cur->name, name)) {
            break;
        }
    }
    pthread_mutex_unlock(&apps_lock);
    return cur;
}

int
application_count()
{
    app_t *cur;
    int appcnt = 0;
    pthread_mutex_lock(&apps_lock);
    // Loop through applications list counting
    for (cur = apps; cur; cur = cur->next) {
        appcnt++;
    }
    pthread_mutex_unlock(&apps_lock);
    return appcnt;
}

int
application_run(app_t *app, session_t *sess, const char *args)
{
    // Sanity checks
    if (!app || !app->execute) {
        return -1;
    }

    // Some debug logging
    if (!session_test_flag(sess, SESS_FLAG_LOCAL)) 
        isaac_log(LOG_DEBUG, "[Session %s] Requested application %s -> args: %s\n", sess->id, app->name, args);

    // Run the application entry point
    return app->execute(sess, app, args);
}

const char *
apperr2str(int apperr)
{
    switch (apperr) {
    case NOT_AUTHENTICATED:
        return "SESSION NOT AUTHENTICATED";
    case UNKNOWN_ACTION:
        return "UNKNOWN ACTION";
    case INVALID_ARGUMENTS:
        return "INVALID ARGUMENT LIST";
    case INVALID_FORMAT:
        return "INVALID MESSAGE FORMAT";
    default:
        return NULL;
    }
}

