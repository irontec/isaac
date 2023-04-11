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
#include <stdio.h>
#include <ctype.h>
#include "app.h"
#include "log.h"

//! Registered application List
GSList *apps = NULL;
//! Registered application List Mutex
static GRecMutex apps_lock;

gint
application_register(const gchar *name, ApplicationFunc execute)
{
    // Check if another application is registered with the same name
    if (application_find_by_name(name)) {
        isaac_log(LOG_ERROR, "Another application exists with name %s\n", name);
        return -1;
    }

    // Allocate memory for application structure
    Application *app = g_malloc0(sizeof(Application));
    g_assert_nonnull(app);
    app->name = name;
    app->execute = execute;

    // Add the new application to the applications list
    g_rec_mutex_lock(&apps_lock);
    apps = g_slist_append(apps, app);
    g_rec_mutex_unlock(&apps_lock);

    // Some debug logging
    isaac_log(LOG_VERBOSE_3, "Registered application '\033[1;36m%s\033[0m'\n", name);
    return 0;
}

gint
application_unregister(const gchar *name)
{
    g_rec_mutex_lock(&apps_lock);
    Application *app = application_find_by_name(name);
    if (app) {
        isaac_log(LOG_VERBOSE_3, "Unregistered application '\033[1;36m%s\033[0m'\n", app->name);
        apps = g_slist_remove(apps, app);
        g_free(app);
    }
    g_rec_mutex_unlock(&apps_lock);
    return 0;
}

Application *
application_find_by_name(const gchar *name)
{
    Application *found = NULL;

    g_rec_mutex_lock(&apps_lock);
    // Loop through applications list till we find given application name
    for (GSList *l = apps; l; l = l->next) {
        Application *app = l->data;
        if (g_ascii_strcasecmp(app->name, name) == 0) {
            found = app;
            break;
        }
    }
    g_rec_mutex_unlock(&apps_lock);
    return found;
}

guint
application_count()
{
    g_rec_mutex_lock(&apps_lock);
    guint count = g_slist_length(apps);
    g_rec_mutex_unlock(&apps_lock);
    return count;
}

gchar *
application_get_names()
{
    GString *names = g_string_new(NULL);
    g_rec_mutex_lock(&apps_lock);
    // Loop through applications list till we find given application name
    for (GSList *l = apps; l; l = l->next) {
        Application *app = l->data;
        g_string_append_printf(names, "%s ", app->name);
    }
    g_rec_mutex_unlock(&apps_lock);
    return g_string_free(names, FALSE);
}

int
application_run(Application *app, Session *sess, const gchar *args)
{
    // Sanity checks
    if (!app || !app->execute) {
        return -1;
    }

    // Fix the arguments string, remove any \r or \n characters
    g_autoptr(GString) arguments = g_string_new(args);
    g_strchomp(arguments->str);

    // Some debug logging
    if (!session_test_flag(sess, SESS_FLAG_LOCAL)) {
        isaac_log(LOG_DEBUG, "[Session#%s] <-- %s %s\n", sess->id, app->name, arguments->str);
    }

    // Run the application entry point
    return app->execute(sess, app, arguments->str);
}

GSList *
application_parse_args(const gchar *argstr)
{
    g_return_val_if_fail(argstr != NULL, NULL);

    GSList *ret = NULL;

    // Support arguments with and without value
    g_auto(GStrv) args = g_strsplit(argstr, " ", -1);
    for (guint i = 0; i < g_strv_length(args); i++) {
        ApplicationArg *arg = g_malloc0(sizeof(ApplicationArg));
        g_return_val_if_fail(arg != NULL, NULL);

        // Check if argument is in VAR=VALUE format
        GStrv var = g_strsplit(args[i], "=", 2);

        // Argument without value
        if (g_strv_length(var) == 1) {
            arg->name = g_strdup(var[0]);
        }

        // Argument with value
        if (g_strv_length(var) == 2) {
            arg->name = g_strdup(var[0]);
            arg->value = g_strdup(var[1]);
        }

        // Free argument parsing
        g_strfreev(var);

        // Add to the arguments list
        ret = g_slist_append(ret, arg);
    }

    return ret;
}

static void
application_free_arg(ApplicationArg *arg)
{
    g_free(arg->name);
    g_free(arg->value);
    g_free(arg);
}

void
application_free_args(GSList *args)
{
    g_slist_free_full(args, (GDestroyNotify) application_free_arg);
}

const gchar *
application_get_arg(GSList *args, const gchar *name)
{
    g_return_val_if_fail(args != NULL, NULL);
    g_return_val_if_fail(name != NULL, NULL);

    // Search for the argument
    for (GSList *l = args; l; l = l->next) {
        ApplicationArg *arg = l->data;
        if (g_ascii_strcasecmp(arg->name, name) == 0) {
            return arg->value;
        }
    }

    // Argument not found
    return NULL;
}

const gchar *
application_get_nth_arg(GSList *args, gint index)
{
    g_return_val_if_fail(args != NULL, NULL);
    ApplicationArg *arg = g_slist_nth_data(args, index);
    return (arg) ? arg->name : NULL;
}

gboolean
application_arg_exists(GSList *args, const gchar *name)
{
    g_return_val_if_fail(args != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);

    // Search for the argument
    for (GSList *l = args; l; l = l->next) {
        ApplicationArg *arg = l->data;
        if (g_ascii_strcasecmp(arg->name, name) == 0) {
            return TRUE;
        }
    }

    // Argument not found
    return FALSE;
}

gboolean
application_arg_has_value(GSList *args, const gchar *name, const gchar *value)
{
    g_return_val_if_fail(args != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);
    g_return_val_if_fail(value != NULL, FALSE);

    // Search for the argument
    for (GSList *l = args; l; l = l->next) {
        ApplicationArg *arg = l->data;
        if (g_ascii_strcasecmp(arg->name, name) == 0 &&
            g_ascii_strcasecmp(arg->value, value) == 0) {
            return TRUE;
        }
    }

    // Argument not found
    return FALSE;
}

const gchar *
apperr2str(enum ApplicationRetCodes apperr)
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
        case INTERNAL_ERROR:
            return "INTERNAL APPLICATION ERROR";
        default:
            return NULL;
    }
}

