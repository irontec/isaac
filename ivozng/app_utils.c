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
 * @file app_utils.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Utils applications to manage sessions
 *
 */

#include <string.h>
#include <stdio.h>
#include "log.h"
#include "app.h"
#include "util.h"
#include "session.h"

//! Application List
extern app_t *apps;
//! Application List Mutex
extern pthread_mutex_t apps_lock;

/**
 * @brief Help command callback
 *
 * When a session request the Help command, this callback is executed.
 * @todo Maybe it will be nice to lock the session before writting the list
 *  of application. Each call to session_write is thread-safe but we want
 *  all the applications written in the same line.
 *
 * @param sess Session structure that requested the application
 * @param app The application structure
 * @param args Aditional command line arguments (not used)
 * @return 0 in all cases
 */
int help_exec(session_t *sess, app_t *app, const char *args)
{
    session_write(sess, "Available applications: ");
    pthread_mutex_lock(&apps_lock);
    // Loop through the apps list printing their names
    app_t *cur = apps;
    while (cur) {
        session_write(sess, "%s ", cur->name);
        cur = cur->next;
    }
    session_write(sess, "\r\n");
    pthread_mutex_unlock(&apps_lock);
    return 0;
}


/**
 * @brief Sets a variable on session
 *
 * Store a variable on current session. All variable values
 * are stored as char strings
 *
 * @param sess Session structure to store the var
 * @param app The application structure
 * @param args  Aditional command line arguments (Variable, Value)
 * @return 0 in all cases
 */
int set_exec(session_t *sess, app_t *app, const char *args)
{
    char variable[80], value[250];

    // Get login data from application arguments
    if (sscanf(args, "%s %s", variable, value) != 2) {
        return INVALID_ARGUMENTS;
    }

    // Store given variable
    session_set_variable(sess, variable, value);
    return session_write(sess, "SETOK\r\n");
}

/**
 * @brief Get a variable from a session
 *
 * Retrieve a variable on current session. All variable values
 * are stored as char strings
 *
 * @param sess Session structure to store the var
 * @param app The application structure
 * @param args  Aditional command line arguments (Variable, Value)
 * @return 0 in all cases
 */
int get_exec(session_t *sess, app_t *app, const char *args)
{
    char variable[80];
    const char *value;

    // Get login data from application arguments
    if (sscanf(args, "%s", variable) != 1) {
        return INVALID_ARGUMENTS;
    }

    // Retrieve given variable
    if (!(value = session_get_variable(sess, variable)))
        return session_write(sess, "GETFAIL Variable %s does not exists.\r\n", variable);

    // Return retrieved variable
    return session_write(sess, "GETOK %s\r\n", value);
}

/**
 * @brief Send a message to other sessions
 *
 * @param sess Session structure that invoked the app
 * @param app The application structure
 * @param args  Aditional command line arguments (Variable, Value)
 * @return 0 in all cases
 */
int broadcast_exec(session_t *sess, app_t *app, const char *args)
{
    session_iter_t *iter;
    session_t *cur;
    char variable[80], value[80], message[1024];

    // Check if message has a condition
    if (sscanf(args, "%[^=]=%s %[^\n]", variable, value, message) < 3) {
        isaac_strcpy(message, args);
        memset(variable, 0, 80);
        memset(value, 0, 80);
    }

    // Loop through sessions
    iter = session_iterator_new();
    while ((cur = session_iterator_next(iter))) {
        // If there is a variable, check current session has the same value
        if (strlen(variable)) {
            const char *cur_value = session_get_variable(cur, variable);
            if (!cur_value || strcasecmp(cur_value, value))
                continue;
        }

        // Otherwise send the message to that session
        session_write(cur, "%s\r\n", message);
    }
    session_iterator_destroy(iter);
    return 0;
}

/**
 * @brief Module load entry point
 *
 * Load module configuration and applications
 *
 * @retval 0 if all applications and configuration has been loaded
 * @retval -1 if any application fails to register or configuration can not be readed
 */
int load_module()
{
    int ret = 0;
    ret |= application_register("Help", help_exec);
    ret |= application_register("Set", set_exec);
    ret |= application_register("Get", get_exec);
    ret |= application_register("Broadcast", broadcast_exec);
    return ret;
}

/**
 * @brief Module unload entry point
 *
 * Unload module applications
 *
 * @return 0 if all applications are unloaded, -1 otherwise
 */
int unload_module()
{
    int ret = 0;
    ret |= application_unregister("Help");
    ret |= application_unregister("Get");
    ret |= application_unregister("Set");
    ret |= application_unregister("Broadcast");
    return ret;
}
