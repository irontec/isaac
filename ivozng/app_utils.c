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
int help_exec(Session *sess, Application *app, const char *args)
{
    g_autofree gchar *names = application_get_names();
    session_write(sess, "Available applications: %s\r\n", names);
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
int set_exec(Session *sess, Application *app, const char *args)
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
int get_exec(Session *sess, Application *app, const char *args)
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
int broadcast_exec(Session *sess, Application *app, const char *args)
{
    char variable[256], value[256], message[2048];

    // Check if message has a condition
    if (sscanf(args, "%[^=]=%s %[^\n]", variable, value, message) < 3) {
        isaac_strcpy(message, args);
        memset(variable, 0, sizeof(value));
        memset(value, 0, sizeof(value));
    }

    // Construct a Request message
    AmiMessage *msg = manager_create_message();
    message_add_header(msg, "Event: Broadcast");
    message_add_header(msg, "Message: %s", message);
    if (strlen(variable)) {
        message_add_header(msg, "Variable: %s", variable);
        message_add_header(msg, "Value: %s", value);
    }
    sessions_enqueue_message(msg);
    return 0;
}

static int
debug_exec(Session *sess, Application *app, const char *args)
{
    g_return_val_if_fail(sess != NULL, 1);
    gboolean debug = session_test_flag(sess, SESS_FLAG_DEBUG);
    if (debug) {
        session_clear_flag(sess, SESS_FLAG_DEBUG);
        session_write(sess, "DEBUGOK DISABLED\n");
        isaac_log(LOG_NOTICE, "Debug on session %s \033[1;31mdisabled\033[0m.\n", sess->id);
    } else {
        session_set_flag(sess, SESS_FLAG_DEBUG);
        session_write(sess, "DEBUGOK ENABLED\n");
        isaac_log(LOG_NOTICE, "Debug on session %s \033[1;32menabled\033[0m.\n", sess->id);
    }
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
    ret |= application_register("HELP", help_exec);
    ret |= application_register("SET", set_exec);
    ret |= application_register("GET", get_exec);
    ret |= application_register("BROADCAST", broadcast_exec);
    ret |= application_register("DEBUG", debug_exec);
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
    ret |= application_unregister("HELP");
    ret |= application_unregister("GET");
    ret |= application_unregister("SET");
    ret |= application_unregister("BROADCAST");
    ret |= application_unregister("DEBUG");
    return ret;
}
