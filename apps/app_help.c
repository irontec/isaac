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
 * @file app_help.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Small application that will print to the session the available actions
 *
 * This is almost a demo application that shows how application callbacks are defined
 * and work.
 */

#include <stdio.h>
#include "app.h"
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
    app_t* cur = apps;
    while (cur) {
        session_write(sess, "%s ", cur->name);
        cur = cur->next;
    }
    session_write(sess, "\n");
    pthread_mutex_unlock(&apps_lock);
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
    return application_register("Help", help_exec);
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
    return application_unregister("Help");
}
