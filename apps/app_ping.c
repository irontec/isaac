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
 * @file app_ping.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Basic module for ping action
 *
 * The smallest module ever. Writes a simple message to the session connection
 * when the action Ping has been requested.
 */
#include <stdio.h>
#include "app.h"
#include "session.h"

/**
 * @brief Ping action entry point
 *
 * Writes a message to session if authenticated.
 *
 * @param sess Session rnuning this application
 * @param app The application structure
 * @param args Not used
 * @return 0 in call cases
 */
int
ping_exec(session_t *sess, app_t *app, const char *args)
{
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }
    session_write(sess, "PONG\r\n");
    return 0;
}

/**
 * @brief Module load entry point
 *
 * Load module applications
 *
 * @retval 0 if all applications been loaded, -1 otherwise
 */
int
load_module()
{
    return application_register("Ping", ping_exec);
}

/**
 * @brief Module unload entry point
 *
 * Unload module applications
 *
 * @return 0 if all applications are unloaded, -1 otherwise
 */
int
unload_module()
{
    return application_unregister("Ping");
}
