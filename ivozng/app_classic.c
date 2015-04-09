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
 * @file app_classic.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Wrapper module for clasic AMI actions Action:
 *
 * This module can handle Action: requests that usually aim to connect to
 * real manager. This can be used for backwards compatibility with AMI.
 *
 */
#include <stdio.h>
#include "app.h"
#include "session.h"
#include "manager.h"
#include "util.h"
#include "log.h"
#include "filter.h"

int
classic_print(filter_t *filter, ami_message_t *msg)
{
    int i;
    for (i = 0; i < msg->hdrcount; i++) {
        session_write(filter->sess, "%s\r\n", msg->headers[i]);
    }
    session_write(filter->sess, "\r\n\r\n");
    return 0;
}

/**
 * @brief Action action entry point
 *
 * @param sess Session rnuning this application
 * @param app The application structure
 * @param args Not used
 * @return 0 in call cases
 */
int
classic_exec(session_t *sess, app_t *app, const char *args)
{
    char action[10], buffer[MAX_LEN];
    ami_message_t msg;
    int res;

    // Get Action name
    if (sscanf(args, "%s", action) != 1) {
        return INVALID_ARGUMENTS;
    }

    // Initialize the message before reading
    memset(&msg, 0, sizeof(struct ami_message));
    // Add the first command header
    message_add_header(&msg, "Action: %s", action);

    // Keep reading input until
    for (;;) {
        // Initialize the message before reading
        memset(&buffer, 0, sizeof(buffer));

        // Get next action message
        if ((res = session_read(sess, buffer))) {
            // Remove the ending characters of the line
            while (buffer[strlen(buffer) - 1] == '\n' || buffer[strlen(buffer) - 1] == '\r') {
                buffer[strlen(buffer) - 1] = '\0';
            }
            // Commands end when an empty line has been entered
            if (isaac_strlen_zero(buffer)) break;
            // Otherise add the line to the message
            message_add_header(&msg, "%s", buffer);
        } else {
            // Failed to read anything
            break;
        }
    }

    // Check the action of the message
    if (!strcasecmp(action, "Login")) {
        // Send a fake response
        session_write(sess, "Response: Success\r\n");
        session_write(sess, "Message: Authentication accepted\r\n");
        session_write(sess, "\r\n\r\n");
        session_write(sess, "Event: FullyBooted\r\n");
        session_write(sess, "Privilege: system,all\r\n");
        session_write(sess, "Status: Fully Booted\r\n");
        session_write(sess, "\r\n\r\n");
        filter_t *filter = filter_create_async(sess, classic_print);
        filter_register(filter);
    } else if (!strcasecmp(action, "Events")) {
        session_write(sess, "Response: Success\r\n");
        session_write(sess, "Events: Off\r\n");
        session_write(sess, "\r\n\r\n");
    } else if (!strcasecmp(action, "Logoff")) {
        session_write(sess, "Response: Goodbye\r\n");
        session_write(sess, "Message: Thanks for all the fish.\r\n");
        session_write(sess, "\r\n\r\n");
        session_finish(sess);
    } else {
        sleep(2);
        // Send this command directly to the manager
        manager_write_message(manager, &msg);
    }

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
    return application_register("Action:", classic_exec);
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
    return application_unregister("Action:");
}
