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
 * @file app_redirect.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Redirect a call to a given context and extension
 *
 */

#include <stdlib.h>
#include <string.h>
#include "app.h"
#include "manager.h"
#include "util.h"
#include "log.h"

/** 
 * @brief Redirect a channel to a given context and extension
 * 
 * Format: REDIRECTCHANNEL CHANNAME CONTEXT EXTEN
 *
 * @param sess Session structure that requested the application
 * @param app The application structure
 * @param args Aditional command line arguments (not used)
 * @return 0 in all cases
 */
int
redirectto_exec(Session *sess, app_t *app, const char *args)
{
    char channame[250], context[256], exten[80];

    // Get Call parameteres
    if (sscanf(args, "%s %s %s", channame, context, exten) < 3)
        return INVALID_ARGUMENTS;

    // Construct a Request message
    ami_message_t msg;
    memset(&msg, 0, sizeof(ami_message_t));
    message_add_header(&msg, "Action: Redirect");
    message_add_header(&msg, "Channel: %s", channame);
    message_add_header(&msg, "Context: %s", context);
    message_add_header(&msg, "Exten: %s", exten);
    message_add_header(&msg, "Priority: 1");
    manager_write_message(manager, &msg);
    session_write(sess, "REDIRECTCHANNELOK Channel redirected\r\n");
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
    int ret = 0;
    ret |= application_register("RedirectChannel", redirectto_exec);
    return ret;
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
    int ret = 0;
    ret |= application_unregister("RedirectChannel");
    return ret;
}
