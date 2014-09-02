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
 * @file app_queue.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Check queue status
 *
 * @warning This module is customized for Ivoz-NG. If won't work without the
 *  required contexts conifgured in asterisk.
 *
 * Check for incoming calls entering queues.
 *
 */

#include <stdlib.h>
#include <string.h>
#include "app.h"
#include "session.h"
#include "manager.h"
#include "filter.h"
#include "util.h"
#include "log.h"

/**
 * @brief Print queue calls count
 *
 * When a new call enters or leaves a queue a message will be printed to the sessions
 * that requested queue information using queueinfo command
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
int
queueinfo_print(filter_t *filter, ami_message_t *msg)
{
    session_t *sess = filter->sess;
    const char *queuename = message_get_header(msg, "Queue");
    const char *count = message_get_header(msg, "Count");
    
    session_write(sess, "QUEUEINFO %s %s\r\n", queuename, count);
    return 0;
}

/**
 * @brief Request Queue information
 *
 * Request queue information for a given queuename. Every time a new call
 * enters or leaves given queue, a message with the callcount will be
 * printed.
 *
 * @param sess Session structure that requested the application
 * @param app The application structure
 * @param args Aditional command line arguments (not used)
 * @return 0 in all cases
 */
int
status_exec(session_t *sess, app_t *app, const char *args)
{
    // Store variable name to flag a queue being watched
    char queuevar[256];
    char queuename[256];

    // Check we are logged in.
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Get queuename to monitor
    if (sscanf(args, "%s", queuename) != 1) {
        return INVALID_ARGUMENTS;
    }

    // Check we havent run this application before
    sprintf(queuevar, "QUEUEINFO_%s", queuename); 
    if (session_get_variable(sess, queuevar)) {
        session_write(sess, "QUEUEINFOOK Already showing info for queue %s\r\n", queuename);
        return 0;
    } else {
        // Store we're monitoring this queue
        session_set_variable(sess, queuevar, queuename);
    }

    // Register a Filter to get All generated channels for
    filter_t *queuefilter = filter_create(sess, FILTER_SYNC_CALLBACK, queueinfo_print);
    filter_new_condition(queuefilter, MATCH_REGEX , "Event", "Join|Leave");
    filter_new_condition(queuefilter, MATCH_EXACT , "Queue", queuename);
    filter_register(queuefilter);

    // Check with uniqueid mode
    session_write(sess, "QUEUEINFOOK Queueinfo for %s will be printed\r\n", queuename);

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
    ret |= application_register("QueueInfo", status_exec);
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
    ret |= application_unregister("QueueInfo");
    return ret;
}
