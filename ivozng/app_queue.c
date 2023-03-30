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

#include "config.h"
#include <libconfig.h>
#include <stdlib.h>
#include <string.h>
#include "app.h"
#include "session.h"
#include "manager.h"
#include "filter.h"
#include "util.h"
#include "log.h"


#define QUEUECONF CONFDIR "/queue.conf"

/**
 * @brief Module configuration readed from QUEUECONF file
 *
 * @see read_queue_config
 */
struct app_queue_config
{
    //! Validate queue names in QUEUEINFO command
    int queueinfo_validate;
    //! Max timeout in milliseconds QUEUEAGENTS will wait
    int queueagents_timeout;
    //! Validate queue names in QUEUEAGENTS command
    int queueagents_validate;
} queue_config;

/**
 * @brief Read module configure options
 *
 * This function will read QUEUECONF file and fill app_quque_conf
 * structure.
 *
 * @param cfile Full path to configuration file
 * @return 0 in case of read success, -1 otherwise
 */
int
read_queue_config(const char *cfile)
{
    config_t cfg;
    int intvalue;

    // Initialize configuration
    config_init(&cfg);

    // Set default values
    queue_config.queueinfo_validate = 1;
    queue_config.queueagents_timeout = 5000;
    queue_config.queueagents_validate = 1;

    // Read configuraiton file
    if (config_read_file(&cfg, cfile) == CONFIG_FALSE) {
        isaac_log(LOG_WARNING, "Error parsing configuration file %s on line %d: %s\n", cfile,
                  config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return -1;
    }

    // Validate queueinfo queue names
    if (config_lookup_int(&cfg, "queueinfo.validate", &intvalue) == CONFIG_TRUE) {
        queue_config.queueinfo_validate = intvalue;
    }

    // Max time queueinfo will wait
    if (config_lookup_int(&cfg, "queueagents.timeoutms", &intvalue) == CONFIG_TRUE) {
        queue_config.queueagents_timeout = intvalue;
    }

    // Validate queueagents queue names
    if (config_lookup_int(&cfg, "queueagents.validate", &intvalue) == CONFIG_TRUE) {
        queue_config.queueagents_validate = intvalue;
    }

    // Dealloc libconfig structure
    config_destroy(&cfg);

    isaac_log(LOG_VERBOSE_3, "Readed configuration from %s\n", cfile);
    return 0;
}

/**
 * @brief Show all queues for current session
 *
 * Print a list of all qeues the memeber is in
 *
 * @param sess Session structure that requested the application
 * @param app The application structure
 * @param args Aditional command line arguments (not used)
 * @return 0 in all cases
 */
int
queueinfo_print_queues(Filter *filter, AmiMessage *msg)
{
    char response[512];
    Session *sess = filter->sess;
    const char *event = message_get_header(msg, "Event");
    const char *queuename = message_get_header(msg, "Queue");

    if (!strcasecmp(event, "QueueMember")) {
        const char *interface = session_get_variable(sess, "INTERFACE");
        if (!strcasecmp(interface, message_get_header(msg, "StateInterface"))) {
            sprintf(response, "%s %s", session_get_variable(sess, "QUEUEINFO_RESPONSE"), queuename);
            session_set_variable(sess, "QUEUEINFO_RESPONSE", response);
        }
    } else if (!strcasecmp(event, "QueueStatusComplete")) {
        session_write(sess, "%s\r\n", session_get_variable(sess, "QUEUEINFO_RESPONSE"));
        filter_destroy(filter);
    }

    return 0;
}

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
queueinfo_print(Filter *filter, AmiMessage *msg)
{
    Session *sess = filter->sess;
    const char *queuename = message_get_header(msg, "Queue");
    const char *count = message_get_header(msg, "Count");

    session_write(sess, "QUEUEINFO %s %s\r\n", queuename, count);
    return 0;
}

/**
 * @brief Print queue agents information
 *
 * When a new agent count changes this function callback will be triggered
 * printing the changed events
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
int
queueagents_print(Filter *filter, AmiMessage *msg)
{
    Session *sess = filter->sess;
    const char *queuename = message_get_header(msg, "Queue");
    const char *count = message_get_header(msg, "Free");

    session_write(sess, "QUEUEAGENTS %s FREE %s\r\n", queuename, count);
    return 0;
}

/**
 * @brief Validate queue name and print queued calls
 *
 * This callback is used when VALIDATE options is passed to QUEUEINFO command
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
int
queueinfo_validate_queue(Filter *filter, AmiMessage *msg)
{
    char queuevar[512];
    Session *sess = filter->sess;
    const char *event = message_get_header(msg, "Event");
    char *queuename = filter_get_userdata(filter);

    sprintf(queuevar, "QUEUEINFO_%s_VALIDATED", queuename);

    if (!strcasecmp(event, "QueueParams")) {
        // Queue exists and it is valid, print OK message
        session_write(sess, "QUEUEINFOOK Queueinfo for %s will be printed\r\n", queuename);
        // Print queued calls
        session_write(sess, "QUEUEINFO %s %s\r\n", queuename, message_get_header(msg, "Calls"));
        // Mark this queue as validated
        session_set_variable(sess, queuevar, "1");

        // Register a Filter to get All generated channels for
        Filter *queuefilter = filter_create_async(sess, queueinfo_print);
        filter_new_condition(queuefilter, MATCH_REGEX, "Event", "Join|Leave");
        filter_new_condition(queuefilter, MATCH_EXACT, "Queue", queuename);
        filter_register(queuefilter);

    } else if (!strcasecmp(event, "QueueStatusComplete")) {
        // Check if we have already validated this queue (we have received QueueParams before QueueStatusComplete)
        if (!session_get_variable(sess, queuevar)) {
            session_write(sess, "QUEUEINFOFAIL Unable to get queuedata of %s\r\n", queuename);
        }
        filter_destroy(filter);
    }

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
 * @param argstr Aditional command line arguments (not used)
 * @return 0 in all cases
 */
int
queueinfo_exec(Session *sess, Application *app, const char *argstr)
{
    // Validate queue name
    int validate;

    // Check we are logged in.
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Check command options
    GSList *args = application_parse_args(argstr);

    // No arguments passed to the command
    if (g_slist_length(args) == 0) {
        // Send the initial banner
        session_set_variable(sess, "QUEUEINFO_RESPONSE", "QUEUEINFOOK");

        // Filter QueueMember and QueueStatusComplete responses
        Filter *queuefilter = filter_create_async(sess, queueinfo_print_queues);
        filter_new_condition(queuefilter, MATCH_REGEX, "Event", "QueueMember|QueueStatusComplete");
        filter_new_condition(queuefilter, MATCH_EXACT, "ActionID", "QueueStatus%s", sess->id);
        filter_register(queuefilter);

        // Construct a Request message
        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: QueueStatus");
        message_add_header(&msg, "ActionID: QueueStatus%s", sess->id);
        manager_write_message(manager, &msg);

        // Free args app arguments
        application_free_args(args);

        return 0;
    }

    // Get queue name from argument
    const gchar *queue_name = application_get_nth_arg(args, 0);

    // Check we haven't run this application before
    g_autoptr(GString) queue_var = g_string_new(NULL);
    g_string_append_printf(queue_var, "QUEUEINFO_%s", queue_name);
    if (session_get_variable(sess, queue_var->str)) {
        session_write(sess, "QUEUEINFOOK Already showing info for queue %s\r\n", queue_var->str);
        return 0;
    } else {
        // Store we're monitoring this queue
        session_set_variable(sess, queue_var->str, queue_name);
    }

    // Command requested validation
    if (application_arg_has_value(args, "VALIDATE", "1")) {
        validate = 1;
    } else if (application_arg_has_value(args, "VALIDATE", "0")) {
        validate = 0;
    } else {
        validate = queue_config.queueinfo_validate;
    }

    // Check if queue name needs to be validated
    if (validate) {
        // Check we have a valid quene name
        Filter *queuevalidatefilter = filter_create_async(sess, queueinfo_validate_queue);
        filter_new_condition(queuevalidatefilter, MATCH_REGEX, "Event", "QueueParams|QueueStatusComplete");
        filter_new_condition(queuevalidatefilter, MATCH_EXACT, "ActionID", "QueueValidate%s%s", queue_name, sess->id);
        filter_set_userdata(queuevalidatefilter, g_strdup(queue_name));
        filter_register(queuevalidatefilter);

        // Construct a Request message
        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: QueueStatus");
        message_add_header(&msg, "Queue: %s", queue_name);
        message_add_header(&msg, "ActionID: QueueValidate%s%s", queue_name, sess->id);
        manager_write_message(manager, &msg);
    } else {
        // Not validated queue, just print OK response
        session_write(sess, "QUEUEINFOOK Queueinfo for %s will be printed\r\n", queue_name);

        // Register a Filter to get All generated channels for
        Filter *queuefilter = filter_create_async(sess, queueinfo_print);
        filter_new_condition(queuefilter, MATCH_REGEX, "Event", "Join|Leave");
        filter_new_condition(queuefilter, MATCH_EXACT, "Queue", queue_name);
        filter_register(queuefilter);
    }

    // Free args app arguments
    application_free_args(args);

    return 0;
}

/**
 * @brief Request Queue agents information
 *
 * Request queue information for a given queuename. Every time the
 * available members changes it will print the free members information.
 *
 * @param sess Session structure that requested the application
 * @param app The application structure
 * @param argstr Aditional command line arguments (not used)
 * @return 0 in all cases
 */
int
queueagents_exec(Session *sess, Application *app, const char *argstr)
{
    // Return message
    AmiMessage retmsg;

    // Validate queue name
    int validate;

    // Check we are logged in.
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Check command options
    GSList *args = application_parse_args(argstr);

    // Get Queue parameters parameters
    if (g_slist_length(args) < 1) {
        application_free_args(args);
        return INVALID_ARGUMENTS;
    }

    // Get queue name from first argument
    const gchar *queue_name = application_get_nth_arg(args, 0);

    // Command requested validation
    if (application_arg_has_value(args, "VALIDATE", "1")) {
        validate = 1;
    } else if (application_arg_has_value(args, "VALIDATE", "0")) {
        validate = 0;
    } else {
        validate = queue_config.queueagents_validate;
    }

    // Check if queue name needs to be validated
    if (validate) {
        // Check we have a valid quene name
        Filter *namefilter = filter_create_sync(sess);
        filter_new_condition(namefilter, MATCH_EXACT, "Event", "QueueSummary");
        filter_new_condition(namefilter, MATCH_EXACT, "Queue", queue_name);
        filter_new_condition(namefilter, MATCH_EXACT, "ActionID", sess->id);
        filter_register(namefilter);

        // Construct a Request message
        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: QueueSummary");
        message_add_header(&msg, "Queue: %s", queue_name);
        message_add_header(&msg, "ActionID: %s", sess->id);
        manager_write_message(manager, &msg);

        if (filter_run(namefilter, queue_config.queueagents_timeout, &retmsg) != 0) {
            // No response Boo!
            session_write(sess, "QUEUEAGENTSFAIL Unable to get queuedata of %s\r\n", queue_name);
            application_free_args(args);
            return 0;
        }
    }

    // Check we haven't run this application before
    g_autoptr(GString) queue_var = g_string_new(NULL);
    g_string_printf(queue_var, "QUEUEAGENTS_%s", queue_name);
    if (session_get_variable(sess, queue_var->str)) {
        session_write(sess, "QUEUEAGENTSOK Already showing agents for queue %s\r\n", queue_name);
        application_free_args(args);
        return 0;
    } else {
        // Store we're monitoring this queue
        session_set_variable(sess, queue_var->str, queue_name);
    }

    // Register a Filter to get All generated channels for
    Filter *queuefilter = filter_create_async(sess, queueagents_print);
    filter_new_condition(queuefilter, MATCH_EXACT_CASE, "UserEvent", "QUEUEAGENTS");
    filter_new_condition(queuefilter, MATCH_EXACT_CASE, "Queue", queue_name);
    filter_register(queuefilter);

    // Check with uniqueid mode
    session_write(sess, "QUEUEAGENTSOK Queueinfo for %s will be printed\r\n", queue_name);

    // If queue has been validated
    if (validate) {
        // Printi intial queue status
        session_write(sess, "QUEUEAGENTS %s FREE %s\r\n", queue_name, message_get_header(&retmsg, "Available"));
    }

    // Free args app arguments
    application_free_args(args);

    return 0;
}

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
queueshow_print(Filter *filter, AmiMessage *msg)
{

    const char *event = message_get_header(msg, "Event");

    if (!strcasecmp(event, "QueueMember")) {
        //Convert the output
        const char *queue = message_get_header(msg, "Queue");
        const char *penalty = message_get_header(msg, "Penalty");
        const char *stateInterface = message_get_header(msg, "StateInterface");
        const char *status = message_get_header(msg, "Status");
        const char *paused = message_get_header(msg, "Paused");
        char stateinfo[20];
        memset(stateinfo, 0, sizeof(stateinfo));

        const char *interface = session_get_variable(filter->sess, "INTERFACE");
        if (strcasecmp(interface, stateInterface))
            return 0;

        if (!strcasecmp(paused, "1")) {
            isaac_strcpy(stateinfo, "PAUSED");
        } else if (!strcasecmp(status, "1")) {
            isaac_strcpy(stateinfo, "IDLE");
        } else if (!strcasecmp(status, "2")) {
            isaac_strcpy(stateinfo, "INUSE");
        } else if (!strcasecmp(status, "6")) {
            isaac_strcpy(stateinfo, "RINGING");
        } else {
            return 0;
        }

        session_write(filter->sess, "QUEUESHOWDATA %s %s %s %s \r\n", queue, penalty, stateInterface, stateinfo);

    } else if (!strcasecmp(event, "QueueStatusComplete")) {
        session_write(filter->sess, "%s\r\n", "QUEUESHOWEND");
        // We dont expect more info about this filter, unregister it here
        filter_destroy(filter);
    }

    return 0;
}

/**
 * @brief Request Queue status
 *
 * Request a list of queues and their status.
 *
 * @param sess Session structure that requested the application
 * @param app The application structure
 * @param args Aditional command line arguments (not used)
 * @return 0 in all cases
 */
int
queueshow_exec(Session *sess, Application *app, const char *args)
{
    // Check we are logged in.
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Filter QueueMember and QueueStatusComplete responses
    Filter *queuefilter = filter_create_async(sess, queueshow_print);
    filter_new_condition(queuefilter, MATCH_REGEX, "Event", "QueueMember|QueueStatusComplete");
    filter_new_condition(queuefilter, MATCH_EXACT, "ActionID", "QueueStatusID%s", sess->id);
    filter_register(queuefilter);


    // Construct a Request message
    AmiMessage msg;
    memset(&msg, 0, sizeof(AmiMessage));
    message_add_header(&msg, "Action: QueueStatus");
    message_add_header(&msg, "ActionID: QueueStatusID%s", sess->id);
    manager_write_message(manager, &msg);

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

    if (read_queue_config(QUEUECONF) != 0) {
        isaac_log(LOG_WARNING, "Failed to read app_queue config file %s. Using defaults.\n", QUEUECONF);
    }

    ret |= application_register("QueueInfo", queueinfo_exec);
    ret |= application_register("QueueShow", queueshow_exec);
    ret |= application_register("QueueAgents", queueagents_exec);
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
    ret |= application_unregister("QueueShow");
    ret |= application_unregister("QueueAgents");
    return ret;
}
