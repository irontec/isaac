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
 * @file app_conference.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Module for manage conference meets through AMI
 *
 * @warning This module is customized for Ivoz-NG. If won't work without the
 *  required contexts configured in asterisk.
 *
 * This is a basic module of Isaac that implements some actios for placing
 * calls into asterisk.\n To make this module work, it must configured using
 * CALLCONF file (usually /etc/isaac/call.conf) and defining the desired contexts
 * in asterisk.
 *
 */
#include <ctype.h>
#include <time.h>
#include <libconfig.h>
#include <stdbool.h>
#include <unistd.h>
#include "app.h"
#include "manager.h"
#include "filter.h"
#include "log.h"
#include "util.h"

#define CONFERENCECONF CONFDIR "/conference.conf"

/**
 * @brief Module configuration read from CONFERENCECONF file
 *
 * @see read_call_config
 */
struct app_conference_config
{
    //! Context to originate the first leg during CONFERENCE action
    char incontext[80];
    //! Context to originate the second leg during CONFERENCE action
    char outcontext[80];
    //! Autoanswer flag. Does not work in all terminals.
    int autoanswer;
} conference_config;

/**
 * @brief Common structure for Call filters
 *
 * This structure contains the shared information between different
 * filters of the same call.
 */
struct app_conference_info
{
    //! Unique ID supplied during CONFERENCE action
    const char *actionid;
    //! List of extensions to invite to conference
    const char **extensions;
    //! Numbers of extensions to invite
    int extensioncnt;
    //! Flag for creating a broadcast conference
    bool broadcast;

    //! Filter for waiting conference events
    filter_t *conference_filter;
};

/**
 * @brief Read module configure options
 *
 * This function will read CONFERENCECONF file and fill app_conference_conf
 * structure. Most of these values are using during conference action process
 * @see conference_exec
 *
 * @param cfile Full path to configuration file
 * @return 0 in case of read success, -1 otherwise
 */
int
read_conference_config(const char *cfile)
{
    config_t cfg;
    const char *value;
    int intvalue;

    // Initialize configuration
    config_init(&cfg);

    // Read configuration file
    if (config_read_file(&cfg, cfile) == CONFIG_FALSE) {
        isaac_log(LOG_ERROR, "Error parsing configuration file %s on line %d: %s\n", cfile,
                config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return -1;
    }

    // Incoming context for first call leg in Originate @see call_exec
    if (config_lookup_string(&cfg, "originate.incontext", &value) == CONFIG_TRUE) {
        strcpy(conference_config.incontext, value);
    }
    // Outgoing context for second call leg in Originate @see call_exec
    if (config_lookup_string(&cfg, "originate.outcontext", &value) == CONFIG_TRUE) {
        strcpy(conference_config.outcontext, value);
    }

    // Autoanwer variable (0,1) for incontext dialplan process
    if (config_lookup_int(&cfg, "originate.autoanswer", &intvalue) == CONFIG_TRUE) {
        conference_config.autoanswer = intvalue;
    }

    // Dealloc libconfig structure
    config_destroy(&cfg);

    isaac_log(LOG_VERBOSE_3, "Readed configuration from %s\n", cfile);
    return 0;
}

/**
 * @brief Get Conference Info structure of a given id
 *
 * Loop through all session filters searching for a conference info
 * structure with the given id.
 *
 * @param sess Session Structure
 * @param id ID supplied in CALL action
 * @return Conference info structure pointer
 */
struct app_conference_info *
get_conference_info_from_id(session_t *sess, const char *id)
{
    filter_t *filter = NULL;
    struct app_conference_info *info = NULL;
    // Get session filter and search the one with that id
    while ((filter = filter_from_session(sess, filter))) {
        info = (struct app_conference_info *) filter_get_userdata(filter);
        // We found the requested action!
        if (info && !strcasecmp(id, info->actionid)) {
            return info;
        }
    }
    return NULL;
}

/**
 * @brief Writes to session CONFERENCESTATUS messages
 *
 * This function sends the CONFERENCESTATUS to a session when some filter
 * events triggers.
 *
 * This function will be callbacked when one of this happens:
 *  - A channel sets ACTIONID variable: This gave us leg1 channel
 *  - This channel begins a Meetme application
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
int
conference_state(filter_t *filter, ami_message_t *msg)
{

    return 0;
}

/**
 * @brief CONFERENCE action entry point
 *
 * Originates a call with the given action id on current session.
 *
 * This function will generate a call using Originate AMI command and add
 * a filter for capturing generated channel. The first leg of the call (going
 * to the registered session agent) will be sent to the configured incoming context
 * (@ref app_conference_config::incontext) that is expected to make a Dial to the configured
 * outgoing context (@ref app_conferece_config::outcontext).
 *
 * - CONFERENCE action requires that session is authenticated (usually through LOGIN action).
 * - CONFERENCE action receives two arguments: An unique actionid that can be used to make other
 *      actions with the generated conference and a coma separated list of extensions to invite.
 *
 * @param sess Session running this application
 * @param app The application structure
 * @param args Call action args "ActionID DestNum"
 * @return 0 in call cases
 */
int
conference_exec(session_t *sess, app_t *app, const char *args)
{
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Command length
    size_t clen = strlen(args);

    // Allocate memory for read input
    char *actionid = malloc(clen);
    char *extensions = malloc(clen);
    char *options = malloc(clen);

    // Get Call parameters
    if (sscanf(args, "%s %s %[^\n]", actionid, extensions, options) < 2) {
        free(actionid);
        free(extensions);
        free(options);
        return INVALID_ARGUMENTS;
    }

    // Initialize application info
    struct app_conference_info *info = malloc(sizeof(struct app_conference_info));
    if (info == NULL) {
        free(actionid);
        free(extensions);
        free(options);
        return INTERNAL_ERROR;
    }

    // Initialize Conference structure
    memset(info, 0, sizeof(struct app_conference_info));

    // Store action id for this request
    info->actionid = actionid;

    // Store extensions to be called
    char *saveptr = NULL;
    char *exten = strtok_r(extensions, ",", &saveptr);
    while (exten != NULL) {
        info->extensions[info->extensioncnt] = exten;
        info->extensioncnt++;
        exten = strtok_r(extensions, ",", &saveptr);
    }

    // Validate we have at least one extension
    if (info->extensioncnt) {
        free(actionid);
        free(extensions);
        free(options);
        free(info);
        return INVALID_ARGUMENTS;
    }

    // Check if uniqueid info is requested
    app_args_t parsed;
    application_parse_args(options, &parsed);

    if (!isaac_strcmp(application_get_arg(&parsed, "BRD"), "1"))
        info->broadcast = 1;

    // Register a Filter to get Generated Channel
    info->conference_filter = filter_create_async(sess, conference_state);
    filter_new_condition(info->conference_filter, MATCH_EXACT, "Event", "VarSet");
    filter_new_condition(info->conference_filter, MATCH_EXACT, "Variable", "ACTIONID");
    filter_new_condition(info->conference_filter, MATCH_EXACT, "Value", actionid);
    filter_set_userdata(info->conference_filter, (void*) info);
    filter_register_oneshot(info->conference_filter);

    // Get the logged agent
    const char *agent = session_get_variable(sess, "AGENT");

    // Construct a Request message
    ami_message_t msg;
    memset(&msg, 0, sizeof(ami_message_t));
    message_add_header(&msg, "Action: Originate");
    message_add_header(&msg, "CallerID: %s", agent);
    message_add_header(&msg, "Channel: Local/%s@%s", agent, conference_config.incontext);
    message_add_header(&msg, "Context: %s", conference_config.outcontext);
    message_add_header(&msg, "Priority: 1");
    message_add_header(&msg, "ActionID: %s", actionid);
    message_add_header(&msg, "Exten: %s", agent);
    message_add_header(&msg, "Async: 1");
    message_add_header(&msg, "Variable: ACTIONID=%s", actionid);
    message_add_header(&msg, "Variable: AUTOANSWER=%d", conference_config.autoanswer);

    // Set variable to indicate conference type
    if (application_get_arg(&parsed, "BRD"))
        message_add_header(&msg, "Variable: ISAAC_CONF_BRD=YES");

    // Send this message to ami
    manager_write_message(manager, &msg);

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
int
load_module()
{
    int res = 0;
    if (read_conference_config(CONFERENCECONF) != 0) {
        isaac_log(LOG_ERROR, "Failed to read app_call config file %s\n", CONFERENCECONF);
        return -1;
    }
    res |= application_register("Conference", conference_exec);
    return res;
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
    int res = 0;
    res |= application_unregister("Conference");
    return res;
}
