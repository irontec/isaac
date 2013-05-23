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
 * @file app_call.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Module for manage originated calls through AMI
 *
 * @warning This module is customized for Ivoz-NG. If won't work without the
 *  required contexts conifgured in asterisk.
 *
 * This is a basic module of Isaac that implements some actios for placing
 * calls into asterisk.\n To make this module work, it must configured using
 * CALLCONF file (usually /etc/isaac/call.conf) and defining the desired contexts
 * in asterisk.
 *
 */
#include <libconfig.h>
#include "app.h"
#include "manager.h"
#include "filter.h"
#include "log.h"

/**
 * @brief Module configuration readed from CALLCONF file
 *
 * @see read_call_config
 */
struct app_call_config
{
    //! Context to originate the first leg during CALL action
    char incontext[80];
    //! Context to originate the second leg during CALL action
    char outcontext[80];
    //! Custom variable of Ivoz-NG to determine the context behaviour
    char rol[20];
    //! Autoanswer flag. Does not work in all terminals.
    int autoanswer;
} call_config;

/**
 * @brief Common structure for Call filters
 *
 * This structure contains the shared information between different
 * filters of the same call.
 */
struct app_call_info
{
    //! Unique ID supplied during CALL action
    char actionid[20];
    //! Filter for capturing the events of Dialed channels
    filter_t *callfilter;
    //! Filter for capturing the events of agent channel
    filter_t *ofilter;
    //! Filter for capturing the events of remote channel
    filter_t *dfilter;
    //! Agent Channel UniqueID
    char ouid[50];
    //! Remote Channel UniqueID
    char duid[50];
    //! Agent Channel Name
    char ochannel[50];
    //! Remote Channel Name
    char dchannel[50];
};

/**
 * @brief Read module configure options
 *
 * This function will read CALLCONF file and fill app_call_conf
 * structure. Most of these values are using during call action process
 * @see call_exec
 *
 * @param cfile Full path to configuration file
 * @return 0 in case of read success, -1 otherwise
 */
int
read_call_config(const char *cfile)
{
    config_t cfg;
    const char *value;
    long int intvalue;

    // Initialize configuration
    config_init(&cfg);

    // Read configuraiton file
    if (config_read_file(&cfg, cfile) == CONFIG_FALSE) {
        isaac_log(LOG_ERROR, "Error parsing configuration file %s on line %d: %s\n", cfile,
                config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return -1;
    }

    // Incoming context for first call leg in Originate @see call_exec
    if (config_lookup_string(&cfg, "originate.incontext", &value) == CONFIG_TRUE) {
        strcpy(call_config.incontext, value);
    }
    // Outgoing context for second call leg in Originate @see call_exec
    if (config_lookup_string(&cfg, "originate.outcontext", &value) == CONFIG_TRUE) {
        strcpy(call_config.outcontext, value);
    }
    // Rol variable (AGENTE, USUARIO) for incontext dialplan process
    if (config_lookup_string(&cfg, "originate.rol", &value) == CONFIG_TRUE) {
        strcpy(call_config.rol, value);
    }
    // Autoanwer variable (0,1) for incontext dialplan process
    if (config_lookup_int(&cfg, "originate.autoanswer", &intvalue) == CONFIG_TRUE) {
        call_config.autoanswer = intvalue;
    }

    isaac_log(LOG_VERBOSE_3, "Readed configuration from %s\n", cfile);
    return 0;
}

/**
 * @brief Get Call Info structure of a given id
 *
 * Loop through all session filters searching for a call info
 * structure with the given id.
 *
 * @todo I think I should implement locking here, a filter could be
 * unregistering while it is being searched.
 *
 * @param sess Session Structure
 * @param id ID supplied in CALL action
 * @return Call info structure
 */
struct app_call_info *
get_call_info_from_id(session_t *sess, const char *id)
{
    filter_t *filter = NULL;
    struct app_call_info *info = NULL;
    // Get session filter and search the one with that id
    while ((filter = get_session_filter(sess, filter))) {
        info = (struct app_call_info *) filter_get_userdata(filter);
        // We found the requested action!
        if (info && !strcasecmp(id, info->actionid)) {
            break;
        }
    }
    return info;
}

/**
 * @brief Writes to session CALLEVENT messages
 *
 * This function sends the CALLEVENTS to a session when some filter
 * events triggers. It is used for Agent and Remote channel events.\n
 *
 * This function will be callbacked when one of this happens:\n
 *  - A channel sets ACTIONID variable: This gave us leg1 channel\n
 *  - This channel begins a Dial Action: This gave us the second leg\n
 *  - Events on any of these two channels\n
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
int
call_state(filter_t *filter, ami_message_t *msg)
{
    // Get Call information
    struct app_call_info *info = (struct app_call_info *) filter_get_userdata(filter);
    // Get message event
    const char *event = message_get_header(msg, "Event");
    const char *from, *to;

    // So this leg is first one or second one?
    if (!strcasecmp(message_get_header(msg, "UniqueID"), info->ouid)) {
        from = "AGENT";
        to = "REMOTE";
    } else {
        from = "REMOTE";
        to = "AGENT";
    }

    // Send CallStatus message depending on received event
    if (!strcasecmp(event, "Hangup")) {
        // Print status message dpending on Hangup Cause
        const char *cause = message_get_header(msg, "Cause");
        if (!strcasecmp(cause, "0") || !strcasecmp(cause, "21")) {
            session_write(filter->sess, "CALLSTATUS %s %s ERROR\n", info->actionid, from);
        } else if (!strcasecmp(cause, "16")) {
            session_write(filter->sess, "CALLSTATUS %s %s HANGUP\n", info->actionid, from);
        } else if (!strcasecmp(cause, "17")) {
            session_write(filter->sess, "CALLSTATUS %s %s BUSY\n", info->actionid, from);
        } else {
            session_write(filter->sess, "CALLSTATUS %s %s UNKOWNHANGUP %s\n", info->actionid, from,
                    cause);
        }

        // We dont expect more info about this filter, it's safe to unregister it here
        filter_unregister(filter);

    } else if (!strcasecmp(event, "Newstate")) {
        // Print status message depending on Channel Status
        const char *state = message_get_header(msg, "ChannelState");
        if (!strcasecmp(state, "5")) {
            session_write(filter->sess, "CALLSTATUS %s %s RINGING\n", info->actionid, from);
        } else if (!strcasecmp(state, "6")) {
            session_write(filter->sess, "CALLSTATUS %s %s ANSWERED\n", info->actionid, from);
        }
    } else if (!strcasecmp(event, "VarSet")) {
        const char *varvalue = message_get_header(msg, "Value");
        const char *varname = message_get_header(msg, "Variable");

        // Progress event on cellphones
        if (!strcasecmp(varvalue, "SIP 183 Session Progress")) {
            session_write(filter->sess, "CALLSTATUS %s %s PROGRESS\n", info->actionid, to);
        }

        // A channel has set ACTIONID var, this is our leg1 channel. It will Dial soon!
        if (!strcasecmp(varname, "ACTIONID")) {
            // Get the UniqueId from the agent channel
            strcpy(info->ouid, message_get_header(msg, "UniqueID"));

            // Register a Filter for the agent statusthe custom manager application PlayDTMF.
            info->ofilter = filter_create(filter->sess, FILTER_SYNC_CALLBACK, call_state);
            filter_new_condition(info->ofilter, MATCH_EXACT, "UniqueID", info->ouid);
            filter_set_userdata(info->ofilter, (void*) info);
            filter_register(info->ofilter);

            // Tell the client the channel is going on!
            session_write(filter->sess, "CALLSTATUS %s AGENT STARTING\n", info->actionid);

            // Remove this filter, we have the uniqueID
            filter_unregister(info->callfilter);
        }
    } else if (!strcasecmp(event, "Dial") && !strcasecmp(message_get_header(msg, "SubEvent"),
            "Begin")) {
        // Get the UniqueId from the agent channel
        strcpy(info->duid, message_get_header(msg, "DestUniqueID"));
        strcpy(info->ochannel, message_get_header(msg, "Channel"));
        strcpy(info->dchannel, message_get_header(msg, "Destination"));

        // Register a Filter for the agent status
        info->dfilter = filter_create(filter->sess, FILTER_SYNC_CALLBACK, call_state);
        info->dfilter->app_info = info;
        filter_new_condition(info->dfilter, MATCH_EXACT, "UniqueID", info->duid);
        filter_register(info->dfilter);

        // Say we have the remote channel
        session_write(filter->sess, "CALLSTATUS %s REMOTE STARTING\n", info->actionid);
    }

    return 0;
}

/**
 * @brief CALL action entry point
 *
 * Originates a call with the given action id on current session.\n
 * This function will generate a call using Originate AMI command and add
 * a filter for capturing generated channel.\n The first leg of the call (going
 * to the registered session agent) will be sent to the configured incoming context
 * (@ref app_call_config::incontext) that is expected to make a Dial to the configured
 * outgoing context (@ref app_call_config::outcontext).\n
 *
 * - CALL action requires that session is authenticated (usually through
 * LOGIN action).\n
 * - CALL action receives two arguments: An unique actionid that can be used
 * to make other actions with the generated call (such as Hanguping or sending
 * DTMF codes) and the number that is wanted to call.\n
 *
 * @param sess Session rnuning this application
 * @param args Call action args "ActionID DestNum"
 * @return 0 in call cases
 */
int
call_exec(session_t *sess, const char *args)
{
    char actionid[20];
    char exten[20];

    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Get Call parameteres
    if (sscanf(args, "%s %s", actionid, exten) != 2) {
        return INVALID_ARGUMENTS;
    }

    // Initialize application info
    struct app_call_info *info = malloc(sizeof(struct app_call_info));
    memset(info, 0, sizeof(struct app_call_info));
    strcpy(info->actionid, actionid);

    // Register a Filter to get Generated Channel
    info->callfilter = filter_create(sess, FILTER_SYNC_CALLBACK, call_state);
    filter_new_condition(info->callfilter, MATCH_EXACT, "Event", "VarSet");
    filter_new_condition(info->callfilter, MATCH_EXACT, "Variable", "ACTIONID");
    filter_new_condition(info->callfilter, MATCH_EXACT, "Value", actionid);
    filter_set_userdata(info->callfilter, (void*) info);
    filter_register(info->callfilter);

    // Get the logged agent
    const char *agent = session_get_variable(sess, "AGENT");

    // Construct a Request message
    ami_message_t msg;
    memset(&msg, 0, sizeof(ami_message_t));
    message_add_header(&msg, "Action: Originate");
    message_add_header(&msg, "CallerID: %s", agent);
    message_add_header(&msg, "Channel: Local/%s@%s", agent, call_config.incontext);
    message_add_header(&msg, "Context: %s", call_config.outcontext);
    message_add_header(&msg, "Priority: 1");
    message_add_header(&msg, "ActionID: %s", actionid);
    message_add_header(&msg, "Exten: %s", exten);
    message_add_header(&msg, "Async: 1");
    message_add_header(&msg, "Variable: ACTIONID=%s", actionid);
    message_add_header(&msg, "Variable: ROL=%s", call_config.rol);
    message_add_header(&msg, "Variable: CALLERID=%s", agent);
    message_add_header(&msg, "Variable: AUTOANSWER=%d", call_config.autoanswer);
    manager_write_message(manager, &msg);

    return 0;
}

/**
 * @brief DTMF action entry point
 *
 * DTMF action will send a DTMF code to a second channel generated using
 * CALL action using the custom manager application PlayDTMF.
 *
 * @param sess Session rnuning this applicationthe custom manager application PlayDTMF.
 * @param args Dtmf action args "ActionID DTMFDigit"
 * @return 0 if the call is found, -1 otherwise
 */
int
dtmf_exec(session_t *sess, const char *args)
{
    struct app_call_info *info;
    char actionid[20];
    char digit[20];

    // This can only be done after authentication
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Get Hangup parameteres
    if (sscanf(args, "%s %s", actionid, digit) != 2) {
        return INVALID_ARGUMENTS;
    }

    // Try to find the action info of the given actionid
    if ((info = get_call_info_from_id(sess, actionid)) && !isaac_strlen_zero(info->dchannel)) {
        // Send the digit to remote channel using PlayDTMF manager action
        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: PlayDTMF");
        message_add_header(&msg, "Channel: %s", info->dchannel);
        message_add_header(&msg, "Digit: %s", digit);
        manager_write_message(manager, &msg);
        session_write(sess, "DTMFOK\n");
    } else {
        session_write(sess, "DTMFFAILED ID NOT FOUND\n");
        return -1;
    }
    return 0;
}

/**
 * @brief Hangup action entry point
 *
 * Hangup action will Hangup the firs channel generated using
 * CALL action using the manager application Hangup. The hangup
 * events will still be parsed by @ref call_state function, unregistering
 * the pending filters
 *
 * @param sess Session rnuning this application
 * @param args Hangup action args "ActionID"
 * @return 0 if the call is found, -1 otherwise
 */
int
hangup_exec(session_t *sess, const char *args)
{
    struct app_call_info *info;
    char actionid[20];

    // This can only be done after authentication
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Get Hangup parameteres
    if (sscanf(args, "%s", actionid) != 1) {
        return INVALID_ARGUMENTS;
    }

    // Try to find the action info of the given actionid
    if ((info = get_call_info_from_id(sess, actionid)) && !isaac_strlen_zero(info->ochannel)) {
        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Hangup");
        message_add_header(&msg, "Channel: %s", info->ochannel);
        manager_write_message(manager, &msg);
        session_write(sess, "HANGUPOK\n");
    } else {
        session_write(sess, "HANGUPFAILED ID NOT FOUND\n");
        return -1;
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
int
load_module()
{
    int res = 0;
    if (read_call_config(CALLCONF) != 0) {
        isaac_log(LOG_ERROR, "Failed to read app_call config file %s\n", CALLCONF);
        return -1;
    }
    res |= application_register("Call", call_exec);
    res |= application_register("Hangup", hangup_exec);
    res |= application_register("Dtmf", dtmf_exec);
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
    res |= application_unregister("Call");
    res |= application_unregister("Hangup");
    res |= application_unregister("Dtmf");
    return res;
}
