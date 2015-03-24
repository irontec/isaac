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
    //char rol[20];
    //! Autoanswer flag. Does not work in all terminals.
    int autoanswer;
    //! File recorded path
    char record_path[512];
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
    char actionid[ACTIONID_LEN];
    //! Filter for capturing the events of Dialed channels
    filter_t *callfilter;
    //! Filter for capturing the events of agent channel
    filter_t *ofilter;
    //! Filter for capturing the events of remote channel
    filter_t *dfilter;
    //! Original call destiny
    char destiny[50];
    //! Agent Channel UniqueID
    char ouid[50];
    //! Remote Channel UniqueID
    char duid[50];
    //! Agent Channel Name
    char ochannel[50];
    //! Remote Channel Name
    char dchannel[50];
    //! Flag: This call is being Recorded
    bool recording;
    //! Flag for printing uniqueid info
    bool print_uniqueid;
    //! Flag for broadcasting call info
    bool broadcast;

    //! Store recording vars
    char grabaciones_modulo[512];
    char grabaciones_tipo[1024];
    char grabaciones_plataforma[2048];
    char grabaciones_origen[2048];
    char grabaciones_destino[2048];
    char grabaciones_fecha_hora[2048];
    char grabaciones_ruta[4086];;
    char grabaciones_fichero[4086];
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
    //if (config_lookup_string(&cfg, "originate.rol", &value) == CONFIG_TRUE) {
    //    strcpy(call_config.rol, value);
    //}

    // Autoanwer variable (0,1) for incontext dialplan process
    if (config_lookup_int(&cfg, "originate.autoanswer", &intvalue) == CONFIG_TRUE) {
        call_config.autoanswer = intvalue;
    }

    // Filepat to store the recordings
    if (config_lookup_string(&cfg, "record.filepath", &value) == CONFIG_TRUE) {
        strcpy(call_config.record_path, value);
    }

    // Dealloc libconfig structure
    config_destroy(&cfg);

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
    while ((filter = filter_from_session(sess, filter))) {
        info = (struct app_call_info *) filter_get_userdata(filter);
        // We found the requested action!
        if (info && !strcasecmp(id, info->actionid)) {
            return info;
        }
    }
    return NULL;
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
    char from[80], state[80], uniqueid[80], response[256];
    bool finished = false;
 
    // Initialize arrays
    memset(from,        0, sizeof(from));
    memset(state,       0, sizeof(state));
    memset(uniqueid,    0, sizeof(uniqueid));
    memset(response,    0, sizeof(response));

    // So this leg is first one or second one?
    if (!strcasecmp(message_get_header(msg, "UniqueID"), info->ouid)) {
        isaac_strcpy(from, "AGENT");
    } else {
        isaac_strcpy(from, "REMOTE");
    }

    // Send CallStatus message depending on received event
    if (!strcasecmp(event, "Hangup")) {
        // Print status message dpending on Hangup Cause
        const char *cause = message_get_header(msg, "Cause");
        if (!strcasecmp(cause, "0") || !strcasecmp(cause, "21")) {
            isaac_strcpy(state, "ERROR");
        } else if (!strcasecmp(cause, "16")) {
            isaac_strcpy(state, "HANGUP");
        } else if (!strcasecmp(cause, "17")) {
            isaac_strcpy(state, "BUSY");
        } else {
            sprintf(state, "UNKNOWNHANGUP %s", cause);
        }

        // This call info has ended
        finished = true;

    } else if (!strcasecmp(event, "MusicOnHold")) {
        if (!strcasecmp(message_get_header(msg, "State"), "Start")) {
            isaac_strcpy(state, "HOLD");
        } else {
            isaac_strcpy(state, "UNHOLD");
        }

        // In this case, the channel that receives the Hold event is the
        // one that is being hold, not holding. So we should swap the
        // AGENT <-> REMOVE value
        if (!strcasecmp(message_get_header(msg, "UniqueID"), info->ouid)) {
            isaac_strcpy(from, "REMOTE");
        } else {
            isaac_strcpy(from, "AGENT");
        }

    } else if (!strcasecmp(event, "Newstate")) {
        // Print status message depending on Channel Status
        const char *chanstate = message_get_header(msg, "ChannelState");
        if (!strcasecmp(chanstate, "5")) {
            isaac_strcpy(state, "RINGING");
        } else if (!strcasecmp(chanstate, "6")) {
            isaac_strcpy(state, "ANSWERED");
        }
    } else if (!strcasecmp(event, "Rename")) {
        if (!strcasecmp(message_get_header(msg, "UniqueID"), info->ouid)) {
            strcpy(info->ochannel, message_get_header(msg, "NewName"));
        }
    } else if (!strcasecmp(event, "VarSet")) {
        const char *varvalue = message_get_header(msg, "Value");
        const char *varname = message_get_header(msg, "Variable");

        // Progress event on cellphones
        if (!strcasecmp(varvalue, "SIP 183 Session Progress")) {
            isaac_strcpy(state, "PROGRESS");
        }

        // Update recording variables
        if (!strncasecmp(varname, "GRABACIONES_", 12)) {
            char recordvar[256],recorduniqueid[80], grabaciones[80], recordtype[80];
            isaac_strcpy(recordvar, varname);
            if (sscanf(recordvar, "%[^_]_%[^_]_%s", grabaciones, recorduniqueid, recordtype) == 3) {
                if (!strcasecmp(recordtype, "MODULO"))     sprintf(info->grabaciones_modulo, "%s;", varvalue);
                if (!strcasecmp(recordtype, "TIPO"))       sprintf(info->grabaciones_tipo, "%s;", varvalue);
                if (!strcasecmp(recordtype, "PLATAFORMA")) sprintf(info->grabaciones_plataforma, "%s;", varvalue);
                if (!strcasecmp(recordtype, "ORIGEN"))     sprintf(info->grabaciones_origen, "%s;", varvalue);
                if (!strcasecmp(recordtype, "DESTINO"))    sprintf(info->grabaciones_destino, "%s;", varvalue);
                if (!strcasecmp(recordtype, "FECHA_HORA")) sprintf(info->grabaciones_fecha_hora, "%s;", varvalue);
                if (!strcasecmp(recordtype, "RUTA"))       sprintf(info->grabaciones_ruta, "%s;", varvalue);
                if (!strcasecmp(recordtype, "FICHERO"))    sprintf(info->grabaciones_fichero, "%s;", varvalue);
            } else {
                isaac_log(LOG_WARNING, "Unhandled record variable %s\n", varname);
            }
        }

        // A channel has set ACTIONID var, this is our leg1 channel. It will Dial soon!
        if (!strcasecmp(varname, "ACTIONID")) {
            // Get the UniqueId from the agent channel
            isaac_strcpy(info->ouid, message_get_header(msg, "UniqueID"));
            // Store provisional Channel Name
            isaac_strcpy(info->ochannel, message_get_header(msg, "Channel"));
            // This messages are always from agent
            isaac_strcpy(from, "AGENT");

            // Register a Filter for the agent statusthe custom manager application PlayDTMF.
            info->ofilter = filter_create_async(filter->sess, call_state);
            filter_new_condition(info->ofilter, MATCH_REGEX, "Event", "Hangup|MusicOnHold|Newstate|Rename|VarSet|Dial");
            filter_new_condition(info->ofilter, MATCH_EXACT, "UniqueID", info->ouid);
            filter_set_userdata(info->ofilter, (void*) info);
            filter_register(info->ofilter);

            // Tell the client the channel is going on!
            isaac_strcpy(state, "STARTING"); 
        }
    } else if (!strcasecmp(event, "Dial") && !strcasecmp(message_get_header(msg, "SubEvent"),
            "Begin")) {
        // Get the UniqueId from the agent channel
        strcpy(info->duid, message_get_header(msg, "DestUniqueID"));
        strcpy(info->dchannel, message_get_header(msg, "Destination"));

        // Register a Filter for the agent status
        info->dfilter = filter_create_async(filter->sess, call_state);
        filter_set_userdata(info->dfilter, info);
        filter_new_condition(info->ofilter, MATCH_REGEX, "Event", "Hangup|MusicOnHold|Newstate|Rename|VarSet|Dial");
        filter_new_condition(info->dfilter, MATCH_EXACT, "UniqueID", info->duid);
        filter_register(info->dfilter);

        // This messages are always from agent
        isaac_strcpy(from, "REMOTE");

        // Store the call state
        isaac_strcpy(state, "STARTING");
    }


    // Built the event message
    if (strlen(state)) {
        // Add Uniqueid to response if requested
        if (info->print_uniqueid) {
            isaac_strcpy(uniqueid, !strcasecmp(from, "AGENT")?info->ouid:info->duid);
            sprintf(response, "CALLSTATUS %s %s %s %s\r\n", info->actionid, uniqueid, from, state);
        } else {
            sprintf(response, "CALLSTATUS %s %s %s\r\n", info->actionid, from, state);
        }

        // Send this message to other clients if requested
        if (info->broadcast) {
            session_write_broadcast(filter->sess, response);
        } else {
            session_write(filter->sess, response);
        }
    }

    // We dont expect more info about this filter, it's safe to unregister it here
    if (finished)
        filter_unregister(filter);

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
 * @param app The application structure
 * @param args Call action args "ActionID DestNum"
 * @return 0 in call cases
 */
int
call_exec(session_t *sess, app_t *app, const char *args)
{
    char actionid[ACTIONID_LEN];
    char exten[20], options[80];

    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Get Call parameteres
    if (sscanf(args, "%s %s %[^\n]", actionid, exten, options) < 2) {
        return INVALID_ARGUMENTS;
    }

    // Initialize application info
    struct app_call_info *info = malloc(sizeof(struct app_call_info));
    memset(info, 0, sizeof(struct app_call_info));
    isaac_strcpy(info->actionid, actionid);
    isaac_strcpy(info->destiny, exten);

    // Check if uniqueid info is requested
    app_args_t parsed;
    application_parse_args(options, &parsed);

    if (!isaac_strcmp(application_get_arg(&parsed, "WUID"), "1"))
        info->print_uniqueid = 1;

    if (!isaac_strcmp(application_get_arg(&parsed, "BRD"), "1"))
        info->broadcast = 1;

    // Register a Filter to get Generated Channel
    info->callfilter = filter_create_async(sess, call_state);
    filter_new_condition(info->callfilter, MATCH_EXACT, "Event", "VarSet");
    filter_new_condition(info->callfilter, MATCH_EXACT, "Variable", "ACTIONID");
    filter_new_condition(info->callfilter, MATCH_EXACT, "Value", actionid);
    filter_set_userdata(info->callfilter, (void*) info);
    filter_register_oneshot(info->callfilter);

    // Get the logged agent
    const char *agent = session_get_variable(sess, "AGENT");
    const char *rol = session_get_variable(sess, "ROL");

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
    message_add_header(&msg, "Variable: ROL=%s", rol);
    message_add_header(&msg, "Variable: CALLERID=%s", agent);
    message_add_header(&msg, "Variable: DESTINO=%s", exten);
    message_add_header(&msg, "Variable: AUTOANSWER=%d", call_config.autoanswer);

    // Forced CLID from application arguments
    if (application_get_arg(&parsed, "CLID"))
        message_add_header(&msg, "Variable: ISAAC_FORCED_CLID=%s", 
            application_get_arg(&parsed, "CLID"));

    // Forced Timeout from application arguments
    if (application_get_arg(&parsed, "TIMEOUT"))
        message_add_header(&msg, "Variable: ISAAC_CALL_TIMEOUT=%s", 
            application_get_arg(&parsed, "TIMEOUT"));

    // Send this message to ami
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
 * @param app The application structure
 * @param args Dtmf action args "ActionID DTMFDigit"
 * @return 0 if the call is found, -1 otherwise
 */
int
dtmf_exec(session_t *sess, app_t *app, const char *args)
{
    struct app_call_info *info;
    char actionid[ACTIONID_LEN];
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
        usleep(300 * 1000); // Wait 300 ms before accepting any other command
        session_write(sess, "DTMFOK\r\n");
    } else {
        session_write(sess, "DTMFFAILED ID NOT FOUND\r\n");
        return -1;
    }
    return 0;
}

/**
 * @brief Hangup action entry point
 *
 * Hangup action will Hangup the first channel generated using
 * CALL action using the manager application Hangup. The hangup
 * events will still be parsed by @ref call_state function, unregistering
 * the pending filters
 *
 * @param sess Session rnuning this application
 * @param app The application structure
 * @param args Hangup action args "ActionID"
 * @return 0 if the call is found, -1 otherwise
 */
int
hangup_exec(session_t *sess, app_t *app, const char *args)
{
    struct app_call_info *info;
    char actionid[ACTIONID_LEN];

    // This can only be done after authentication
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Get Hangup parameteres
    if (sscanf(args, "%s", actionid) != 1) {
        return INVALID_ARGUMENTS;
    }

    // Try to find the action info of the given actionid
    if ((info = get_call_info_from_id(sess, actionid))) { 
        if (!isaac_strlen_zero(info->ochannel)) {
            ami_message_t msg;
            memset(&msg, 0, sizeof(ami_message_t));
            message_add_header(&msg, "Action: Hangup");
            message_add_header(&msg, "Channel: %s", info->ochannel);
            manager_write_message(manager, &msg);
            session_write(sess, "HANGUPOK\r\n");
        } else {
            session_write(sess, "HANGUPFAILED CHANNEL NOT FOUND\r\n");
        }
    } else {
        session_write(sess, "HANGUPFAILED ID NOT FOUND\r\n");
        return -1;
    }
    return 0;
}

/**
 * @brief Hold action entry point
 *
 * Hold action will send an event to the first channel generated by
 * CALL action using the manager application SIPNotifyChan. Not all
 * terminals support hold event.
 *
 * @param sess Session rnuning this application
 * @param app The application structure
 * @param args Hangup action args "ActionID"
 * @return 0 if the call is found, -1 otherwise
 */
int
hold_unhold_exec(session_t *sess, app_t *app, const char *args)
{
    struct app_call_info *info;
    char actionid[ACTIONID_LEN];
    char action[10];
    int i;

    // This can only be done after authentication
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Get Hangup parameteres
    if (sscanf(args, "%s", actionid) != 1) {
        return INVALID_ARGUMENTS;
    }

    // Convert action to uppercase
    isaac_strcpy(action, app->name);
    for (i=0; action[i]; i++){
        action[i] = (char) toupper(action[i]);
    }

    // Try to find the action info of the given actionid
    if ((info = get_call_info_from_id(sess, actionid)) && !isaac_strlen_zero(info->ochannel)) {
        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: SIPNotifyChan");
        message_add_header(&msg, "Channel: %s", info->ochannel);
        message_add_header(&msg, "Event: %s", ((!strcasecmp(app->name, "Hold"))?"hold":"talk"));
        manager_write_message(manager, &msg);
        session_write(sess, "%sOK\r\n", action);
    } else {
        session_write(sess, "%sFAILED ID NOT FOUND\r\n", action);
        return -1;
    }
    return 0;
}

/**
 * @brief Record action entry point
 *
 * Record action will start MixMonitor on given channel and will
 * set some variables for record post processing (in h extension).
 *
 * @param sess Session rnuning this application
 * @param app The application structure
 * @param args Hangup action args "ActionID" and "UniqueID"
 * @return 0 if the call is found, -1 otherwise
 */
int
record_exec(session_t *sess, app_t *app, const char *args)
{
    struct app_call_info *info;
    char actionid[ACTIONID_LEN];
    char filename[128];
    time_t timer;
    char timestr[25];
    struct tm* tm_info;

    // This can only be done after authentication
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Get Hangup parameteres
    if (sscanf(args, "%s %s", actionid, filename) != 2) {
        return INVALID_ARGUMENTS;
    }

    // Try to find the action info of the given actionid
    if ((info = get_call_info_from_id(sess, actionid)) && !isaac_strlen_zero(info->ochannel)) {

        // Check if this call is already being recorded
        if (info->recording) {
            session_write(sess, "RECORDFAILED CALL IS ALREADY BEING RECORDED\r\n");
            return -1;
        }

        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: MixMonitor");
        message_add_header(&msg, "Channel: %s", info->ochannel);
        message_add_header(&msg, "File: %s/%s.wav", call_config.record_path, filename);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->ochannel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_MODULO", info->ouid);
        message_add_header(&msg, "Value: %sCC", info->grabaciones_modulo);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->ochannel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_PLATAFORMA", info->ouid);
        message_add_header(&msg, "Value: %s", info->grabaciones_plataforma);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->ochannel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_TIPO", info->ouid);
        message_add_header(&msg, "Value: %son-demand_ISAAC", info->grabaciones_tipo);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->ochannel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_ORIGEN", info->ouid);
        message_add_header(&msg, "Value: %s%s",info->grabaciones_origen,session_get_variable(sess, "AGENT"));
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->ochannel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_DESTINO", info->ouid);
        message_add_header(&msg, "Value: %s%s",info->grabaciones_destino, info->destiny);
        manager_write_message(manager, &msg);

        time(&timer);
        tm_info = localtime(&timer);
        strftime(timestr, 25, "%Y:%m:%d_%H:%M:%S", tm_info);
        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->ochannel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_FECHA_HORA", info->ouid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_fecha_hora, timestr);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->ochannel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_RUTA", info->ouid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_ruta, call_config.record_path);
        manager_write_message(manager, &msg);
        
        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->ochannel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_FICHERO", info->ouid);
        message_add_header(&msg, "Value: %s%s.wav", info->grabaciones_fichero, filename);
        manager_write_message(manager, &msg);

        // Flag this call as being recorded
        info->recording = true;

        session_write(sess, "RECORDOK\r\n");
    } else {
        session_write(sess, "RECORDFAILED ID NOT FOUND\r\n");
        return -1;
    }
    return 0;
}


/**
 * @brief Record action entry point
 *
 * Record action will start MixMonitor on given channel and will
 * set some variables for record post processing (in h extension).
 *
 * @param sess Session rnuning this application
 * @param app The application structure
 * @param args Hangup action args "ActionID" and "UniqueID"
 * @return 0 if the call is found, -1 otherwise
 */
int
recordstop_exec(session_t *sess, app_t *app, const char *args)
{
    struct app_call_info *info;
    char actionid[ACTIONID_LEN];

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

        // Check if this call is not being recorded
        if (!info->recording) {
            session_write(sess, "RECORDSTOPFAILED CALL NOT BEING RECORDED\r\n");
            return -1;
        }

        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Command");
        message_add_header(&msg, "Command: mixmonitor stop %s", info->ochannel);
        manager_write_message(manager, &msg);

        // Flag this call as not being recorded
        info->recording = false;

        session_write(sess, "RECORDSTOPOK\r\n");
    } else {
        session_write(sess, "RECORDSTOPFAILED ID NOT FOUND\r\n");
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
    res |= application_register("Hold", hold_unhold_exec);
    res |= application_register("Unhold", hold_unhold_exec);
    res |= application_register("Record", record_exec);
    res |= application_register("RecordStop", recordstop_exec);
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
    res |= application_unregister("Hold");
    res |= application_unregister("Unhold");
    res |= application_unregister("Record");
    res |= application_unregister("RecordStop");
    return res;
}
