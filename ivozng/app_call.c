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
#include "config.h"
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

#define CALLCONF CONFDIR "/call.conf"

/**
 * @brief Module configuration read from CALLCONF file
 *
 * @see read_call_config
 */
typedef struct
{
    //! Context to originate the first leg during CALL action
    gchar *incontext;
    //! Context to originate the second leg during CALL action
    gchar *outcontext;
    //! Auto-answer flag. Does not work in all terminals.
    gboolean autoanswer;
    //! File recorded path
    gchar *record_path;
} AppCallConfig;

/**
 * @brief Common structure for Call filters
 *
 * This structure contains the shared information between different
 * filters of the same call.
 */
typedef struct
{
    //! Unique ID supplied during CALL action
    gchar *actionid;
    //! Original call destination
    gchar *destination;
    //! Dialplan partition id
    gchar *partition;
    //! Agent Channel UniqueID
    gchar *agent_uniqueid;
    //! Remote Channel UniqueID
    gchar *remote_uniqueid;
    //! Agent Channel Name
    gchar *agent_channel;
    //! Remote Channel Name
    gchar *remote_channel;
    //** Display variables were introduced in isaac 2.x for asterisk 18+
    //** in order to support integrations that relay on UniqueID information we keep uniqueids to
    //** track calls, and uniqueids to display in CALLSTATUS commands
    //! Agent Channel Displayed UniqueID
    gchar *agent_display_uniqueid;
    //! Remote Channel Displayed UniqueID
    gchar *remote_display_uniqueid;
    //! Agent Channel Displayed Name
    gchar *agent_display_channel;
    //! Flag: This call is being Recorded
    gboolean recording;
    //! MixMonitor id being Recorded
    gchar *recording_id;
    //! Flag for printing uniqueid info
    gboolean print_uniqueid;
    //! Flag for broadcasting call info
    gboolean broadcast;

    //! Store recording vars
    gchar grabaciones_modulo[512];
    gchar grabaciones_tipo[1024];
    gchar grabaciones_plataforma[2048];
    gchar grabaciones_origen[2048];
    gchar grabaciones_destino[2048];
    gchar grabaciones_fecha_hora[2048];
    gchar grabaciones_ruta[4086];;
    gchar grabaciones_fichero[4086];
    gchar grabaciones_partition[4086];
    gchar grabaciones_idcola[4086];
} AppCallInfo;

/**
 * @brief Module configuration storage
 */
static AppCallConfig call_config;

/**
 * @brief Read module configure options
 *
 * This function will read CALLCONF file and fill app_call_conf
 * structure. Most of these values are using during call action process
 * @see call_exec
 *
 * @param cfile Full path to configuration file
 * @return TRUE in case of read success, FALSE otherwise
 */
static gboolean
read_call_config(const gchar *cfile)
{
    config_t cfg;
    const gchar *value;
    gint intvalue;

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
        call_config.incontext = g_strdup(value);
    }
    // Outgoing context for second call leg in Originate @see call_exec
    if (config_lookup_string(&cfg, "originate.outcontext", &value) == CONFIG_TRUE) {
        call_config.outcontext = g_strdup(value);
    }

    // Auto-answer variable (0,1) for incontext dialplan process
    if (config_lookup_int(&cfg, "originate.autoanswer", &intvalue) == CONFIG_TRUE) {
        call_config.autoanswer = intvalue;
    }

    // Filepath to store the recordings
    if (config_lookup_string(&cfg, "record.filepath", &value) == CONFIG_TRUE) {
        call_config.record_path = g_strdup(value);
    }

    // Dealloc libconfig structure
    config_destroy(&cfg);

    isaac_log(LOG_VERBOSE_3, "Read configuration from %s\n", cfile);
    return 0;
}

/**
 * @brief Get Call Info structure of a given id
 *
 * Loop through all session filters searching for a call info
 * structure with the given id.
 *
 * @param sess Session Structure
 * @param actionid ID supplied in CALL action
 * @return Call info structure
 */
static AppCallInfo *
get_call_info_from_id(Session *sess, const gchar *actionid)
{
    for (GSList *l = sess->filters; l; l = l->next) {
        Filter *filter = l->data;
        if (g_ascii_strcasecmp(filter->app->name, "CALL") == 0) {
            // We found the requested action!
            AppCallInfo *info = (AppCallInfo *) filter_get_userdata(l->data);
            if (info && g_ascii_strcasecmp(actionid, info->actionid) == 0) {
                return info;
            }
        }
    }
    return NULL;
}

static void
call_info_free(AppCallInfo *info)
{
    g_free(info->actionid);
    g_free(info->destination);
    g_free(info->partition);
    g_free(info->agent_uniqueid);
    g_free(info->remote_uniqueid);
    g_free(info->agent_channel);
    g_free(info->remote_channel);
    g_free(info->agent_display_uniqueid);
    g_free(info->remote_display_uniqueid);
    g_free(info->agent_display_channel);
    g_free(info->recording_id);
}

static void
call_status_inactivate_filters(Filter *filter, AppCallInfo *info)
{
    g_return_if_fail(filter != NULL);
    g_return_if_fail(info != NULL);

    if (filter_get_userdata(filter) == info) {
        filter_inactivate(filter);
    }
}

static void
call_status_send_response(Session *sess, AppCallInfo *info, gboolean agent_event, const gchar *state)
{
    g_autoptr(GString) response = g_string_new("CALLSTATUS");
    g_string_append_printf(response, " %s", info->actionid);

    // Add Display UniqueID if required
    if (info->print_uniqueid) {
        g_string_append_printf(
            response, " %s",
            (agent_event)
            ? info->agent_display_uniqueid
            : info->remote_display_uniqueid
        );
    }

    // Add the rest of the event data
    g_string_append_printf(response, " %s", (agent_event) ? "AGENT" : "REMOTE");
    g_string_append_printf(response, " %s", state);
    g_string_append(response, "\r\n");

    // Send this message to other clients if requested
    if (info->broadcast) {
        session_write_broadcast(sess, response->str);
    } else {
        session_write(sess, response->str);
    }
}

/**
 * @brief Writes to session CALLEVENT messages
 *
 * This function sends the CALLEVENT to a session when some filter
 * events triggers. It is used for Agent and Remote channel events.\n
 *
 * This function will be called when one of this happens:\n
 *  - A channel sets ACTIONID variable: This gave us leg1 channel\n
 *  - This channel begins a Dial Action: This gave us the second leg\n
 *  - Events on any of these two channels\n
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
static gint
call_state(Filter *filter, AmiMessage *msg)
{
    // Get Call information
    AppCallInfo *info = filter_get_userdata(filter);

    // Get message event
    const gchar *event = message_get_header(msg, "Event");

    // Determine if event is for AGENT or REMOTE channel
    gboolean agent_event = g_ascii_strcasecmp(
        message_get_header(msg, "UniqueID"),
        info->agent_uniqueid
    ) == 0;

    // Determine channel state
    gchar *state = NULL;

    // Send CallStatus message depending on received event
    if (g_ascii_strcasecmp(event, "Hangup") == 0) {
        // Print status message depending on Hangup Cause
        const gchar *cause = message_get_header(msg, "Cause");
        g_autoptr(GString) unknown_hangup = g_string_new(NULL);
        if (g_ascii_strcasecmp(cause, "0") == 0 || g_ascii_strcasecmp(cause, "21") == 0) {
            state = "ERROR";
        } else if (!strcasecmp(cause, "16")) {
            state = "HANGUP";
        } else if (!strcasecmp(cause, "17")) {
            state = "BUSY";
        } else if (!strcasecmp(cause, "19")) {
            state = "REJECTED";
        } else {
            g_string_append_printf(unknown_hangup, "UNKNOWNHANGUP %s", cause);
            state = unknown_hangup->str;
        }

        // Send current state to session
        call_status_send_response(filter->sess, info, agent_event, state);

        // Channel is down, remove this filter
        if (agent_event) {
            g_slist_foreach(filter->sess->filters, (GFunc) call_status_inactivate_filters, info);
        }

        return 0;
    } else if (g_ascii_strncasecmp(event, "MusicOnHold", 11) == 0) {
        if (g_ascii_strcasecmp(event, "MusicOnHoldStart") == 0
            || g_ascii_strcasecmp(message_get_header(msg, "State"), "Start") == 0) {
            state = "HOLD";
        } else {
            state = "UNHOLD";
        }

        // In this case, the channel that receives the Hold event is the
        // one that is being hold, not holding. So we should swap the
        // AGENT <-> REMOVE value
        call_status_send_response(filter->sess, info, !agent_event, state);
    } else if (g_ascii_strcasecmp(event, "Newstate") == 0) {
        // Print status message depending on Channel Status
        const gchar *channel_state = message_get_header(msg, "ChannelState");
        if (g_ascii_strcasecmp(channel_state, "5") == 0) {
            state = "RINGING";
        } else if (g_ascii_strcasecmp(channel_state, "6") == 0) {
            state = "ANSWERED";
        }

        // Send current state to session
        call_status_send_response(filter->sess, info, agent_event, state);
    } else if (g_ascii_strcasecmp(event, "Rename") == 0) {
        if (g_ascii_strcasecmp(message_get_header(msg, "UniqueID"), info->agent_uniqueid) == 0) {
            info->agent_channel = g_strdup(message_get_header(msg, "NewName"));
        }
    } else if (g_ascii_strcasecmp(event, "VarSet") == 0) {
        const gchar *var_name = message_get_header(msg, "Variable");
        const gchar *var_value = message_get_header(msg, "Value");

        // Progress event on cellphones
        if (g_ascii_strcasecmp(var_value, "SIP 183 Session Progress") == 0) {
            call_status_send_response(filter->sess, info, agent_event, "PROGRESS");
        }

        if (g_ascii_strcasecmp(var_name, "IDDIALPLANPARTITION") == 0) {
            info->partition = g_strdup(var_value);
        }

        // Update recording variables
        if (g_ascii_strncasecmp(var_name, "GRABACIONES_", 12) == 0) {
            char recordvar[256], recorduniqueid[80], grabaciones[80], recordtype[80];
            isaac_strcpy(recordvar, var_name);
            if (sscanf(recordvar, "%[^_]_%[^_]_%s", grabaciones, recorduniqueid, recordtype) == 3) {
                if (g_ascii_strcasecmp(recordtype, "MODULO") == 0)
                    sprintf(info->grabaciones_modulo, "%s;", var_value);
                if (g_ascii_strcasecmp(recordtype, "TIPO") == 0)
                    sprintf(info->grabaciones_tipo, "%s;", var_value);
                if (g_ascii_strcasecmp(recordtype, "PLATAFORMA") == 0)
                    sprintf(info->grabaciones_plataforma, "%s;", var_value);
                if (g_ascii_strcasecmp(recordtype, "ORIGEN") == 0)
                    sprintf(info->grabaciones_origen, "%s;", var_value);
                if (g_ascii_strcasecmp(recordtype, "DESTINO") == 0)
                    sprintf(info->grabaciones_destino, "%s;", var_value);
                if (g_ascii_strcasecmp(recordtype, "FECHA_HORA") == 0)
                    sprintf(info->grabaciones_fecha_hora, "%s;", var_value);
                if (g_ascii_strcasecmp(recordtype, "RUTA") == 0)
                    sprintf(info->grabaciones_ruta, "%s;", var_value);
                if (g_ascii_strcasecmp(recordtype, "FICHERO") == 0)
                    sprintf(info->grabaciones_fichero, "%s;", var_value);
                if (g_ascii_strcasecmp(recordtype, "IDDIALPLANPARTITION") == 0)
                    sprintf(info->grabaciones_partition, "%s;", var_value);
                if (g_ascii_strcasecmp(recordtype, "IDCOLA") == 0)
                    sprintf(info->grabaciones_idcola, "%s;", var_value);
            } else {
                isaac_log(LOG_WARNING, "Unhandled record variable %s\n", var_name);
            }
        }

        // A channel has set ACTIONID var, this is our leg1 channel. It will Dial soon!
        if (g_ascii_strcasecmp(var_name, "ACTIONID") == 0) {
            const gchar *uniqueid = message_get_header(msg, "Uniqueid");
            const gchar *linkedid = message_get_header(msg, "Linkedid");

            // If this is the first Local channel
            if (g_ascii_strcasecmp(uniqueid, linkedid) == 0) {
                // Store uniqueid for DialBegin event
                info->remote_display_uniqueid = g_strdup(uniqueid);
                info->agent_display_channel = g_strdup(message_get_header(msg, "Channel"));
            } else {
                // Store uniqueid for DialBegin event
                info->agent_display_uniqueid = g_strdup(uniqueid);

                // Create a new filter to find the final channel these Local channels will dial
                // These event now happen on a local channel, so try to find the final channel
                Filter *dial_filter = filter_create_async(
                    filter->sess, filter->app, "Get Channels info from DialBegin events", call_state
                );
                filter_new_condition(dial_filter, MATCH_REGEX, "Event", "DialBegin");
                filter_new_condition(
                    dial_filter,
                    MATCH_REGEX,
                    "Uniqueid",
                    "%s|%s",
                    info->remote_display_uniqueid,
                    info->agent_display_uniqueid
                );
                filter_set_userdata_full(dial_filter, (gpointer) info, (GDestroyNotify) call_info_free);
                filter_register(dial_filter);
            }
        }
    } else if (g_ascii_strcasecmp(event, "DialBegin") == 0) {
        if (g_ascii_strcasecmp(message_get_header(msg, "UniqueID"), info->agent_display_uniqueid) == 0) {
            // Get the UniqueId from the agent channel
            info->agent_uniqueid = g_strdup(message_get_header(msg, "DestUniqueid"));
            info->agent_channel = g_strdup(message_get_header(msg, "DestChannel"));

            // Register a Filter for the agent status
            Filter *agent_filter = filter_create_async(
                filter->sess, filter->app, "Agent real channel events", call_state
            );
            filter_new_condition(agent_filter, MATCH_REGEX, "Event", "Hangup|MusicOnHold|Newstate|Rename|Dial");
            filter_new_condition(agent_filter, MATCH_EXACT, "UniqueID", info->agent_uniqueid);
            filter_set_userdata_full(agent_filter, (gpointer) info, (GDestroyNotify) call_info_free);
            filter_register(agent_filter);

            Filter *agent_vars_filter = filter_create_async(
                filter->sess, filter->app, "Agent real channel Var Events", call_state
            );
            filter_new_condition(agent_vars_filter, MATCH_REGEX, "Event", "VarSet");
            filter_new_condition(agent_vars_filter, MATCH_EXACT, "UniqueID", info->agent_uniqueid);
            filter_new_condition(agent_vars_filter, MATCH_REGEX, "Variable", "IDDIALPLANPARTITION|GRABACIONES_");
            filter_set_userdata_full(agent_vars_filter, (gpointer) info, (GDestroyNotify) call_info_free);
            filter_register(agent_vars_filter);

            // Send current state to session
            call_status_send_response(filter->sess, info, TRUE, "STARTING");;
        }

        if (g_ascii_strcasecmp(message_get_header(msg, "UniqueID"), info->remote_display_uniqueid) == 0) {
            // Get the UniqueId from the remote channel
            info->remote_uniqueid = g_strdup(message_get_header(msg, "DestUniqueid"));
            info->remote_channel = g_strdup(message_get_header(msg, "DestChannel"));

            // Register a Filter for the agent status
            Filter *remote_filter = filter_create_async(
                filter->sess, filter->app, "Remote real channel events", call_state
            );
            filter_set_userdata_full(remote_filter, (gpointer) info, (GDestroyNotify) call_info_free);
            filter_new_condition(remote_filter, MATCH_REGEX, "Event", "Hangup|MusicOnHold|Newstate|Rename|Dial");
            filter_new_condition(remote_filter, MATCH_EXACT, "UniqueID", info->remote_uniqueid);
            filter_register(remote_filter);

            Filter *remote_vars_filter = filter_create_async(
                filter->sess, filter->app, "Remote real channel Var Events", call_state
            );
            filter_new_condition(remote_vars_filter, MATCH_REGEX, "Event", "VarSet");
            filter_new_condition(remote_vars_filter, MATCH_EXACT, "UniqueID", info->remote_uniqueid);
            filter_new_condition(remote_vars_filter, MATCH_REGEX, "Variable", "IDDIALPLANPARTITION|GRABACIONES_");
            filter_set_userdata_full(remote_vars_filter, (gpointer) info, (GDestroyNotify) call_info_free);
            filter_register(remote_vars_filter);

            // Send current state to session
            call_status_send_response(filter->sess, info, FALSE, "STARTING");

            // All data retrieved
            filter_inactivate(filter);
        }
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
 * @param app The application structure
 * @param argstr Call action argstr "ActionID DestNum"
 * @return 0 in call cases
 */
int
call_exec(Session *sess, Application *app, const char *argstr)
{
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Check if uniqueid info is requested
    GSList *args = application_parse_args(argstr);
    if (g_slist_length(args) < 2) {
        application_free_args(args);
        return INVALID_ARGUMENTS;
    }

    // First argument is the ID of the call
    const gchar *actionid = application_get_nth_arg(args, 0);
    // Second argument is the number to be dialed
    const gchar *exten = application_get_nth_arg(args, 1);

    // Initialize application info
    AppCallInfo *info = g_rc_box_new0(AppCallInfo);
    g_return_val_if_fail(info != NULL, APP_RET_ERROR);
    info->actionid = g_strdup(actionid);
    info->destination = g_strdup(exten);

    if (application_arg_exists(args, "WUID")) {
        info->print_uniqueid = 1;
    }

    if (application_arg_exists(args, "BRD")) {
        info->broadcast = 1;
    }

    // Register a Filter to get Generated Channel
    Filter *local_chans_filter = filter_create_async(sess, app, "Originated call status", call_state);
    filter_new_condition(local_chans_filter, MATCH_EXACT, "Event", "VarSet");
    filter_new_condition(local_chans_filter, MATCH_EXACT, "Variable", "ACTIONID");
    filter_new_condition(local_chans_filter, MATCH_EXACT, "Value", actionid);
    filter_set_userdata_full(local_chans_filter, (gpointer) info, (GDestroyNotify) call_info_free);
    filter_register(local_chans_filter);

    // Get the logged agent
    const gchar *agent = session_get_variable(sess, "AGENT");
    const gchar *rol = session_get_variable(sess, "ROL");

    // Construct a Request message
    AmiMessage msg;
    memset(&msg, 0, sizeof(AmiMessage));
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
    const gchar *value = NULL;
    if ((value = application_get_arg(args, "CLID")) != NULL) {
        message_add_header(&msg, "Variable: ISAAC_FORCED_CLID=%s", value);
    }

    // Forced SRC CLID from application arguments
    if ((value = application_get_arg(args, "SRC_CLID")) != NULL) {
        message_add_header(&msg, "Variable: ISAAC_SRC_FORCED_CLID=%s", value);
    }

    // Forced Timeout from application arguments
    if ((value = application_get_arg(args, "TIMEOUT")) != NULL) {
        message_add_header(&msg, "Variable: ISAAC_CALL_TIMEOUT=%s", value);
    }

    // Originate absolute TIMEOUT (default 30s)
    if ((value = application_get_arg(args, "ABSOLUTE_TIMEOUT")) != NULL) {
        message_add_header(&msg, "Timeout: %s", value);
    }

    // Remove initial info reference
    g_rc_box_release(info);

    // Send this message to ami
    manager_write_message(manager, &msg);

    // Free args app arguments
    application_free_args(args);

    return APP_RET_SUCCESS;
}

/**
 * @brief DTMF action entry point
 *
 * DTMF action will send a DTMF code to a second channel generated using
 * CALL action using the custom manager application PlayDTMF.
 *
 * @param sess Session rnuning this application
 * @param app The application structure
 * @param args Dtmf action args "ActionID DTMFDigit"
 * @return 0 if the call is found, -1 otherwise
 */
int
dtmf_exec(Session *sess, Application *app, const char *args)
{
    AppCallInfo *info;
    char actionid[ACTIONID_LEN];
    char digit[20];

    // This can only be done after authentication
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Get Hangup parameters
    if (sscanf(args, "%s %s", actionid, digit) != 2) {
        return INVALID_ARGUMENTS;
    }

    // Try to find the action info of the given actionid
    if ((info = get_call_info_from_id(sess, actionid)) && !isaac_strlen_zero(info->remote_channel)) {
        // Send the digit to remote channel using PlayDTMF manager action
        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: PlayDTMF");
        message_add_header(&msg, "Channel: %s", info->remote_channel);
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
hangup_exec(Session *sess, Application *app, const char *args)
{
    AppCallInfo *info;
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
        if (!isaac_strlen_zero(info->agent_channel)) {
            AmiMessage msg;
            memset(&msg, 0, sizeof(AmiMessage));
            message_add_header(&msg, "Action: Hangup");
            message_add_header(&msg, "Channel: %s", info->agent_channel);
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
hold_unhold_exec(Session *sess, Application *app, const char *args)
{
    AppCallInfo *info;
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
    for (i = 0; action[i]; i++) {
        action[i] = (char) toupper(action[i]);
    }

    // Try to find the action info of the given actionid
    if ((info = get_call_info_from_id(sess, actionid)) && !isaac_strlen_zero(info->agent_channel)) {
        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: SIPNotifyChan");
        message_add_header(&msg, "Channel: %s", info->agent_channel);
        message_add_header(&msg, "Event: %s", ((!strcasecmp(app->name, "Hold")) ? "hold" : "talk"));
        manager_write_message(manager, &msg);
        session_write(sess, "%sOK\r\n", action);
    } else {
        session_write(sess, "%sFAILED ID NOT FOUND\r\n", action);
        return -1;
    }
    return 0;
}

int
record_state(Filter *filter, AmiMessage *msg)
{
    // Get Call information
    AppCallInfo *info = (AppCallInfo *) filter_get_userdata(filter);

    // Get message data
    const char *response = message_get_header(msg, "Response");

    if (response == NULL) {
        session_write(filter->sess, "RECORDFAILED %s\r\n", response);
        return -1;
    }

    if (strncasecmp(response, "Success", 7) == 0) {
        const char *mixmonitor_id = message_get_header(msg, "MixmonitorID");
        if (mixmonitor_id != NULL) {
            info->recording_id = g_strdup(mixmonitor_id);
        }
    }

    // Flag this call as being recorded
    info->recording = true;

    // Notify recording worked
    session_write(filter->sess, "RECORDOK\r\n");
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
record_exec(Session *sess, Application *app, const char *args)
{
    AppCallInfo *info;
    char actionid[ACTIONID_LEN];
    char filename[128];
    time_t timer;
    char timestr[25];
    struct tm *tm_info;

    // This can only be done after authentication
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Get Hangup parameters
    if (sscanf(args, "%s %s", actionid, filename) != 2) {
        return INVALID_ARGUMENTS;
    }

    // Try to find the action info of the given actionid
    if ((info = get_call_info_from_id(sess, actionid)) && !isaac_strlen_zero(info->agent_channel)) {

        // Check if this call is already being recorded
        if (info->recording) {
            session_write(sess, "RECORDFAILED CALL IS ALREADY BEING RECORDED\r\n");
            return -1;
        }

        Filter *record_status = filter_create_async(sess, app, "Recording status", record_state);
        filter_new_condition(record_status, MATCH_EXACT, "ActionID", "RECORD_%s", actionid);
        filter_set_userdata_full(record_status, (gpointer) info, (GDestroyNotify) call_info_free);
        filter_register_oneshot(record_status);

        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: MixMonitor");
        message_add_header(&msg, "Channel: %s", info->agent_channel);
        message_add_header(&msg, "File: %s/%s.wav", call_config.record_path, filename);
        message_add_header(&msg, "ActionID: RECORD_%s", actionid);
        message_add_header(&msg, "Options: i(ISAAC_RECORDING)");
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->agent_display_channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_MODULO", info->agent_display_uniqueid);
        message_add_header(&msg, "Value: %sCC", info->grabaciones_modulo);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->agent_display_channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_PLATAFORMA", info->agent_display_uniqueid);
        message_add_header(&msg, "Value: %s", info->grabaciones_plataforma);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->agent_display_channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_TIPO", info->agent_display_uniqueid);
        message_add_header(&msg, "Value: %son-demand_ISAAC", info->grabaciones_tipo);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->agent_display_channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_ORIGEN", info->agent_display_uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_origen, session_get_variable(sess, "AGENT"));
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->agent_display_channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_DESTINO", info->agent_display_uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_destino, info->destination);
        manager_write_message(manager, &msg);

        time(&timer);
        tm_info = localtime(&timer);
        strftime(timestr, 25, "%Y:%m:%d_%H:%M:%S", tm_info);
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->agent_display_channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_FECHA_HORA", info->agent_display_uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_fecha_hora, timestr);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->agent_display_channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_RUTA", info->agent_display_uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_ruta, call_config.record_path);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->agent_display_channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_FICHERO", info->agent_display_uniqueid);
        message_add_header(&msg, "Value: %s%s.wav", info->grabaciones_fichero, filename);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->agent_display_channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_IDDIALPLANPARTITION", info->agent_display_uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_partition, info->partition);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->agent_display_channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_IDCOLA", info->agent_display_uniqueid);
        message_add_header(&msg, "Value: %s", info->grabaciones_idcola);
        manager_write_message(manager, &msg);

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
recordstop_exec(Session *sess, Application *app, const char *args)
{
    AppCallInfo *info;
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
    if ((info = get_call_info_from_id(sess, actionid)) && !isaac_strlen_zero(info->agent_channel)) {

        // Check if this call is not being recorded
        if (!info->recording) {
            session_write(sess, "RECORDSTOPFAILED CALL NOT BEING RECORDED\r\n");
            return -1;
        }

        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: StopMixMonitor");
        message_add_header(&msg, "Channel: %s", info->agent_channel);
        if (strlen(info->recording_id) != 0) {
            message_add_header(&msg, "MixMonitorID: %s", info->recording_id);
        }
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
    res |= application_register("CALL", call_exec);
    res |= application_register("HANGUP", hangup_exec);
    res |= application_register("DTMF", dtmf_exec);
    res |= application_register("HOLD", hold_unhold_exec);
    res |= application_register("UNHOLD", hold_unhold_exec);
    res |= application_register("RECORD", record_exec);
    res |= application_register("RECORDSTOP", recordstop_exec);
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
    res |= application_unregister("CALL");
    res |= application_unregister("HANGUP");
    res |= application_unregister("DTMF");
    res |= application_unregister("HOLD");
    res |= application_unregister("UNHOLD");
    res |= application_unregister("RECORD");
    res |= application_unregister("RECORDSTOP");

    // Free module configuration data
    g_free(call_config.incontext);
    g_free(call_config.outcontext);
    g_free(call_config.record_path);

    return res;
}
