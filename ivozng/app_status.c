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
 * @file app_status.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Check incoming calls from Queues to Agents
 *
 * @warning This module is customized for Ivoz-NG. If won't work without the
 *  required contexts configured in asterisk.
 *
 * Check for incoming calls to agents and print status events. This module will
 * also check if the call is being called to another agent.
 *
 */

#include "config.h"
#include <glib.h>
#include <libconfig.h>
#include "app.h"
#include "session.h"
#include "manager.h"
#include "filter.h"
#include "log.h"

#define STATUSCONF CONFDIR "/status.conf"


/**
 * @brief Module configuration read from STATUSCONF file
 *
 * @see read_call_config
 */
typedef struct
{
    //! Recordings path
    gchar *record_path;
} AppStatusConfig;

/**
 * @brief Status application custom structure
 *
 * This structure contains the information of a Queue incoming call
 * to print EXTERNALCALLSTATUS messages
 */
typedef struct
{
    //! Platform of the Queue receiving the call
    char plat[120];
    //! Queue receiving the call
    char queue[150];
    //! CallerID num of the incoming call
    char clidnum[20];
    //! UniqueID from incoming call
    char uniqueid[20];
    //! Incoming Channel name
    char channel[80];
    //! Agent channel
    char agent_channel[80];
    //! Attended transfer State (See Asterisk Call states)
    int xfer_state;
    //! Agent to which this call is being transferred
    char xfer_agent[20];
    //! Agent channel in case of attended transfer
    char xfer_channel[80];
    //! Answered flag
    gboolean answered;
    //! Held flag
    gboolean hold;
    //! Direct agent
    gboolean agent;
    //! Mark the call as being recorded
    gboolean recording;
    //! Mixmonitor id being Recorded
    char recording_id[256];
    //! Store recording vars
    char grabaciones_modulo[512];
    char grabaciones_tipo[1024];
    char grabaciones_plataforma[2048];
    char grabaciones_origen[2048];
    char grabaciones_destino[2048];
    char grabaciones_fecha_hora[2048];
    char grabaciones_ruta[4086];;
    char grabaciones_fichero[4086];
} AppStatusInfo;

// Module configuration storage
static AppStatusConfig status_config;

gchar *recordvars[] =
    {
        "MODULO",
        "PLATAFORMA",
        "TIPO",
        "ORIGEN",
        "DESTINO",
        "FECHA_HORA",
        "RUTA",
        "FICHERO",
        NULL
    };

/**
 * @brief Read module configure options
 *
 * This function will read STATUSCONF file and fill app_call_conf
 * structure. Most of these values are using during call action process
 *
 * @param cfile Full path to configuration file
 * @return TRUE in case of read success, FALSE otherwise
 */
static gboolean
read_status_config(const gchar *cfile)
{
    config_t cfg;
    const gchar *value;

    // Initialize configuration
    config_init(&cfg);

    // Read configuration file
    if (config_read_file(&cfg, cfile) == CONFIG_FALSE) {
        isaac_log(LOG_ERROR, "Error parsing configuration file %s on line %d: %s\n", cfile,
                  config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return FALSE;
    }

    // File path to store the recordings
    if (config_lookup_string(&cfg, "record.filepath", &value) == CONFIG_TRUE) {
        status_config.record_path = g_strdup(value);
    }

    // Dealloc libconfig structure
    config_destroy(&cfg);

    isaac_log(LOG_VERBOSE_3, "Read configuration from %s\n", cfile);
    return TRUE;
}

/**
 * @brief Returns channel name for a given UniqueID
 *
 * @param uniqueid Channel UniqueID
 * @returns status structure pointer or NULL if not found
 */
static AppStatusInfo *
find_channel_info_by_uniqueid(Session *sess, const char *uniqueid)
{
    // Find the call with that uniqueid
    for (GSList *l = sess->filters; l; l = l->next) {
        Filter *filter = l->data;
        if (g_ascii_strcasecmp(filter->app->name, "STATUS") == 0) {
            AppStatusInfo *info = filter_get_userdata(filter);
            if (info != NULL && g_ascii_strcasecmp(info->uniqueid, uniqueid) == 0) {
                return info;
            }
        }
    }

    // No channel found with that uniqueid
    return NULL;
}

/**
 * @brief Returns agent channel name for a given UniqueID
 *
 * @param uniqueid Channel UniqueID
 * @returns agent channel name or NULL if not found
 */
static gchar *
find_agent_channel_by_uniqueid(Session *sess, const gchar *uniqueid)
{
    AppStatusInfo *info = find_channel_info_by_uniqueid(sess, uniqueid);
    return (info != NULL) ? info->agent_channel : NULL;
}

/**
 * @brief Returns channel name for a given UniqueID
 *
 * @param uniqueid Channel UniqueID
 * @returns channel name or NULL if not found
 */
static gchar *
find_channel_by_uniqueid(Session *sess, const gchar *uniqueid)
{
    AppStatusInfo *info = find_channel_info_by_uniqueid(sess, uniqueid);
    return (info != NULL) ? info->channel : NULL;
}

/**
 * @brief Injects messages to AMI to simulate an incoming call
 *
 * When a transfer occurs, some clients want to receive status
 * messages in the transfer receiver bus.
 *
 * This is not naturally possible so, if we want to trigger
 * status filters, we must inject those messages.
 *
 * For a status callback trigger, we need
 * a) Transfer receiver Agent
 * b) Transfer receiver Channel
 * c) Transfer receiver Channel status (Answered, Ringing..)
 *
 * The rest of the information (such as platform, uniqueid, ...)
 * will be the same that the original one (stored in the filter
 * userdata pointer)
 */
static gint
status_inject_queue_call(Filter *filter)
{
    AppStatusInfo *info = filter_get_userdata(filter);
    g_return_val_if_fail(info != NULL, 1);

    /**
     * For EXTERNALCALLAGENT events we don't require to inject events in AMI
     * Dialplan will trigger the ISAAC_AGENT_MONITOR variable logic
     */
    if (info->agent) return 1;

    /* Construct a Request message (fake VarSet).
     * This will trigger the initial Status callback and will try to search a
     * Event: Dial message to obtain the real SIP/ channel name (not the Local/ one)
     */
    AmiMessage user_msg;
    memset(&user_msg, 0, sizeof(AmiMessage));
    message_add_header(&user_msg, "Event: VarSet");
    message_add_header(&user_msg, "Variable: __ISAAC_MONITOR");
    message_add_header(&user_msg, "Value: %s!%s!%s!%s!%s", info->plat, info->clidnum, info->channel, info->uniqueid,
                       info->queue);
    message_add_header(&user_msg, "Channel: Local/%s@agentes", info->xfer_agent);
    filter_inject_message(filter, &user_msg);

    /* Construct a Request message (fake Dial).
     * We trigger the second callback of Status, now providing the SIP/ channel name
     * so the logic can detect when this channel status changes
     */
    memset(&user_msg, 0, sizeof(AmiMessage));
    message_add_header(&user_msg, "Event: Dial");
    message_add_header(&user_msg, "SubEvent: Begin");
    message_add_header(&user_msg, "Channel: Local/%s@agentes", info->xfer_agent);
    message_add_header(&user_msg, "Destination: %s", info->xfer_channel);
    message_add_header(&user_msg, "CallerIDName: %s", info->plat);
    message_add_header(&user_msg, "CallerIDNum: %s", info->clidnum);
    filter_inject_message(filter, &user_msg);

    /* Construct NewState fake status messages
     * We generate Newstate messages to update the channel status to match the
     * real status.
     */
    if (info->xfer_state >= 5) {
        memset(&user_msg, 0, sizeof(AmiMessage));
        message_add_header(&user_msg, "Event: Newstate");
        message_add_header(&user_msg, "Channel: %s", info->xfer_channel);
        message_add_header(&user_msg, "ChannelState: 5");
        filter_inject_message(filter, &user_msg);
    }

    if (info->xfer_state >= 6) {
        memset(&user_msg, 0, sizeof(AmiMessage));
        message_add_header(&user_msg, "Event: Newstate");
        message_add_header(&user_msg, "Channel: %s", info->xfer_channel);
        message_add_header(&user_msg, "ChannelState: 6");
        filter_inject_message(filter, &user_msg);
    }

    return 1;
}

/**
 * @brief Callback for blind transfer
 *
 * When the agents transfer its call using an blind transfer, this callback
 * will be executed. This function will create a FAKE AMI message for the agent
 * that is receiving the transferred call.
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
static gint
status_blindxfer(Filter *filter, AmiMessage *msg)
{
    AppStatusInfo *info = filter_get_userdata(filter);

    // Not previous status known on blind transfer
    info->xfer_state = 0;
    // Destiny transfer channel name
    strcpy(info->xfer_channel, message_get_header(msg, "Destination"));

    // We have enough information to inject messages in receiver bus
    status_inject_queue_call(filter);

    return 0;
}

/**
 * @brief Callback for attended transfer using features
 *
 * When agents transfer using builtin, a new local channel is spawned that call the
 * final agent.
 * We try to find the dial that calls to the final agent to fill our xfer structures
 *
 */
static gint
status_builtin_xfer(Filter *filter, AmiMessage *msg)
{
    AppStatusInfo *info = filter_get_userdata(filter);

    if (!strcasecmp(message_get_header(msg, "Variable"), "TRANSFERERNAME")) {
        g_autofree gchar *local_channel = g_strdup(message_get_header(msg, "Channel"));
        local_channel[strlen(local_channel) - 1] = '2';

        // Try to find the final xfer channel
        Filter *builtin_xfer_filter = filter_create_async(
            filter->sess,
            filter->app,
            "Find final xfer channel",
            status_builtin_xfer
        );
        filter_new_condition(builtin_xfer_filter, MATCH_EXACT, "Event", "VarSet");
        filter_new_condition(builtin_xfer_filter, MATCH_EXACT, "Channel", local_channel);
        filter_new_condition(builtin_xfer_filter, MATCH_EXACT, "Variable", "BRIDGEPEER");
        filter_new_condition(builtin_xfer_filter, MATCH_START_WITH, "Value", "SIP/");
        filter_set_userdata(builtin_xfer_filter, (void *) info);
        filter_register_oneshot(builtin_xfer_filter);

    } else if (!strcasecmp(message_get_header(msg, "Variable"), "BRIDGEPEER")) {
        // Final Xfer channel found!
        strcpy(info->xfer_channel, message_get_header(msg, "Value"));
    }

    return 0;
}

/**
 * @brief Agent's Call state changes filter callback.
 *
 * When the agents's call leg status changes, this callback will be triggered.
 * It will also check if the remote call is being transferred to another agent
 * creating filters to get all required messages.
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
static gint
status_print(Filter *filter, AmiMessage *msg)
{
    AppStatusInfo *info = (AppStatusInfo *) filter_get_userdata(filter);
    Session *sess = filter->sess;
    const char *event = message_get_header(msg, "Event");
    g_autoptr(GString) response = g_string_new(NULL);

    // CallStatus response
    if (g_ascii_strcasecmp(event, "Newstate") == 0
        || g_ascii_strcasecmp(event, "Hangup") == 0
        || g_ascii_strcasecmp(event, "IsaacTransfer") == 0
        || g_ascii_strncasecmp(event, "MusicOnHold", 11) == 0) {
        if (info->agent) {
            g_string_append(response, "EXTERNALCALLAGENTSTATUS ");
        } else {
            g_string_append(response, "EXTERNALCALLSTATUS ");
        }
        if (session_get_variable(sess, "STATUSWUID")) {
            g_string_append_printf(response, "%s ", info->uniqueid);
        }
        if (session_get_variable(sess, "STATUSDEBUG")) {
            g_string_append_printf(response, "%s %s ", info->agent_channel, info->channel);
        }
        g_string_append_printf(response, "%s ", info->plat);
        if (session_get_variable(sess, "STATUSWQUEUE")) {
            g_string_append_printf(response, "%s ", info->queue);
        }
        g_string_append_printf(response, "%s ", info->clidnum);
    }

    // Send ExternalCallStatus message depending on received event
    if (g_ascii_strcasecmp(event, "Newstate") == 0) {

        // Print status message depending on Channel Status
        if (g_ascii_strcasecmp(message_get_header(msg, "ChannelState"), "5") == 0) {
            g_string_append_printf(response, "RINGING\r\n");
        } else if (g_ascii_strcasecmp(message_get_header(msg, "ChannelState"), "6") == 0) {
            g_string_append_printf(response, "ANSWERED\r\n");
            info->answered = TRUE;

            Filter
                *call_filter = filter_create_async(filter->sess, filter->app, "MoH changes on channel", status_print);
            filter_new_condition(call_filter, MATCH_REGEX, "Event", "MusicOnHold|MusicOnHoldStart|MusicOnHoldStop");
            filter_new_condition(call_filter, MATCH_EXACT, "Channel", info->channel);
            filter_set_userdata(call_filter, (void *) info);
            filter_register(call_filter);
        }
    } else if (!strncasecmp(event, "MusicOnHold", 11)) {
        // This filter lives only during answered calls
        if (info->answered) {
            // Avoid sending multiple times the same status
            if (!info->hold
                &&
                    (g_ascii_strcasecmp(event, "MusicOnHoldStart") == 0
                        || g_ascii_strcasecmp(message_get_header(msg, "State"), "Start") == 0)
                ) {
                g_string_append_printf(response, "HOLD\r\n");
                info->hold = TRUE;
            } else if (info->hold
                &&
                    (g_ascii_strcasecmp(event, "MusicOnHoldStop") == 0
                        || g_ascii_strcasecmp(message_get_header(msg, "State"), "Stop") == 0)
                ) {
                g_string_append_printf(response, "UNHOLD\r\n");
                info->hold = FALSE;
            } else {
                // Clear this event
                g_string_truncate(response, 0);
            }
        } else {
            // Hold filter is no longer needed
            filter_destroy(filter);
            // Clear this event
            g_string_truncate(response, 0);
        }

    } else if (g_ascii_strcasecmp(event, "Hangup") == 0) {

        // #0042649 Regression. Noanswer status is not valid sometimes.
        //const char *cause = message_get_header(msg, "Cause");
        //if (!isaac_strcmp(cause, "17")) {
        //    // Queue call rejected by agent
        //    sprintf(statusevent + strlen(statusevent), "BUSY\r\n");
        //} else if (!info->answered) {
        //    // Queue call timeout
        //    sprintf(statusevent + strlen(statusevent), "NOANSWER\r\n");
        //} else {
        //    // Queue call has finished for this agent
        //    sprintf(statusevent + strlen(statusevent), "HANGUP\r\n");
        //}

        // Queue call has finished for this agent
        g_string_append_printf(response, "HANGUP\r\n");
        info->answered = FALSE;

        // Unregister all filters of current channel
        filter = NULL;
        while ((filter = filter_from_userdata(sess, info))) {
            filter_destroy(filter);
        }
    } else if (g_ascii_strcasecmp(event, "IsaacTransfer") == 0) {
        // Queue call has been transferred
        g_string_append_printf(response, "TRANSFERRED\r\n");

        if (g_ascii_strcasecmp(message_get_header(msg, "TransferType"), "Attended") == 0) {
            // We have the destination information
            strcpy(info->xfer_channel, message_get_header(msg, "TargetChannel"));
            strcpy(info->xfer_agent, message_get_header(msg, "TransferExten"));
            // Blonde transfer, destiny was ringing
            info->xfer_state = 6;
            // We have enough information to inject messages in receiver bus
            isaac_log(LOG_NOTICE, "[Session#%s] Detected Attended Transfer to %s\n", filter->sess->id,
                      info->xfer_agent);
            status_inject_queue_call(filter);
        }

        if (g_ascii_strcasecmp(message_get_header(msg, "TransferType"), "Blonde") == 0) {
            // We have the destination information
            strcpy(info->xfer_channel, message_get_header(msg, "TargetChannel"));
            strcpy(info->xfer_agent, message_get_header(msg, "TransferExten"));
            // Blonde transfer, destiny was ringing
            info->xfer_state = 5;
            // We have enough information to inject messages in receiver bus
            isaac_log(LOG_NOTICE, "[Session#%s] Detected Blonde Transfer to %s\n", filter->sess->id, info->xfer_agent);
            status_inject_queue_call(filter);
        }

        if (g_ascii_strcasecmp(message_get_header(msg, "TransferType"), "Blind") == 0) {
            // Copy the destiny agent
            strcpy(info->xfer_agent, message_get_header(msg, "TransferExten"));
            isaac_log(LOG_NOTICE, "[Session#%s] Detected Blind Transfer to %s\n", filter->sess->id, info->xfer_agent);

            // Find the session for the given interface
            Session *xfer_sess = session_by_variable("AGENT", info->xfer_agent);

            if (xfer_sess) {
                // We get the Attender transfer type from masquerade Event
                Filter *blind_xfer_filter = filter_create_async(
                    sess,
                    filter->app,
                    "Get Xfer destination",
                    status_blindxfer);
                filter_new_condition(blind_xfer_filter, MATCH_EXACT, "Event", "Dial");
                filter_new_condition(blind_xfer_filter, MATCH_EXACT, "SubEvent", "Begin");
                filter_new_condition(blind_xfer_filter, MATCH_EXACT, "Channel", info->channel);
                filter_set_userdata(blind_xfer_filter, (void *) info);
                filter_register_oneshot(blind_xfer_filter);
            }
        }

        if (g_ascii_strcasecmp(message_get_header(msg, "TransferType"), "Builtin") == 0) {
            if (g_ascii_strcasecmp(message_get_header(msg, "SubEvent"), "Begin") == 0) {
                strcpy(info->xfer_agent, message_get_header(msg, "TransferExten"));
                info->xfer_state = 6;

                // We get the Attender transfer type from masquearde Event
                Filter *builtin_xfer_filter = filter_create_async(
                    sess,
                    filter->app,
                    "Get Xfer destination",
                    status_builtin_xfer);
                filter_new_condition(builtin_xfer_filter, MATCH_EXACT, "Event", "VarSet");
                filter_new_condition(builtin_xfer_filter, MATCH_EXACT, "Variable", "TRANSFERERNAME");
                filter_new_condition(builtin_xfer_filter, MATCH_EXACT, "Value", info->agent_channel);
                filter_set_userdata(builtin_xfer_filter, (void *) info);
                filter_register_oneshot(builtin_xfer_filter);

                // Not yet ready to consider this a transfer
                g_string_truncate(response, 0);
            } else {
                char xferchan[80];
                strcpy(xferchan, info->xfer_channel);
                char *interface = strtok(xferchan, "-");

                // Find the session for the given interface
                Session *xfer_sess = session_by_variable("INTERFACE", interface);

                if (xfer_sess) {
                    // We have enough information to inject messages in receiver bus
                    strcpy(info->xfer_agent, session_get_variable(xfer_sess, "AGENT"));
                    isaac_log(LOG_NOTICE, "[Session#%s] Detected Builtin Transfer to %s\n", filter->sess->id,
                              info->xfer_agent);
                    status_inject_queue_call(filter);
                } else {
                    // Oh, transferring to someone not logged in
                    isaac_log(LOG_WARNING,
                              "[Session#%s] Ignoring transfer injection to %s. It does not have any Isaac sessions Up.\n",
                              filter->sess->id,
                              interface);
                }
            }
        }
    }

    // Check if there's something to write to client
    if (response->len) {
        session_write(sess, response->str);
    }

    return 0;
}

/**
 * @brief Status filter callback.
 *
 * When a call is being placed to the logged agent, Isaac F&C logic will callback here.
 * This function will store in filter's info the Dial information for future CALLEVENT
 * messages and register a new filter to monitoring agent's leg status
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
gint
status_call(Filter *filter, AmiMessage *msg)
{
    AppStatusInfo *info = (AppStatusInfo *) filter_get_userdata(filter);

    // Get the interesting channel name, we will fetch the rest of the messages
    // that match that ID
    strcpy(info->agent_channel, message_get_header(msg, "Destination"));
    // Fallback for DialBegin Asterisk 18+ event
    if (strlen(info->agent_channel) == 0) {
        strcpy(info->agent_channel, message_get_header(msg, "DestChannel"));
    }

    // Register a Filter for notifying this call
    Filter *callfilter = filter_create_async(
        filter->sess,
        filter->app,
        "Initial events from Agent channel",
        status_print
    );
    filter_new_condition(callfilter, MATCH_REGEX, "Event", "Newstate|Hangup|IsaacTransfer");
    filter_new_condition(callfilter, MATCH_EXACT, "Channel", info->agent_channel);
    filter_set_userdata(callfilter, (void *) info);
    filter_register(callfilter);

    return 0;
}

int
record_variables(Filter *filter, AmiMessage *msg)
{
    const char *varvalue = message_get_header(msg, "Value");
    const char *varname = message_get_header(msg, "Variable");

    if (!strncasecmp(varname, "GRABACIONES_", 12)) {
        char recordvar[256], recorduniqueid[80], grabaciones[80], recordtype[80];
        strcpy(recordvar, varname);
        if (sscanf(recordvar, "%[^_]_%[^_]_%s", grabaciones, recorduniqueid, recordtype) == 3) {
            AppStatusInfo *info;
            if ((info = find_channel_info_by_uniqueid(filter->sess, recorduniqueid))) {
                if (!strcasecmp(recordtype, "MODULO")) sprintf(info->grabaciones_modulo, "%s;", varvalue);
                if (!strcasecmp(recordtype, "TIPO")) sprintf(info->grabaciones_tipo, "%s;", varvalue);
                if (!strcasecmp(recordtype, "PLATAFORMA")) sprintf(info->grabaciones_plataforma, "%s;", varvalue);
                if (!strcasecmp(recordtype, "ORIGEN")) sprintf(info->grabaciones_origen, "%s;", varvalue);
                if (!strcasecmp(recordtype, "DESTINO")) sprintf(info->grabaciones_destino, "%s;", varvalue);
                if (!strcasecmp(recordtype, "FECHA_HORA")) sprintf(info->grabaciones_fecha_hora, "%s;", varvalue);
                if (!strcasecmp(recordtype, "RUTA")) sprintf(info->grabaciones_ruta, "%s;", varvalue);
                if (!strcasecmp(recordtype, "FICHERO")) sprintf(info->grabaciones_fichero, "%s;", varvalue);
            } else {
                isaac_log(LOG_WARNING, "Unhandled record variable %s for uniqueid %s\n", varname, recorduniqueid);
            }
        } else {
            isaac_log(LOG_WARNING, "Unhandled record variable %s\n", varname);
        }
    }

    return 0;
}

/**
 * @brief Get Incoming call UniqueID from __ISAAC_MONITOR variable
 *
 */
int
status_incoming_uniqueid(Filter *filter, AmiMessage *msg)
{
    char value[512];
    char plat[120], clidnum[20], uniqueid[20], channel[80], queue[150];
    int i;

    // Copy __ISAAC_MONITOR value
    strcpy(value, message_get_header(msg, "Value"));

    // Initialize al variables
    memset(plat, 0, sizeof(plat));
    memset(clidnum, 0, sizeof(clidnum));
    memset(uniqueid, 0, sizeof(uniqueid));
    memset(channel, 0, sizeof(channel));
    memset(queue, 0, sizeof(queue));

    if (sscanf(value, "%[^!]!%[^!]!%[^!]!%[^!]!%s", plat, clidnum, channel, uniqueid, queue)) {
        isaac_log(LOG_DEBUG, "[Session#%s] Detected %s on channel %s: %s\n",
                  filter->sess->id,
                  message_get_header(msg, "Variable"),
                  message_get_header(msg, "Channel"),
                  message_get_header(msg, "Value"));

        // Initialize application info
        AppStatusInfo *info = malloc(sizeof(AppStatusInfo));
        memset(info, 0, sizeof(AppStatusInfo));
        strcpy(info->plat, plat);
        strcpy(info->clidnum, clidnum);
        strcpy(info->channel, channel);
        strcpy(info->uniqueid, uniqueid);
        strcpy(info->queue, queue);
        info->answered = FALSE;
        info->hold = FALSE;
        info->agent = FALSE;
        info->recording = FALSE;

        // If variable matches agent format
        if (!strcmp(message_get_header(msg, "Variable"), "ISAAC_AGENT_MONITOR")) {
            // Mark this as direct to agent
            info->agent = TRUE;
            // Store agent channel name
            strcpy(info->agent_channel, message_get_header(msg, "Channel"));

            // Register a Filter for notifying this call
            Filter *callfilter =
                filter_create_async(filter->sess, filter->app, "Agent channel status changes", status_print);
            filter_new_condition(callfilter, MATCH_REGEX, "Event", "Newstate|Hangup|IsaacTransfer|VarSet");
            filter_new_condition(callfilter, MATCH_EXACT, "Channel", info->agent_channel);
            filter_set_userdata(callfilter, (void *) info);
            filter_register(callfilter);

        } else {
            Filter *channelfilter =
                filter_create_async(filter->sess, filter->app, "Agent channel name fetch", status_call);
            filter_new_condition(channelfilter, MATCH_REGEX, "Event", "Dial|DialBegin");
            filter_new_condition(channelfilter, MATCH_REGEX, "SubEvent", "Begin|");
            filter_new_condition(channelfilter, MATCH_EXACT, "Channel", message_get_header(msg, "Channel"));
            filter_set_userdata(channelfilter, (void *) info);
            filter_register_oneshot(channelfilter);

            // Register a Filter for notifying this call
            Filter *recordfilter =
                filter_create_async(filter->sess, filter->app, "Find Recording variables", record_variables);
            filter_new_condition(recordfilter, MATCH_REGEX, "Variable", "GRABACIONES_%s_.*", info->uniqueid);
            filter_set_userdata(recordfilter, (void *) info);
            filter_register(recordfilter);

            // Construct a Request message
            AmiMessage recordget;

            for (i = 0; recordvars[i] != NULL; i++) {
                memset(&recordget, 0, sizeof(AmiMessage));
                message_add_header(&recordget, "Action: GetVar");
                message_add_header(&recordget, "Channel: %s", info->channel);
                message_add_header(&recordget, "ActionId: RECORD_%s", info->uniqueid);
                message_add_header(&recordget, "Variable: GRABACIONES_%s_%s", info->uniqueid, recordvars[i]);
                manager_write_message(manager, &recordget);
            }
        }
    }
    return 0;
}

/**
 * @brief Status command callback
 *
 * When a session request the Status command, this callback is executed.\n
 * This action basically creates a filter to monitoring the logged agents
 * Queue calls. Those calls info will be sent to status_call function
 *
 * @param sess Session structure that requested the application
 * @param app The application structure
 * @param args Additional command line arguments (not used)
 * @return 0 in all cases
 */
gint
status_exec(Session *sess, Application *app, const gchar *argstr)
{
    // Check we are logged in.
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Check we haven't run this application before
    if (session_get_variable(sess, "APPSTATUS")) {
        session_write(sess, "STATUSOK Already showing status for this agent.\r\n");
        return APP_RET_SUCCESS;
    }

    const gchar *agent = session_get_variable(sess, "AGENT");
    const gchar *interface = session_get_variable(sess, "INTERFACE");

    // Register a Filter to get All generated channels for
    Filter *queue_channel_filter = filter_create_async(sess, app, "Incoming call from queue", status_incoming_uniqueid);
    filter_new_condition(queue_channel_filter, MATCH_EXACT, "Event", "VarSet");
    filter_new_condition(queue_channel_filter, MATCH_EXACT, "Variable", "__ISAAC_MONITOR");
    filter_new_condition(queue_channel_filter, MATCH_REGEX, "Channel", "Local/%s(_1)?@agentes", agent);
    filter_register(queue_channel_filter);

    // Parse rest of status arguments
    GSList *args = application_parse_args(argstr);

    // Check if debug is enabled
    if (application_arg_exists(args, "DEBUG")) {
        session_set_variable(sess, "STATUSDEBUG", "1");
    }

    // Check with uniqueid mode
    if (application_arg_exists(args, "WUID")) {
        session_set_variable(sess, "STATUSWUID", "1");
    }

    // Check with queuename mode
    if (application_arg_exists(args, "WQUEUE")) {
        session_set_variable(sess, "STATUSWQUEUE", "1");
    }

    // Check with agent mode
    if (application_arg_exists(args, "WAGENT")) {
        session_set_variable(sess, "STATUSWAGENT", "1");

        // Listen to ISAAC_MONITOR in Agent channels
        Filter *agent_filter = filter_create_async(sess, app, "Get agent from incoming call", status_incoming_uniqueid);
        filter_new_condition(agent_filter, MATCH_EXACT, "Event", "VarSet");
        filter_new_condition(agent_filter, MATCH_EXACT, "Variable", "ISAAC_AGENT_MONITOR");
        filter_new_condition(agent_filter, MATCH_REGEX, "Channel", "%s", interface);
        filter_register(agent_filter);
    }

    if (session_get_variable(sess, "STATUSWUID") && session_get_variable(sess, "STATUSWQUEUE")) {
        session_write(sess, "STATUSOK Agent %s status will be printed (With UniqueID and Queue info).\r\n", agent);
    } else if (session_get_variable(sess, "STATUSWUID")) {
        session_write(sess, "STATUSOK Agent %s status will be printed (With UniqueID info).\r\n", agent);
    } else if (session_get_variable(sess, "STATUSWQUEUE")) {
        session_write(sess, "STATUSOK Agent %s status will be printed (With Queue info).\r\n", agent);
    } else {
        session_write(sess, "STATUSOK Agent %s status will be printed .\r\n", agent);
    }

    // Mark current session as already displaying status
    session_set_variable(sess, "APPSTATUS", "1");

    // Free args app arguments
    application_free_args(args);

    return 0;
}

/**
 * @brief Answer application callback
 *
 * Answer a channel identified by given uniqueid
 *
 * @param sess Session structure that requested the application
 * @param app The application structure
 * @param args Additional command line arguments (not used)
 * @return 0 in all cases
 */
int
answer_exec(Session *sess, Application *app, const char *args)
{
    char uniqueid[50];
    char *channame = NULL;

    // Check we are logged in.
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Parse aplication arguments
    if (sscanf(args, "%s", uniqueid) != 1) {
        return INVALID_ARGUMENTS;
    }

    if ((channame = find_agent_channel_by_uniqueid(sess, uniqueid))) {
        // Construct a Request message
        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: SIPnotifyChan");
        message_add_header(&msg, "Channel: %s", channame);
        message_add_header(&msg, "Event: talk");
        manager_write_message(manager, &msg);

        // Give some feedback
        session_write(sess, "ANSWEROK Event sent\r\n");
    } else {
        // Ups.
        session_write(sess, "ANSWERFAILED Channel not found\r\n");
    }

    return 0;
}

/**
 * @brief Holduid application callback
 *
 * Holds a channel identified by given uniqueid
 *
 * @param sess Session structure that requested the application
 * @param app The application structure
 * @param args Aditional command line arguments (not used)
 * @return 0 in all cases
 */
int
holduid_exec(Session *sess, Application *app, const char *args)
{
    char uniqueid[50];
    char *channame = NULL;

    // Check we are logged in.
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Parse application arguments
    if (sscanf(args, "%s", uniqueid) != 1) {
        return INVALID_ARGUMENTS;
    }

    if ((channame = find_agent_channel_by_uniqueid(sess, uniqueid))) {
        // Construct a Request message
        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: SIPnotifyChan");
        message_add_header(&msg, "Channel: %s", channame);
        message_add_header(&msg, "Event: hold");
        manager_write_message(manager, &msg);

        // Give some feedback
        session_write(sess, "HOLDUIDOK Event sent\r\n");
    } else {
        // Ups.
        session_write(sess, "HOLDUIDFAILED Channel not found\r\n");
    }

    return 0;
}

/**
 * @brief Unholduid application callback
 *
 * Unholds a channel identified by given uniqueid
 *
 * @param sess Session structure that requested the application
 * @param app The application structure
 * @param args Aditional command line arguments (not used)
 * @return 0 in all cases
 */
int
unholduid_exec(Session *sess, Application *app, const char *args)
{
    char uniqueid[50];
    char *channame = NULL;

    // Check we are logged in.
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Parse aplication arguments
    if (sscanf(args, "%s", uniqueid) != 1) {
        return INVALID_ARGUMENTS;
    }

    if ((channame = find_agent_channel_by_uniqueid(sess, uniqueid))) {
        // Construct a Request message
        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: SIPnotifyChan");
        message_add_header(&msg, "Channel: %s", channame);
        message_add_header(&msg, "Event: talk");
        manager_write_message(manager, &msg);

        // Give some feedback
        session_write(sess, "UNHOLDUIDOK Event sent\r\n");
    } else {
        // Ups.
        session_write(sess, "UNHOLDUIDFAILED Channel not found\r\n");
    }

    return 0;
}

/**
 * @brief Hangupuid application callback
 *
 * Hangups a channel identified by given uniqueid
 *
 * @param sess Session structure that requested the application
 * @param app The application structure
 * @param args Aditional command line arguments (not used)
 * @return 0 in all cases
 */
int
hangupuid_exec(Session *sess, Application *app, const char *args)
{
    char uniqueid[50];
    char *channame = NULL;

    // Check we are logged in.
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Parse application arguments
    if (sscanf(args, "%s", uniqueid) != 1) {
        return INVALID_ARGUMENTS;
    }

    if ((channame = find_agent_channel_by_uniqueid(sess, uniqueid))) {
        // Construct a Request message
        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Hangup");
        message_add_header(&msg, "Channel: %s", channame);
        manager_write_message(manager, &msg);

        // Give some feedback
        session_write(sess, "HANGUPUIDOK Event sent\r\n");
    } else {
        // Ups.
        session_write(sess, "HANGUPUIDFAILED Channel not found\r\n");
    }

    return 0;
}

/**
 * @brief Playbackuid application callback
 *
 * Hangups a channel identified by given uniqueid
 *
 * @param sess Session structure that requested the application
 * @param app The application structure
 * @param args Aditional command line arguments (not used)
 * @return 0 in all cases
 */
int
playbackuid_exec(Session *sess, Application *app, const char *args)
{
    char uniqueid[50], filename[512], actionid[10];
    char *channame = NULL;
    const char *response;

    // Check we are logged in.
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Parse aplication arguments
    if (sscanf(args, "%s %s", uniqueid, filename) != 2) {
        return INVALID_ARGUMENTS;
    }

    if ((channame = find_channel_by_uniqueid(sess, uniqueid))) {

        // Create a filter to get playback response
        Filter *respfilter = filter_create_sync(sess);
        filter_new_condition(respfilter, MATCH_EXACT, "Event", "Playback");
        filter_new_condition(respfilter, MATCH_EXACT, "ActionID", random_actionid(actionid, 10));
        filter_register(respfilter);

        // Construct a Request message
        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Playback");
        message_add_header(&msg, "Channel: %s", channame);
        message_add_header(&msg, "Filename: %s", filename);
        message_add_header(&msg, "ActionID: %s", actionid);
        manager_write_message(manager, &msg);

        // Get the response!
        AmiMessage retmsg;
        if (filter_run(respfilter, 5000, &retmsg) == 0) {
            response = message_get_header(&retmsg, "Result");
            if (!strcasecmp(response, "Success")) {
                session_write(sess, "PLAYBACKOK File is being played\r\n");
            } else {
                session_write(sess, "PLAYBACKFAILED Unable to play file\r\n");
            }
        } else {
            // filter didn't triggered
            session_write(sess, "PLAYBACKFAILED Request timeout\r\n");
        }
    } else {
        // Ups.
        session_write(sess, "PLAYBACKFAILED Channel not found\r\n");
    }

    return 0;
}

/**
 * @brief SetVarUID application callback
 *
 *
 */
int
setvaruid_exec(Session *sess, Application *app, const char *argstr)
{
    char uniqueid[50], options[512];
    const char *channame = NULL;
    const char *varname = NULL;
    const char *varvalue = NULL;

    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED))
        return NOT_AUTHENTICATED;

    // Check if uniqueid info is requested
    GSList *args = application_parse_args(argstr);

    // Get Variable name
    if ((varname = application_get_arg(args, "VARIABLE")) == NULL || strlen(varname) == 0) {
        application_free_args(args);
        return INVALID_ARGUMENTS;
    }

    // Get Variable value
    if ((varvalue = application_get_arg(args, "VALUE")) == NULL) {
        application_free_args(args);
        return INVALID_ARGUMENTS;
    }

    // Get target channel
    if ((channame = find_channel_by_uniqueid(sess, uniqueid))) {
        // Construct a Request message
        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", channame);
        message_add_header(&msg, "Variable: %s", varname);
        message_add_header(&msg, "Value: %s", varvalue);
        manager_write_message(manager, &msg);
        session_write(sess, "SETVARUIDOK Channel variable set\r\n");
    } else {
        // Ups.
        session_write(sess, "SETVARUIDFAILED Channel not found\r\n");
    }

    // Free args app arguments
    application_free_args(args);

    return 0;
}

/**
 * @brief RedirectUID application callback
 */
int
redirectuid_exec(Session *sess, Application *app, const char *args)
{
    char uniqueid[50], context[256], exten[80];
    const char *channame = NULL;


    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED))
        return NOT_AUTHENTICATED;

    // Get Call parameters
    if (sscanf(args, "%s %s %s", uniqueid, context, exten) < 3)
        return INVALID_ARGUMENTS;

    // Get target channel
    if ((channame = find_channel_by_uniqueid(sess, uniqueid))) {
        // Construct a Request message
        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Redirect");
        message_add_header(&msg, "Channel: %s", channame);
        message_add_header(&msg, "Context: %s", context);
        message_add_header(&msg, "Exten: %s", exten);
        message_add_header(&msg, "Priority: 1");
        manager_write_message(manager, &msg);
        session_write(sess, "REDIRECTUIDOK Channel redirected\r\n");
    } else {
        // Ups.
        session_write(sess, "REDIRECTUIFAILED Failed to redirect channel\r\n");
    }
    return 0;
}

int
recorduid_state(Filter *filter, AmiMessage *msg)
{
    // Get Call information
    AppStatusInfo *info = (AppStatusInfo *) filter_get_userdata(filter);

    // Get message data
    const char *response = message_get_header(msg, "Response");

    if (response == NULL) {
        session_write(filter->sess, "RECORDUIDFAILED %s\r\n", response);
        return -1;
    }

    if (strncasecmp(response, "Success", 7) == 0) {
        const char *mixmonitor_id = message_get_header(msg, "MixmonitorID");
        if (mixmonitor_id != NULL) {
            strcpy(info->recording_id, mixmonitor_id);
        }
    }

    // Flag this call as being recorded
    info->recording = TRUE;

    // Notify recording worked
    session_write(filter->sess, "RECORDUIDOK\r\n");
    return 0;
}

/**
 * @brief RecordUID action entry point
 *
 * RecordUID action will start MixMonitor on given channel and will
 * set some variables for record post processing (in h extension).
 *
 * @param sess Session running this application
 * @param app The application structure
 * @param args Hangup action args "ActionID" and "UniqueID"
 * @return 0 if the call is found, -1 otherwise
 */
int
recorduid_exec(Session *sess, Application *app, const char *args)
{
    AppStatusInfo *info;
    char uniqueid[ACTIONID_LEN];
    char filename[128];
    time_t timer;
    char timestr[25];
    struct tm *tm_info;

    // This can only be done after authentication
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Get Hangup parameters
    if (sscanf(args, "%s %s", uniqueid, filename) != 2) {
        return INVALID_ARGUMENTS;
    }

    // Try to find the action info of the given uniqueid
    if ((info = find_channel_info_by_uniqueid(sess, uniqueid))) {

        // Check if this call is already being recorded
        if (info->recording) {
            session_write(sess, "RECORDUIDFAILED CALL IS ALREADY BEING RECORDED\r\n");
            return -1;
        }

        Filter *record_status = filter_create_async(sess, app, "Get Recording status", recorduid_state);
        filter_new_condition(record_status, MATCH_EXACT, "ActionID", "RECORD_%s", uniqueid);
        filter_set_userdata(record_status, (void *) info);
        filter_register_oneshot(record_status);

        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: MixMonitor");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "File: %s/%s.wav", status_config.record_path, filename);
        message_add_header(&msg, "ActionID: RECORD_%s", uniqueid);
        message_add_header(&msg, "Options: i(ISAAC_RECORDING)");
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_MODULO", info->uniqueid);
        message_add_header(&msg, "Value: %sCC", info->grabaciones_modulo);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_PLATAFORMA", info->uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_plataforma, info->plat);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_TIPO", info->uniqueid);
        message_add_header(&msg, "Value: %son-demand_ISAAC", info->grabaciones_tipo);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_ORIGEN", info->uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_origen, info->clidnum);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_DESTINO", info->uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_destino, session_get_variable(sess, "AGENT"));
        manager_write_message(manager, &msg);

        time(&timer);
        tm_info = localtime(&timer);
        strftime(timestr, 25, "%Y:%m:%d_%H:%M:%S", tm_info);
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_FECHA_HORA", info->uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_fecha_hora, timestr);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_RUTA", info->uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_ruta, status_config.record_path);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_FICHERO", info->uniqueid);
        message_add_header(&msg, "Value: %s%s.wav", info->grabaciones_fichero, filename);
        manager_write_message(manager, &msg);

    } else {
        session_write(sess, "RECORDUIDFAILED ID NOT FOUND\r\n");
        return -1;
    }
    return 0;
}

/**
 * @brief RecordUID action entry point
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
recordstopuid_exec(Session *sess, Application *app, const char *args)
{
    AppStatusInfo *info;
    char uniqueid[ACTIONID_LEN];

    // This can only be done after authentication
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Get Hangup parameters
    if (sscanf(args, "%s", uniqueid) != 1) {
        return INVALID_ARGUMENTS;
    }

    // Try to find the action info of the given actionid
    if ((info = find_channel_info_by_uniqueid(sess, uniqueid))) {

        // Check if this call is not being recorded
        if (!info->recording) {
            session_write(sess, "RECORDSTOPUIDFAILED CALL NOT BEING RECORDED\r\n");
            return -1;
        }

        AmiMessage msg;
        memset(&msg, 0, sizeof(AmiMessage));
        message_add_header(&msg, "Action: StopMixMonitor");
        message_add_header(&msg, "Channel: %s", info->channel);
        if (strlen(info->recording_id) != 0) {
            message_add_header(&msg, "MixMonitorID: %s", info->recording_id);
        }
        manager_write_message(manager, &msg);

        // Flag this call as not being recorded
        info->recording = FALSE;

        session_write(sess, "RECORDSTOPUIDOK\r\n");
    } else {
        session_write(sess, "RECORDSTOPUIDFAILED ID NOT FOUND\r\n");
        return -1;
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
gint
load_module()
{
    gint ret = 0;
    if (!read_status_config(STATUSCONF)) {
        isaac_log(LOG_ERROR, "Failed to read app_status config file %s\n", STATUSCONF);
        return -1;
    }
    ret |= application_register("STATUS", status_exec);
    ret |= application_register("ANSWER", answer_exec);
    ret |= application_register("ANSWERUID", answer_exec);
    ret |= application_register("HOLDUID", holduid_exec);
    ret |= application_register("UNHOLDUID", unholduid_exec);
    ret |= application_register("HANGUPUID", hangupuid_exec);
    ret |= application_register("PLAYBACKUID", playbackuid_exec);
    ret |= application_register("SETVARUID", setvaruid_exec);
    ret |= application_register("REDIRECTUID", redirectuid_exec);
    ret |= application_register("RECORDUID", recorduid_exec);
    ret |= application_register("RECORDSTOPUID", recordstopuid_exec);
    return ret;
}

/**
 * @brief Module unload entry point
 *
 * Unload module applications
 *
 * @return 0 if all applications are unloaded, -1 otherwise
 */
gint
unload_module()
{
    gint ret = 0;
    ret |= application_unregister("STATUS");
    ret |= application_unregister("ANSWER");
    ret |= application_unregister("ANSWERUID");
    ret |= application_unregister("HOLDUID");
    ret |= application_unregister("UNHOLDUID");
    ret |= application_unregister("HANGUPUID");
    ret |= application_unregister("PLAYBACKUID");
    ret |= application_unregister("SETVARUID");
    ret |= application_unregister("REDIRECTUID");
    ret |= application_unregister("RECORDUID");
    ret |= application_unregister("RECORDSTOPUID");
    return ret;
}
