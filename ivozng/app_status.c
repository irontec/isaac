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
 *  required contexts conifgured in asterisk.
 *
 * Check for incoming calls to agents and print status events. This module will
 * also check if the call is being called to another agent.
 *
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <libconfig.h>
#include "app.h"
#include "session.h"
#include "manager.h"
#include "filter.h"
#include "util.h"
#include "log.h"

#define STATUSCONF CONFDIR "/status.conf"

char *recordvars[] =
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
 * @brief Module configuration readed from STATUSCONF file
 *
 * @see read_call_config
 */
struct app_status_config
{
    //! File recorded path
    char record_path[512];
} status_config;


/**
 * @brief Status application custom structure
 *
 * This structure contains the information of a Queue incoming call
 * to print EXTERNALCALLSTATUS messages
 */
struct app_status_info
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
    //! Agent channel in case of attended tansfer
    char xfer_channel[80];
    //! Answered flag
    bool answered;
    //! Holded flag
    bool holded;
    //! Direct agent
    bool agent;
    //! Mark the call as being recorded
    bool recording;
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
};

/**
 * @brief Read module configure options
 *
 * This function will read STATUSCONF file and fill app_call_conf
 * structure. Most of these values are using during call action process
 *
 * @param cfile Full path to configuration file
 * @return 0 in case of read success, -1 otherwise
 */
int
read_status_config(const char *cfile)
{
    config_t cfg;
    const char *value;

    // Initialize configuration
    config_init(&cfg);

    // Read configuraiton file
    if (config_read_file(&cfg, cfile) == CONFIG_FALSE) {
        isaac_log(LOG_ERROR, "Error parsing configuration file %s on line %d: %s\n", cfile,
                  config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return -1;
    }

    // Filepat to store the recordings
    if (config_lookup_string(&cfg, "record.filepath", &value) == CONFIG_TRUE) {
        strcpy(status_config.record_path, value);
    }

    // Dealloc libconfig structure
    config_destroy(&cfg);

    isaac_log(LOG_VERBOSE_3, "Readed configuration from %s\n", cfile);
    return 0;
}


/**
 * @brief Returns agent channel name for a given UniqueID
 *
 * @param uniqueid Channel UniqueID
 * @returns agent channel name or NULL if not found
 */
char *
find_agent_channel_by_uniqueid(session_t *sess, const char *uniqueid)
{
    filter_t *filter = NULL;
    struct app_status_info *info = NULL;

    // Find the call with that uniqueid
    while ((filter = filter_from_session(sess, filter))) {
        info = (struct app_status_info *) filter_get_userdata(filter);
        if (info && !strcasecmp(info->uniqueid, uniqueid)) {
            return info->agent_channel;
        }
    }

    // No channel found with that uniqueid
    return NULL;
}

/**
 * @brief Returns channel name for a given UniqueID
 *
 * @param uniqueid Channel UniqueID
 * @returns channel name or NULL if not found
 */
char *
find_channel_by_uniqueid(session_t *sess, const char *uniqueid)
{
    filter_t *filter = NULL;
    struct app_status_info *info = NULL;

    // Find the call with that uniqueid
    while ((filter = filter_from_session(sess, filter))) {
        info = (struct app_status_info *) filter_get_userdata(filter);
        if (info && !strcasecmp(info->uniqueid, uniqueid)) {
            return info->channel;
        }
    }

    // No channel found with that uniqueid
    return NULL;
}


/**
 * @brief Returns channel name for a given UniqueID
 *
 * @param uniqueid Channel UniqueID
 * @returns status structure pointer or NULL if not found
 */
struct app_status_info *
find_channel_info_by_uniqueid(session_t *sess, const char *uniqueid)
{
    filter_t *filter = NULL;
    struct app_status_info *info = NULL;

    // Find the call with that uniqueid
    while ((filter = filter_from_session(sess, filter))) {
        info = (struct app_status_info *) filter_get_userdata(filter);
        if (info && !strcasecmp(info->uniqueid, uniqueid)) {
            return info;
        }
    }

    // No channel found with that uniqueid
    return NULL;
}

/**
 * @brief Injects messages to AMI to simulate an incoming call
 *
 * When a transfer occurs, some clients want to receive status
 * messages in the transfer receiver bus.
 *
 * This is not naturaly possible so, if we want to trigger
 * status filters, we must inject those messages.
 *
 * For a status callback trigger, we need
 * a) Transfer receiver Agent
 * b) Transfer receiver Channel
 * c) Transfer receiver Channel status (Anwered, Ringing..)
 *
 * The rest of the information (such as platform, uniqueid, ...)
 * will be the same that the original one (stored in the filter
 * userdata pointer)
 */
int
status_inject_queue_call(filter_t *filter)
{

    struct app_status_info *info = (struct app_status_info *) filter_get_userdata(filter);

    /**
     * For EXTERNALCALLAGENT events we don't require to inject events in AMI
     * Dialplan will trigger the ISAAC_AGENT_MONITOR variable logic
     */
    if (info->agent) return 1;

    /* Construct a Request message (fake VarSet).
     * This will trigger the initial Status callback and will try to search a
     * Event: Dial message to obtain the real SIP/ channel name (not the Local/ one)
     */
    ami_message_t usermsg;
    memset(&usermsg, 0, sizeof(ami_message_t));
    message_add_header(&usermsg, "Event: VarSet");
    message_add_header(&usermsg, "Variable: __ISAAC_MONITOR");
    message_add_header(&usermsg, "Value: %s!%s!%s!%s!%s", info->plat, info->clidnum, info->channel, info->uniqueid,
                       info->queue);
    message_add_header(&usermsg, "Channel: Local/%s@agentes", info->xfer_agent);
    filter_inject_message(filter, &usermsg);

    /* Construct a Request message (fake Dial).
     * We trigger the second callback of Status, now providing the SIP/ channel name
     * so the logic can detect when this channel status changes
     */
    memset(&usermsg, 0, sizeof(ami_message_t));
    message_add_header(&usermsg, "Event: Dial");
    message_add_header(&usermsg, "SubEvent: Begin");
    message_add_header(&usermsg, "Channel: Local/%s@agentes", info->xfer_agent);
    message_add_header(&usermsg, "Destination: %s", info->xfer_channel);
    message_add_header(&usermsg, "CallerIDName: %s", info->plat);
    message_add_header(&usermsg, "CallerIDNum: %s", info->clidnum);
    filter_inject_message(filter, &usermsg);

    /* Construct NewState fake status messages
     * We generate Newstate messages to update the channel status to match the
     * real status.
     */
    if (info->xfer_state >= 5) {
        memset(&usermsg, 0, sizeof(ami_message_t));
        message_add_header(&usermsg, "Event: Newstate");
        message_add_header(&usermsg, "Channel: %s", info->xfer_channel);
        message_add_header(&usermsg, "ChannelState: 5");
        filter_inject_message(filter, &usermsg);
    }

    if (info->xfer_state >= 6) {
        memset(&usermsg, 0, sizeof(ami_message_t));
        message_add_header(&usermsg, "Event: Newstate");
        message_add_header(&usermsg, "Channel: %s", info->xfer_channel);
        message_add_header(&usermsg, "ChannelState: 6");
        filter_inject_message(filter, &usermsg);
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
int
status_blindxfer(filter_t *filter, ami_message_t *msg)
{
    struct app_status_info *info = (struct app_status_info *) filter_get_userdata(filter);

    // Not previous status known on blind transfer
    info->xfer_state = 0;
    // Destiny transfer channel name
    isaac_strcpy(info->xfer_channel, message_get_header(msg, "Destination"));

    // We have enough information to inject messages in receiver bus
    status_inject_queue_call(filter);

    return 0;
}

/**
 * @brief Callback for attended transfer using features
 *
 * When agents transfer using builtin, a new local channel is spwaned that call the
 * final agent.
 * We try to find the dial that calls to the final agent to fill our xfer structures
 *
 */
int
status_builtinxfer(filter_t *filter, ami_message_t *msg)
{
    struct app_status_info *info = (struct app_status_info *) filter_get_userdata(filter);

    if (!strcasecmp(message_get_header(msg, "Variable"), "TRANSFERERNAME")) {
        char local_channel[80];
        isaac_strcpy(local_channel, message_get_header(msg, "Channel"));
        local_channel[strlen(local_channel) - 1] = '2';

        // Try to find the final xfer channel
        filter_t *builtinxferfilter = filter_create_async(filter->sess, status_builtinxfer);
        filter_new_condition(builtinxferfilter, MATCH_EXACT, "Event", "VarSet");
        filter_new_condition(builtinxferfilter, MATCH_EXACT, "Channel", local_channel);
        filter_new_condition(builtinxferfilter, MATCH_EXACT, "Variable", "BRIDGEPEER");
        filter_new_condition(builtinxferfilter, MATCH_START_WITH, "Value", "SIP/");
        filter_set_userdata(builtinxferfilter, (void *) info);
        filter_register_oneshot(builtinxferfilter);

    } else if (!strcasecmp(message_get_header(msg, "Variable"), "BRIDGEPEER")) {
        // Final Xfer channel found!
        isaac_strcpy(info->xfer_channel, message_get_header(msg, "Value"));
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
int
status_print(filter_t *filter, ami_message_t *msg)
{
    struct app_status_info *info = (struct app_status_info *) filter_get_userdata(filter);
    session_t *sess = filter->sess;
    const char *event = message_get_header(msg, "Event");
    char statusevent[512];

    // Initialize response string
    memset(statusevent, 0, sizeof(statusevent));

    // CallStatus response
    if (!isaac_strcmp(event, "Newstate") || !isaac_strcmp(event, "Hangup")
        || !isaac_strcmp(event, "IsaacTransfer")  || !isaac_strncmp(event, "MusicOnHold", 11)) {
        if (info->agent) {
            sprintf(statusevent, "EXTERNALCALLAGENTSTATUS ");
        } else {
            sprintf(statusevent, "EXTERNALCALLSTATUS ");
        }
        if (session_get_variable(sess, "STATUSWUID"))
            sprintf(statusevent + strlen(statusevent), "%s ", info->uniqueid);
        if (session_get_variable(sess, "STATUSDEBUG"))
            sprintf(statusevent + strlen(statusevent), "%s %s ", info->agent_channel, info->channel);
        sprintf(statusevent + strlen(statusevent), "%s ", info->plat);
        if (session_get_variable(sess, "STATUSWQUEUE"))
            sprintf(statusevent + strlen(statusevent), "%s ", info->queue);
        sprintf(statusevent + strlen(statusevent), "%s ", info->clidnum);
    }

    // Send ExternalCallStatus message depending on received event
    if (!isaac_strcmp(event, "Newstate")) {

        // Print status message depending on Channel Status
        if (!isaac_strcmp(message_get_header(msg, "ChannelState"), "5")) {
            sprintf(statusevent + strlen(statusevent), "RINGING\r\n");
        } else if (!isaac_strcmp(message_get_header(msg, "ChannelState"), "6")) {
            sprintf(statusevent + strlen(statusevent), "ANSWERED\r\n");
            info->answered = true;

            filter_t *callfilter = filter_create_async(filter->sess, status_print);
            filter_new_condition(callfilter, MATCH_REGEX, "Event", "MusicOnHold|MusicOnHoldStart|MusicOnHoldStop");
            filter_new_condition(callfilter, MATCH_EXACT, "Channel", info->channel);
            filter_set_userdata(callfilter, (void *) info);
            filter_register(callfilter);
        }
    } else if (!strncasecmp(event, "MusicOnHold",11)) {
        // This filter lives only during answered calls
        if (info->answered) {
            // Avoid sending multiple times the same status
            if (!info->holded &&
                (!strcasecmp(event, "MusicOnHoldStart") || !strcasecmp(message_get_header(msg, "State"), "Start"))
            ) {
                sprintf(statusevent + strlen(statusevent), "HOLD\r\n");
                info->holded = 1;
            } else if (info->holded &&
                    (!strcasecmp(event, "MusicOnHoldStop") || !strcasecmp(message_get_header(msg, "State"), "Stop"))
            ) {
                sprintf(statusevent + strlen(statusevent), "UNHOLD\r\n");
                info->holded = 0;
            } else {
                // Clear this event
                memset(statusevent, 0, sizeof(statusevent));
            }
        } else {
            // Hold filter is no longer needed
            filter_unregister(filter);
            // Clear this event
            memset(statusevent, 0, sizeof(statusevent));
        }

    } else if (!isaac_strcmp(event, "Hangup")) {

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
        sprintf(statusevent + strlen(statusevent), "HANGUP\r\n");
        info->answered = false;

        // Unregister all filters of current channel
        filter = NULL;
        while ((filter = filter_from_userdata(sess, info))) {
            filter_unregister(filter);
        }
    } else if (!isaac_strcmp(event, "IsaacTransfer")) {
        // Queue call has been transfered
        sprintf(statusevent + strlen(statusevent), "TRANSFERRED\r\n");

        if (!isaac_strcmp(message_get_header(msg, "TransferType"), "Attended")) {
            // We have the destriny information
            isaac_strcpy(info->xfer_channel, message_get_header(msg, "TargetChannel"));
            isaac_strcpy(info->xfer_agent, message_get_header(msg, "TransferExten"));
            // Blonde transfer, destiny was ringing
            info->xfer_state = 6;
            // We have enough information to inject messages in receiver bus
            isaac_log(LOG_NOTICE, "[Session %s] Detected Attended Transfer to %s\n", filter->sess->id,
                      info->xfer_agent);
            status_inject_queue_call(filter);
        }

        if (!isaac_strcmp(message_get_header(msg, "TransferType"), "Blonde")) {
            // We have the destriny information
            isaac_strcpy(info->xfer_channel, message_get_header(msg, "TargetChannel"));
            isaac_strcpy(info->xfer_agent, message_get_header(msg, "TransferExten"));
            // Blonde transfer, destiny was ringing
            info->xfer_state = 5;
            // We have enough information to inject messages in receiver bus
            isaac_log(LOG_NOTICE, "[Session %s] Detected Blonde Transfer to %s\n", filter->sess->id, info->xfer_agent);
            status_inject_queue_call(filter);
        }

        if (!isaac_strcmp(message_get_header(msg, "TransferType"), "Blind")) {

            // Copy the destiny agent
            isaac_strcpy(info->xfer_agent, message_get_header(msg, "TransferExten"));
            isaac_log(LOG_NOTICE, "[Session %s] Detected Blind Transfer to %s\n", filter->sess->id, info->xfer_agent);

            // Find the session for the given interface
            session_t *xfer_sess = session_by_variable("AGENT", info->xfer_agent);

            if (xfer_sess) {
                // We get the Attender transfer type from masquearde Event
                filter_t *blindxferfilter = filter_create_async(sess, status_blindxfer);
                filter_new_condition(blindxferfilter, MATCH_EXACT, "Event", "Dial");
                filter_new_condition(blindxferfilter, MATCH_EXACT, "SubEvent", "Begin");
                filter_new_condition(blindxferfilter, MATCH_EXACT, "Channel", info->channel);
                filter_set_userdata(blindxferfilter, (void *) info);
                filter_register_oneshot(blindxferfilter);
            }
        }

        if (!isaac_strcmp(message_get_header(msg, "TransferType"), "Builtin")) {
            if (!isaac_strcmp(message_get_header(msg, "SubEvent"), "Begin")) {
                isaac_strcpy(info->xfer_agent, message_get_header(msg, "TransferExten"));
                info->xfer_state = 6;

                // We get the Attender transfer type from masquearde Event
                filter_t *builtinxferfilter = filter_create_async(sess, status_builtinxfer);
                filter_new_condition(builtinxferfilter, MATCH_EXACT, "Event", "VarSet");
                filter_new_condition(builtinxferfilter, MATCH_EXACT, "Variable", "TRANSFERERNAME");
                filter_new_condition(builtinxferfilter, MATCH_EXACT, "Value", info->agent_channel);
                filter_set_userdata(builtinxferfilter, (void *) info);
                filter_register_oneshot(builtinxferfilter);

                // Not yet ready to consider this a transfer
                memset(statusevent, 0, sizeof(statusevent));
            } else {
                char xferchan[80];
                isaac_strcpy(xferchan, info->xfer_channel);
                char *interface = strtok(xferchan, "-");

                // Find the session for the given interface
                session_t *xfer_sess = session_by_variable("INTERFACE", interface);

                if (xfer_sess) {
                    // We have enough information to inject messages in receiver bus
                    isaac_strcpy(info->xfer_agent, session_get_variable(xfer_sess, "AGENT"));
                    isaac_log(LOG_NOTICE, "[Session %s] Detected Builtin Transfer to %s\n", filter->sess->id,
                              info->xfer_agent);
                    status_inject_queue_call(filter);
                } else {
                    // Oh, transfering to someone not logged in
                    isaac_log(LOG_WARNING,
                              "[Session %s] Ignoring transfer injection to %s. It does not have any Isaac sessions Up.\n",
                              filter->sess->id, interface);
                }
            }
        }
    }

    // Check if there's something to write to client
    if (strlen(statusevent)) {
        session_write(sess, statusevent);
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
int
status_call(filter_t *filter, ami_message_t *msg)
{
    struct app_status_info *info = (struct app_status_info *) filter_get_userdata(filter);

    // Get the interesting channel name, we will fetch the rest of the messages
    // that match that ID
    isaac_strcpy(info->agent_channel, message_get_header(msg, "Destination"));
    // Fallback for DialBegin Asterisk 18+ event
    if (strlen(info->agent_channel) == 0) {
        isaac_strcpy(info->agent_channel, message_get_header(msg, "DestChannel"));
    }

    // Register a Filter for notifying this call
    filter_t *callfilter = filter_create_async(filter->sess, status_print);
    filter_new_condition(callfilter, MATCH_REGEX, "Event", "Newstate|Hangup|IsaacTransfer");
    filter_new_condition(callfilter, MATCH_EXACT, "Channel", info->agent_channel);
    filter_set_userdata(callfilter, (void *) info);
    filter_register(callfilter);

    return 0;
}

int
record_variables(filter_t *filter, ami_message_t *msg)
{
    const char *varvalue = message_get_header(msg, "Value");
    const char *varname = message_get_header(msg, "Variable");

    if (!strncasecmp(varname, "GRABACIONES_", 12)) {
        char recordvar[256], recorduniqueid[80], grabaciones[80], recordtype[80];
        isaac_strcpy(recordvar, varname);
        if (sscanf(recordvar, "%[^_]_%[^_]_%s", grabaciones, recorduniqueid, recordtype) == 3) {
            struct app_status_info *info;
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
status_incoming_uniqueid(filter_t *filter, ami_message_t *msg)
{
    char value[512];
    char plat[120], clidnum[20], uniqueid[20], channel[80], queue[150];
    int i;

    // Copy __ISAAC_MONITOR value
    isaac_strcpy(value, message_get_header(msg, "Value"));

    // Initialize al variables
    memset(plat, 0, sizeof(plat));
    memset(clidnum, 0, sizeof(clidnum));
    memset(uniqueid, 0, sizeof(uniqueid));
    memset(channel, 0, sizeof(channel));
    memset(queue, 0, sizeof(queue));

    if (sscanf(value, "%[^!]!%[^!]!%[^!]!%[^!]!%s", plat, clidnum, channel, uniqueid, queue)) {
        isaac_log(LOG_DEBUG, "[Session %s] Detected %s on channel %s: %s\n",
                  filter->sess->id,
                  message_get_header(msg, "Variable"),
                  message_get_header(msg, "Channel"),
                  message_get_header(msg, "Value"));

        // Initialize application info
        struct app_status_info *info = malloc(sizeof(struct app_status_info));
        memset(info, 0, sizeof(struct app_status_info));
        isaac_strcpy(info->plat, plat);
        isaac_strcpy(info->clidnum, clidnum);
        isaac_strcpy(info->channel, channel);
        isaac_strcpy(info->uniqueid, uniqueid);
        isaac_strcpy(info->queue, queue);
        info->answered = false;
        info->holded = false;
        info->agent = false;
        info->recording = false;

        // If variable matches agent format
        if (!strcmp(message_get_header(msg, "Variable"), "ISAAC_AGENT_MONITOR")) {
            // Mark this as direct to agent
            info->agent = true;
            // Store agent channel name
            isaac_strcpy(info->agent_channel, message_get_header(msg, "Channel"));

            // Register a Filter for notifying this call
            filter_t *callfilter = filter_create_async(filter->sess, status_print);
            filter_new_condition(callfilter, MATCH_REGEX, "Event", "Newstate|Hangup|IsaacTransfer|VarSet");
            filter_new_condition(callfilter, MATCH_EXACT, "Channel", info->agent_channel);
            filter_set_userdata(callfilter, (void *) info);
            filter_register(callfilter);

        } else {
            filter_t *channelfilter = filter_create_async(filter->sess, status_call);
            filter_new_condition(channelfilter, MATCH_REGEX, "Event", "Dial|DialBegin");
            filter_new_condition(channelfilter, MATCH_REGEX, "SubEvent", "Begin|");
            filter_new_condition(channelfilter, MATCH_EXACT, "Channel", message_get_header(msg, "Channel"));
            filter_set_userdata(channelfilter, (void *) info);
            filter_register_oneshot(channelfilter);

            // Register a Filter for notifying this call
            filter_t *recordfilter = filter_create_async(filter->sess, record_variables);
            filter_new_condition(recordfilter, MATCH_REGEX, "Variable", "GRABACIONES_%s_.*", info->uniqueid);
            filter_set_userdata(recordfilter, (void *) info);
            filter_register(recordfilter);

            // Construct a Request message
            ami_message_t recordget;

            for (i = 0; recordvars[i] != NULL; i++) {
                memset(&recordget, 0, sizeof(ami_message_t));
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
 * @param args Aditional command line arguments (not used)
 * @return 0 in all cases
 */
int
status_exec(session_t *sess, app_t *app, const char *args)
{
    const char *agent = session_get_variable(sess, "AGENT");
    const char *interface = session_get_variable(sess, "INTERFACE");

    // Check we are logged in.
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Check we havent run this application before
    if (session_get_variable(sess, "APPSTATUS")) {
        session_write(sess, "STATUSOK Already showing status for this agent.\r\n");
        return 0;
    }

    // Register a Filter to get All generated channels for
    filter_t *channelfilter = filter_create_async(sess, status_incoming_uniqueid);
    filter_new_condition(channelfilter, MATCH_EXACT, "Event", "VarSet");
    filter_new_condition(channelfilter, MATCH_EXACT, "Variable", "__ISAAC_MONITOR");
    filter_new_condition(channelfilter, MATCH_REGEX, "Channel", "Local/%s(_1)?@agentes", agent);
    filter_register(channelfilter);

    // Parse rest of status arguments
    app_args_t parsed;
    application_parse_args(args, &parsed);

    // Check if debug is enabled
    if (!isaac_strcmp(application_get_arg(&parsed, "DEBUG"), "1"))
        session_set_variable(sess, "STATUSDEBUG", "1");

    // Check with uniqueid mode
    if (!isaac_strcmp(application_get_arg(&parsed, "WUID"), "1"))
        session_set_variable(sess, "STATUSWUID", "1");

    // Check with queuename mode
    if (!isaac_strcmp(application_get_arg(&parsed, "WQUEUE"), "1"))
        session_set_variable(sess, "STATUSWQUEUE", "1");

    // Check with agent mode
    if (!isaac_strcmp(application_get_arg(&parsed, "WAGENT"), "1")) {
        session_set_variable(sess, "STATUSWAGENT", "1");

        // Listen to ISAAC_MONITOR in Agent channels
        filter_t *agentfilter = filter_create_async(sess, status_incoming_uniqueid);
        filter_new_condition(agentfilter, MATCH_EXACT, "Event", "VarSet");
        filter_new_condition(agentfilter, MATCH_EXACT, "Variable", "ISAAC_AGENT_MONITOR");
        filter_new_condition(agentfilter, MATCH_REGEX, "Channel", "%s", interface);
        filter_register(agentfilter);
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

    session_set_variable(sess, "APPSTATUS", "1");

    return 0;
}

/**
 * @brief Answer application callback
 *
 * Answer a channel identified by given uniqueid
 *
 * @param sess Session structure that requested the application
 * @param app The application structure
 * @param args Aditional command line arguments (not used)
 * @return 0 in all cases
 */
int
answer_exec(session_t *sess, app_t *app, const char *args)
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
        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
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
holduid_exec(session_t *sess, app_t *app, const char *args)
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
        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
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
unholduid_exec(session_t *sess, app_t *app, const char *args)
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
        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
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
hangupuid_exec(session_t *sess, app_t *app, const char *args)
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
        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
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
playbackuid_exec(session_t *sess, app_t *app, const char *args)
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
        filter_t *respfilter = filter_create_sync(sess);
        filter_new_condition(respfilter, MATCH_EXACT, "Event", "Playback");
        filter_new_condition(respfilter, MATCH_EXACT, "ActionID", random_actionid(actionid, 10));
        filter_register(respfilter);

        // Construct a Request message
        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Playback");
        message_add_header(&msg, "Channel: %s", channame);
        message_add_header(&msg, "Filename: %s", filename);
        message_add_header(&msg, "ActionID: %s", actionid);
        manager_write_message(manager, &msg);

        // Get the response!
        ami_message_t retmsg;
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
setvaruid_exec(session_t *sess, app_t *app, const char *args)
{
    char uniqueid[50], options[512];
    const char *channame = NULL;
    const char *varname = NULL;
    const char *varvalue = NULL;


    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED))
        return NOT_AUTHENTICATED;

    // Get Call parameteres
    if (sscanf(args, "%s %[^\n]", uniqueid, options) < 2)
        return INVALID_ARGUMENTS;

    // Check if uniqueid info is requested
    app_args_t parsed;
    application_parse_args(options, &parsed);


    // Get Variable name
    if (!(varname = application_get_arg(&parsed, "VARIABLE")) && strlen(varname))
        return INVALID_ARGUMENTS;

    // Get Variable value
    if (!(varvalue = application_get_arg(&parsed, "VALUE")))
        return INVALID_ARGUMENTS;

    // Get target channel
    if ((channame = find_channel_by_uniqueid(sess, uniqueid))) {
        // Construct a Request message
        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
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
    return 0;
}

/**
 * @brief RedirectUID application callback
 */
int
redirectuid_exec(session_t *sess, app_t *app, const char *args)
{
    char uniqueid[50], context[256], exten[80];
    const char *channame = NULL;


    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED))
        return NOT_AUTHENTICATED;

    // Get Call parameteres
    if (sscanf(args, "%s %s %s", uniqueid, context, exten) < 3)
        return INVALID_ARGUMENTS;

    // Get target channel
    if ((channame = find_channel_by_uniqueid(sess, uniqueid))) {
        // Construct a Request message
        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
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
recorduid_state(filter_t *filter, ami_message_t *msg)
{
    // Get Call information
    struct app_status_info *info = (struct app_status_info *) filter_get_userdata(filter);

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
    info->recording = true;

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
 * @param sess Session rnuning this application
 * @param app The application structure
 * @param args Hangup action args "ActionID" and "UniqueID"
 * @return 0 if the call is found, -1 otherwise
 */
int
recorduid_exec(session_t *sess, app_t *app, const char *args)
{
    struct app_status_info *info;
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

        filter_t *record_status = filter_create_async(sess, recorduid_state);
        filter_new_condition(record_status, MATCH_EXACT, "ActionID", "RECORD_%s", uniqueid);
        filter_set_userdata(record_status, (void *) info);
        filter_register_oneshot(record_status);

        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: MixMonitor");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "File: %s/%s.wav", status_config.record_path, filename);
        message_add_header(&msg, "ActionID: RECORD_%s", uniqueid);
        message_add_header(&msg, "Options: i(ISAAC_RECORDING)");
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_MODULO", info->uniqueid);
        message_add_header(&msg, "Value: %sCC", info->grabaciones_modulo);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_PLATAFORMA", info->uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_plataforma, info->plat);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_TIPO", info->uniqueid);
        message_add_header(&msg, "Value: %son-demand_ISAAC", info->grabaciones_tipo);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_ORIGEN", info->uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_origen, info->clidnum);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_DESTINO", info->uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_destino, session_get_variable(sess, "AGENT"));
        manager_write_message(manager, &msg);

        time(&timer);
        tm_info = localtime(&timer);
        strftime(timestr, 25, "%Y:%m:%d_%H:%M:%S", tm_info);
        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_FECHA_HORA", info->uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_fecha_hora, timestr);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Setvar");
        message_add_header(&msg, "Channel: %s", info->channel);
        message_add_header(&msg, "Variable: GRABACIONES_%s_RUTA", info->uniqueid);
        message_add_header(&msg, "Value: %s%s", info->grabaciones_ruta, status_config.record_path);
        manager_write_message(manager, &msg);

        memset(&msg, 0, sizeof(ami_message_t));
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
recordstopuid_exec(session_t *sess, app_t *app, const char *args)
{
    struct app_status_info *info;
    char uniqueid[ACTIONID_LEN];

    // This can only be done after authentication
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Get Hangup parameteres
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

        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: StopMixMonitor");
        message_add_header(&msg, "Channel: %s", info->channel);
        if (strlen(info->recording_id) != 0) {
            message_add_header(&msg, "MixMonitorID: %s", info->recording_id);
        }
        manager_write_message(manager, &msg);

        // Flag this call as not being recorded
        info->recording = false;

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
int
load_module()
{
    int ret = 0;
    if (read_status_config(STATUSCONF) != 0) {
        isaac_log(LOG_ERROR, "Failed to read app_status config file %s\n", STATUSCONF);
        return -1;
    }
    ret |= application_register("Status", status_exec);
    ret |= application_register("Answer", answer_exec);
    ret |= application_register("AnswerUID", answer_exec);
    ret |= application_register("HoldUID", holduid_exec);
    ret |= application_register("UnholdUID", unholduid_exec);
    ret |= application_register("HangupUID", hangupuid_exec);
    ret |= application_register("PlaybackUID", playbackuid_exec);
    ret |= application_register("SetVarUID", setvaruid_exec);
    ret |= application_register("RedirectUID", redirectuid_exec);
    ret |= application_register("RecordUID", recorduid_exec);
    ret |= application_register("RecordStopUID", recordstopuid_exec);
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
    ret |= application_unregister("Status");
    ret |= application_unregister("Answer");
    ret |= application_unregister("AnswerUID");
    ret |= application_unregister("HoldUID");
    ret |= application_unregister("UnholdUID");
    ret |= application_unregister("HangupUID");
    ret |= application_unregister("PlaybackUID");
    ret |= application_unregister("SetVarUID");
    ret |= application_unregister("RedirectUID");
    ret |= application_unregister("RecordUID");
    ret |= application_unregister("RecordStopUID");
    return ret;
}
