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

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "app.h"
#include "session.h"
#include "manager.h"
#include "filter.h"
#include "util.h"
#include "log.h"

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
    //! CallerID num of the incoming call
    char clidnum[20];
    //! UniqueID from incoming call
    char uniqueid[20];
    //! Incoming Channel name
    char channel[80];
    //! Agent channel
    char agent_channel[80];
    //! Attended transfer State (See Asterisk Call states)
    int  xfer_state;
    //! Agent to which this call is being transferred
    char xfer_agent[20];
    //! Agent channel in case of attended tansfer
    char xfer_channel[80];
    //! Answered flag
    bool answered;
};

/**
 * @brief Returns channel name for a given UniqueID
 *
 * @param uniqueid Channel UniqueID
 * @returns channel name or NULL if not found
 */
char *
find_channel_by_uniqueid(session_t *sess, const char *uniqueid) {
    filter_t *filter = NULL;
    struct app_status_info *info = NULL;

    // Find the call with that uniqueid
    while((filter = filter_from_session(sess, filter))) {
        info = (struct app_status_info *) filter_get_userdata(filter);
        if (info && !strcasecmp(info->uniqueid, uniqueid)) {
            return info->agent_channel;
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

    /* Construct a Request message (fake VarSet).
     * This will trigger the initial Status callback and will try to search a 
     * Event: Dial message to obtain the real SIP/ channel name (not the Local/ one) 
     */
    ami_message_t usermsg;
    memset(&usermsg, 0, sizeof(ami_message_t));
    message_add_header(&usermsg, "Event: VarSet");
    message_add_header(&usermsg, "Variable: __ISAAC_MONITOR");
    message_add_header(&usermsg, "Value: \"%s!%s!%s!%s\"", info->plat, info->clidnum, info->channel, info->uniqueid);
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
        local_channel[strlen(local_channel)-1] = '2';

        // Try to find the final xfer channel
        filter_t *builtinxferfilter = filter_create(filter->sess, FILTER_SYNC_CALLBACK, status_builtinxfer);
        filter_new_condition(builtinxferfilter, MATCH_EXACT, "Event", "VarSet");
        filter_new_condition(builtinxferfilter, MATCH_EXACT, "Channel", local_channel);
        filter_new_condition(builtinxferfilter, MATCH_EXACT, "Variable", "BRIDGEPEER");
        filter_new_condition(builtinxferfilter, MATCH_START_WITH, "Value", "SIP/");
        filter_set_userdata(builtinxferfilter, (void*) info);
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
    || !isaac_strcmp(event, "IsaacTransfer")) {
        sprintf(statusevent, "EXTERNALCALLSTATUS ");
        if (session_get_variable(sess, "STATUSWUID")) 
            sprintf(statusevent + strlen(statusevent), "%s ", info->uniqueid);
        if (session_get_variable(sess, "STATUSDEBUG"))
            sprintf(statusevent + strlen(statusevent), "%s %s ", info->agent_channel, info->channel);
        sprintf(statusevent + strlen(statusevent), "%s ", info->plat);
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
        }

    } else if (!isaac_strcmp(event, "Hangup")) {

        const char *cause = message_get_header(msg, "Cause");
        if (!isaac_strcmp(cause, "17")) {
            // Queue call rejected by agent
            sprintf(statusevent + strlen(statusevent), "BUSY\r\n");
        } else if (!info->answered) {
            // Queue call timeout
            sprintf(statusevent + strlen(statusevent), "NOANSWER\r\n");
        } else {
            // Queue call has finished for this agent
            sprintf(statusevent + strlen(statusevent), "HANGUP\r\n");
        }

        // We dont expect more info about this filter, it's safe to unregister it here
        filter_unregister(filter);

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
            isaac_log(LOG_NOTICE, "[Session %s] Detected Attended Transfer to %s\n", filter->sess->id, info->xfer_agent);
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
                filter_t *blindxferfilter = filter_create(sess, FILTER_SYNC_CALLBACK, status_blindxfer);
                filter_new_condition(blindxferfilter, MATCH_EXACT, "Event", "Dial");
                filter_new_condition(blindxferfilter, MATCH_EXACT, "SubEvent", "Begin");
                filter_new_condition(blindxferfilter, MATCH_EXACT, "UniqueID", message_get_header(msg, "TargetUniqueid"));
                filter_set_userdata(blindxferfilter, (void*) info);
                filter_register_oneshot(blindxferfilter);
            }
        }

        if (!isaac_strcmp(message_get_header(msg, "TransferType"), "Builtin")) {
            if (!isaac_strcmp(message_get_header(msg, "SubEvent"), "Begin")) {
                isaac_strcpy(info->xfer_agent, message_get_header(msg, "TransferExten"));
                info->xfer_state = 6;

                // We get the Attender transfer type from masquearde Event
                filter_t *builtinxferfilter = filter_create(sess, FILTER_SYNC_CALLBACK, status_builtinxfer);
                filter_new_condition(builtinxferfilter, MATCH_EXACT, "Event", "VarSet");
                filter_new_condition(builtinxferfilter, MATCH_EXACT, "Variable", "TRANSFERERNAME");
                filter_new_condition(builtinxferfilter, MATCH_EXACT, "Value", info->agent_channel);
                filter_set_userdata(builtinxferfilter, (void*) info);
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
                    isaac_log(LOG_NOTICE, "[Session %s] Detected Builtin Transfer to %s\n", filter->sess->id, info->xfer_agent);
                    status_inject_queue_call(filter);
                } else {
                    // Oh, transfering to someone not logged in
                    isaac_log(LOG_WARNING, "[Session %s] Ignoring transfer injection to %s. It does not have any Isaac sessions Up.\n",
                        interface);
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

    // Register a Filter for notifying this call
    filter_t *callfilter = filter_create(filter->sess, FILTER_SYNC_CALLBACK, status_print);
    filter_new_condition(callfilter, MATCH_REGEX, "Event", "Newstate|Hangup|IsaacTransfer");
    filter_new_condition(callfilter, MATCH_EXACT, "Channel", info->agent_channel);
    filter_set_userdata(callfilter, (void*) info);
    filter_register(callfilter);

    return 0;
}

/**
 * @brief Get Incoming call UniqueID from __ISAAC_MONITOR variable
 *
 */
int
status_incoming_uniqueid(filter_t *filter, ami_message_t *msg) {
    char value[100]; 
    char plat[120], clidnum[20], uniqueid[20], channel[80];
    const char *agent = session_get_variable(filter->sess, "AGENT");

    // Copy __ISAAC_MONITOR value
    isaac_strcpy(value, message_get_header(msg, "Value"));

    if(sscanf(value, "\"%[^!]!%[^!]!%[^!]!%[^!\"]\"", plat, clidnum, channel, uniqueid)) {

        // Already showing this call
        //if (status_showing_uniqueid(filter->sess, uniqueid)) {
        //    isaac_log(LOG_WARNING, "[Session %s] Already showing information for uniqueid %s\n", 
        //        filter->sess->id, uniqueid);
        //    return 0;
        //} 

        // FIXME FIXME FIXME (Ignore internal queue calls)
        if (strlen(clidnum) == strlen(agent) || !strncasecmp(channel, "Local/", 6))
            return 0;
        
        isaac_log(LOG_NOTICE, "[Session %s] Detected ISAAC_MONITOR on channel %s: %s\n",
            filter->sess->id,
            message_get_header(msg, "Channel"),
            message_get_header(msg, "Value"));

        // Initialize application info
        struct app_status_info *info = malloc(sizeof(struct app_status_info));
        isaac_strcpy(info->plat, plat);
        isaac_strcpy(info->clidnum, clidnum);
        isaac_strcpy(info->channel, channel);
        isaac_strcpy(info->uniqueid, uniqueid);
        info->answered = false;

        filter_t *channelfilter = filter_create(filter->sess, FILTER_SYNC_CALLBACK, status_call);
        filter_new_condition(channelfilter, MATCH_EXACT , "Event", "Dial");
        filter_new_condition(channelfilter, MATCH_EXACT , "SubEvent", "Begin");
        filter_new_condition(channelfilter, MATCH_EXACT, "Channel", message_get_header(msg, "Channel"));
        filter_set_userdata(channelfilter, (void*) info);
        filter_register_oneshot(channelfilter);
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
    filter_t *channelfilter = filter_create(sess, FILTER_SYNC_CALLBACK, status_incoming_uniqueid);
    filter_new_condition(channelfilter, MATCH_EXACT , "Event", "VarSet");
    filter_new_condition(channelfilter, MATCH_EXACT , "Variable", "__ISAAC_MONITOR");
    filter_new_condition(channelfilter, MATCH_REGEX, "Channel", "Local/%s@agentes", agent, interface);
    filter_register(channelfilter);

    // Check with uniqueid mode
    if (args) {
        if (strstr(args, "DEBUG")) {
            session_set_variable(sess, "STATUSDEBUG", "1");
        }

        if (strstr(args, "WUID")) {
            session_set_variable(sess, "STATUSWUID", "1");        
            session_write(sess, "STATUSOK Agent %s status will be printed (With UniqueID info).\r\n", agent);
        } else {
            session_write(sess, "STATUSOK Agent %s status will be printed.\r\n", agent);
        }
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

    if ((channame = find_channel_by_uniqueid(sess, uniqueid))) {
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

    if ((channame = find_channel_by_uniqueid(sess, uniqueid))) {
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

    if ((channame = find_channel_by_uniqueid(sess, uniqueid))) {
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

    if ((channame = find_channel_by_uniqueid(sess, uniqueid))) {
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
    ret |= application_register("Status", status_exec);
    ret |= application_register("Answer", answer_exec);
    ret |= application_register("HoldUID", holduid_exec);
    ret |= application_register("UnholdUID", unholduid_exec);
    ret |= application_register("HangupUID", hangupuid_exec);
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
    ret |= application_unregister("HoldUID");
    ret |= application_unregister("UnholdUID");
    ret |= application_unregister("HangupUID");
    return ret;
}
