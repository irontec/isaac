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
    //! Attended transfer State (See Asterisk Call states)
    int  xfer_state;
    //! Agent to which this call is being transfered
    char xfer_agent[20];
};

/**
 * @brief Callback for blind transfer
 *
 * When the agents transfer its call using an blind transfer, this callback
 * will be executed. This function will create a FAKE AMI message for the agent
 * that is receiving the transfered call.
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
int
status_blindxfer(filter_t *filter, ami_message_t *msg){
    struct app_status_info *info = (struct app_status_info *) filter_get_userdata(filter);

    // Construct a Request message (fake Dial)
    ami_message_t usermsg;
    memset(&usermsg, 0, sizeof(ami_message_t));
    message_add_header(&usermsg, "Event: Dial");
    message_add_header(&usermsg, "SubEvent: Begin");
    message_add_header(&usermsg, "Channel: Local/%s@agentes", info->xfer_agent);
    message_add_header(&usermsg, "Destination: %s", message_get_header(msg, "Destination"));
    message_add_header(&usermsg, "CallerIDName: %s", info->plat);
    message_add_header(&usermsg, "CallerIDNum: %s", info->clidnum);
    check_filters_for_message(&usermsg);
    return 0;
}

/**
 * @brief Callback for attended transfer
 *
 * When the agents transfer its call using an attended transfer, this callback
 * will be executed. We can get the original call status (Attended or Semi-Attended)
 * and the target agent. This function will generate FAKE AMI messages for the agent
 * who is receiving the transfered call.
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
int
status_attxfer(filter_t *filter, ami_message_t *msg)
{
    session_t *sess;
    char interface[80] = "\0", destiny[80] = "\0", match[80];
    char varvalue[MAX_LEN];
    struct app_status_info *info = (struct app_status_info *) filter_get_userdata(filter);
    const char *event = message_get_header(msg, "Event");

    if (!isaac_strcmp(event, "Masquerade")) {
        // Store actual session
        sess = filter->sess;

        // Masquerade Event, get the Destiny channel status from here
        if (!isaac_strcmp(message_get_header(msg, "OriginalState"), "Ring")) {
            info->xfer_state = 5;
        } else if (!isaac_strcmp(message_get_header(msg, "OriginalState"), "Up")) {
            info->xfer_state = 6;
        } else {
            info->xfer_state = 0;
        }

        // We get the Destiny channel from SIP Messages
        filter_t *attfilter = filter_create(filter->sess, FILTER_SYNC_CALLBACK, status_attxfer);
        filter_new_condition(attfilter, MATCH_EXACT, "Event", "VarSet");
        filter_new_condition(attfilter, MATCH_REGEX, "Variable", "~HASH~SIP_CAUSE~.*|BRIDGEPEER");
        filter_new_condition(attfilter, MATCH_EXACT, "Channel", message_get_header(msg, "Clone"));
        filter_set_userdata(attfilter, (void*) info);
        filter_register_oneshot(attfilter);

    } else if (!isaac_strcmp(event, "VarSet")) {

        if (!isaac_strcmp(message_get_header(msg, "Variable"), "BRIDGEPEER")){
            isaac_strcpy(destiny, message_get_header(msg, "Value"));
            isaac_strcpy(varvalue, message_get_header(msg, "Value"));
            if (sscanf(varvalue, "%[^-]", match)) {
                isaac_strcpy(interface, match);
            }

        } else {
            // VarSet, get Destiny channel name from here
            isaac_strcpy(varvalue, message_get_header(msg, "Variable"));
            if (sscanf(varvalue, "~HASH~SIP_CAUSE~%[^~]", match)) {
                isaac_strcpy(destiny, match);
            }
            // VarSet, get Destiny interface from here
            isaac_strcpy(varvalue, message_get_header(msg, "Variable"));
            if (sscanf(varvalue, "~HASH~SIP_CAUSE~%[^-]", match)) {
                isaac_strcpy(interface, match);
            }
        }

        isaac_log(LOG_NOTICE, "%s@%s\n", destiny, interface);

        // Check if we have everything we need
        if (isaac_strlen_zero(interface) || isaac_strlen_zero(destiny)) {
            isaac_log(LOG_ERROR, "Failed to get Attxfer destination\n");
            return -1;
        }

        // Ok we have the interface, check if there is an agent with that interface
        // in a active session
        if ((sess = session_by_variable("INTERFACE", interface))) {
            // Construct a Request message (fake Dial)
            ami_message_t usermsg;
            memset(&usermsg, 0, sizeof(ami_message_t));
            message_add_header(&usermsg, "Event: Dial");
            message_add_header(&usermsg, "SubEvent: Begin");
            message_add_header(&usermsg, "Channel: Local/%s@agentes", session_get_variable(sess,
                    "AGENT"));
            message_add_header(&usermsg, "Destination: %s", destiny);
            message_add_header(&usermsg, "CallerIDName: %s", info->plat);
            message_add_header(&usermsg, "CallerIDNum: %s", info->clidnum);
            // Pass the readed msg to the H&C logic
            check_filters_for_message(&usermsg);

            // Construct NewState fake messages
            if (info->xfer_state >= 5) {
                memset(&usermsg, 0, sizeof(ami_message_t));
                message_add_header(&usermsg, "Event: Newstate");
                message_add_header(&usermsg, "Channel: %s", destiny);
                message_add_header(&usermsg, "ChannelState: 5");
                check_filters_for_message(&usermsg);
            }
            if (info->xfer_state >= 6) {
                memset(&usermsg, 0, sizeof(ami_message_t));
                message_add_header(&usermsg, "Event: Newstate");
                message_add_header(&usermsg, "Channel: %s", destiny);
                message_add_header(&usermsg, "ChannelState: 6");
                check_filters_for_message(&usermsg);
            }
        }
    }
    return 0;
}


/**
 * @brief Agent's Call state changes filter callback.
 *
 * When the agents's call leg status changes, this callback will be triggered.
 * It will also check if the remote call is being transfered to another agent
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
    char statusevent[256];

    // Initialize response string
    memset(statusevent, 0, sizeof(statusevent));

    // CallStatus response
    if (!isaac_strcmp(event, "Newstate") || !isaac_strcmp(event, "UserEvent") ||
        !isaac_strcmp(event, "Hangup") || !isaac_strcmp(event, "Transfer")) {
        sprintf(statusevent, "EXTERNALCALLSTATUS ");
        if (session_get_variable(sess, "STATUSWUID")) 
            sprintf(statusevent + strlen(statusevent), "%s ", info->uniqueid);
        sprintf(statusevent + strlen(statusevent), "%s ", info->plat);
        sprintf(statusevent + strlen(statusevent), "%s ", info->clidnum);
    }

    // Send ExternalCallStatus message depending on received event
    if (!isaac_strcmp(event, "Newstate") || !isaac_strcmp(event, "UserEvent")) {
        // Print status message depending on Channel Status
        if (!isaac_strcmp(message_get_header(msg, "ChannelState"), "5")) {
            sprintf(statusevent + strlen(statusevent), "RINGING\r\n");
        } else if (!isaac_strcmp(message_get_header(msg, "ChannelState"), "6")) {
            sprintf(statusevent + strlen(statusevent), "ANSWERED\r\n");
        }
    } else if (!isaac_strcmp(event, "Hangup")) {
        // Queue call has finished for this agent
        sprintf(statusevent + strlen(statusevent), "HANGUP\r\n");
        // We dont expect more info about this filter, it's safe to unregister it here
        filter_unregister(filter);
    } else if (!isaac_strcmp(event, "Transfer")) {
        // Queue call has been transfered
        sprintf(statusevent + strlen(statusevent), "TRANSFERED\r\n");
        if (!isaac_strcmp(message_get_header(msg, "TransferType"), "Attended")) {
            // At this point, we know the agent is transfering the call to another agent
            // But we still dont have the target channel nor even the transfer state (Att, SemiAtt..)

            // We get the Attender transfer type from masquearde Event
            filter_t *attstatefilter = filter_create(sess, FILTER_SYNC_CALLBACK, status_attxfer);
            filter_new_condition(attstatefilter, MATCH_EXACT, "Event", "Masquerade");
            filter_new_condition(attstatefilter, MATCH_EXACT, "Original", message_get_header(msg,
                    "TargetChannel"));
            filter_set_userdata(attstatefilter, (void*) info);
            filter_register_oneshot(attstatefilter);

        } else if (!isaac_strcmp(message_get_header(msg, "TransferType"), "Blind")) {
            // Copy the destiny agent
            isaac_strcpy(info->xfer_agent, message_get_header(msg, "TransferExten"));

            // We get the Attender transfer type from masquearde Event
            filter_t *blindxferfilter = filter_create(sess, FILTER_SYNC_CALLBACK, status_blindxfer);
            filter_new_condition(blindxferfilter, MATCH_EXACT, "Event", "Dial");
            filter_new_condition(blindxferfilter, MATCH_EXACT, "SubEvent", "Begin");
            filter_new_condition(blindxferfilter, MATCH_EXACT, "UniqueID", message_get_header(msg, "TargetUniqueid"));
            filter_set_userdata(blindxferfilter, (void*) info);
            filter_register_oneshot(blindxferfilter);
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
    const char *dest = message_get_header(msg, "Destination");

    // Register a Filter for notifying this call
    filter_t *callfilter = filter_create(filter->sess, FILTER_SYNC_CALLBACK, status_print);
    filter_new_condition(callfilter, MATCH_REGEX, "Event", "Newstate|Hangup|Transfer");
    filter_new_condition(callfilter, MATCH_EXACT, "Channel", dest);
    filter_set_userdata(callfilter, (void*) info);
    filter_register(callfilter);

    return 0;
}

/**
 * @brief Get Incoming call UniqueID from __TOUCH_MONITOR variable
 *
 */
int
status_incoming_uniqueid(filter_t *filter, ami_message_t *msg) {
    char value[100]; 
    char plat[120], clidnum[20], agent[20], uniqueid[20];

    // Copy __TOUCH_MONITOR value
    isaac_strcpy(value, message_get_header(msg, "Value"));

    if(sscanf(value, "\"%[^-]-%[^-]-%[^-]-%[^-\"]\"", plat, clidnum, agent, uniqueid)) {
        // Initialize application info
        struct app_status_info *info = malloc(sizeof(struct app_status_info));
        isaac_strcpy(info->plat, plat);
        isaac_strcpy(info->clidnum, clidnum);
        isaac_strcpy(info->uniqueid, uniqueid);

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
    filter_new_condition(channelfilter, MATCH_EXACT , "Variable", "__TOUCH_MONITOR");
    filter_new_condition(channelfilter, MATCH_START_WITH, "Channel", "Local/%s@agentes", agent, interface);
    filter_register(channelfilter);

    // Check with uniqueid mode
    if (args && !strncasecmp(args, "WUID", 4)) {
        session_set_variable(sess, "STATUSWUID", "1");        
        session_write(sess, "STATUSOK Agent %s status will be printed (With UniqueID info).\r\n", agent);
    } else {
        session_write(sess, "STATUSOK Agent %s status will be printed.\r\n", agent);
    }


    session_set_variable(sess, "APPSTATUS", "1");

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
    return application_register("Status", status_exec);
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
    return application_unregister("Status");
}
