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
 * CONFERENCECONF file (usually /etc/isaac/conference.conf) and defining the
 * desired contexts in asterisk.
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

#define CONFERENCECONF CONFDIR "/conference.conf"

/**
 * @brief Module configuration read from CONFERENCECONF file
 *
 * @see read_conference_config
 */
struct app_conference_config
{
    //! Context to originate the first host leg during CONFERENCE action
    char host_incontext[80];
    //! Context to originate the second host leg during CONFERENCE action
    char host_outcontext[80];
    //! Context to originate the first guest leg during CONFERENCE action
    char guest_incontext[80];
    //! Context to originate the second guest leg during CONFERENCE action
    char guest_outcontext[80];

    //! Autoanswer flag. Does not work in all terminals.
    int autoanswer;
} conference_config;

struct app_conference_guest
{
    //! Guest Channel extension
    char extension[20];
    //! Guest Channel UniqueID
    char uid[50];
    //! Guest action id
    char actionid[128];
};

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
    //! Conference ID for meetme
    const char *conference_id;
    //! List of extensions to invite to conference
    struct app_conference_guest guests[20];
    //! Numbers of extensions to invite
    int guestcnt;
    //! Flag for creating a broadcast conference
    int mute;
    //! Host Channel UniqueID
    char host_uid[50];
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
    if (config_lookup_string(&cfg, "originate.host_incontext", &value) == CONFIG_TRUE) {
        strcpy(conference_config.host_incontext, value);
    }
    // Outgoing context for second call leg in Originate @see call_exec
    if (config_lookup_string(&cfg, "originate.host_outcontext", &value) == CONFIG_TRUE) {
        strcpy(conference_config.host_outcontext, value);
    }

    // Incoming context for first call leg in Originate @see call_exec
    if (config_lookup_string(&cfg, "originate.guest_incontext", &value) == CONFIG_TRUE) {
        strcpy(conference_config.guest_incontext, value);
    }
    // Outgoing context for second call leg in Originate @see call_exec
    if (config_lookup_string(&cfg, "originate.guest_outcontext", &value) == CONFIG_TRUE) {
        strcpy(conference_config.guest_outcontext, value);
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
 * @brief Get Conference Guest Info structure of a given actionid
 *
 * @param sess Session Structure
 * @param actionid ID generated from conference actionid for a given guest
 * @return Conference guest info structure pointer
 */
static struct app_conference_guest *
conference_guest_from_actionid(struct app_conference_info *info, const char *actionid)
{
    int i;
    for (i = 0; i < info->guestcnt; i++) {
        if (strcmp(info->guests[i].actionid, actionid) == 0) {
            return &info->guests[i];
        }
    }

    return NULL;
}

/**
 * @brief Get Conference Guest Info structure of a given unique id
 *
 * @param sess Session Structure
 * @param uid Asterisk UniqueID for guest call
 * @return Conference guest info structure pointer
 */
static struct app_conference_guest *
conference_guest_rom_uid(struct app_conference_info *info, const char *uid)
{
    int i;
    for (i = 0; i < info->guestcnt; i++) {
        if (strcmp(info->guests[i].uid, uid) == 0) {
            return &info->guests[i];
        }
    }

    return NULL;
}

/**
 * Print conference Guest status changes
 *
 * @param filter Triggering filter structure
 * @param msg AMI message that matched the filter conditions
 * @return 0 in all cases
 */
static int
conference_guest_state(Filter *filter, AmiMessage *msg)
{
    // Get conference information (stored in filter)
    struct app_conference_info *info = (struct app_conference_info *) filter_get_userdata(filter);

    // Get Guest information from message UniqueID
    struct app_conference_guest *guest = conference_guest_rom_uid(info, message_get_header(msg, "UniqueID"));

    // Get message event
    const char *event = message_get_header(msg, "Event");

    if (!strcasecmp(event, "VarSet")) {
        const char *varname = message_get_header(msg, "Variable");

        // A channel has set ACTIONID var, this is our leg1 channel. It will Dial soon!
        if (!strcasecmp(varname, "ACTIONID")) {

            struct app_conference_guest *guest = conference_guest_from_actionid(info, message_get_header(msg, "Value"));

            // Get the UniqueId from the agent channel
            isaac_strcpy(guest->uid, message_get_header(msg, "UniqueID"));

            // Register a Filter for the agent status the custom manager application PlayDTMF.
            Filter *guest_filter = filter_create_async(filter->sess, conference_guest_state);
            filter_new_condition(guest_filter, MATCH_REGEX, "Event", "Hangup|MeetmeJoin|MeetmeLeave");
            filter_new_condition(guest_filter, MATCH_REGEX, "UniqueID", guest->uid);
            filter_set_userdata(guest_filter, (void *) info);
            filter_register(guest_filter);

            session_write(filter->sess,
                          "CONFERENCESTATUS %s %s STARTING\n",
                          info->actionid,
                          guest->extension
            );
        }
    } else if (!strcasecmp(event, "Hangup")) {
        session_write(filter->sess,
                      "CONFERENCESTATUS %s %s ERROR %s\n",
                      info->actionid,
                      guest->extension,
                      message_get_header(msg, "Cause")
        );

        // This is the last interesting message for this guest
        filter_destroy(filter);
    } else if (!strcasecmp(event, "MeetmeJoin")) {
        session_write(filter->sess,
                      "CONFERENCESTATUS %s %s JOINED\n",
                      info->actionid,
                      guest->extension
        );
    } else if (!strcasecmp(event, "MeetmeLeave")) {
        session_write(filter->sess,
                      "CONFERENCESTATUS %s %s LEFT\n",
                      info->actionid,
                      guest->extension
        );

        // This is the last interesting message for this guest
        filter_destroy(filter);
    }

    return 0;
}

/**
 * Send an Originate request to one Conference guest
 *
 * @param sess Session running Conference application
 * @param info Conference information pointer
 * @param guest Conference Guest information
 * @return 0 in all cases
 */
static int
conference_guest_invite(Session *sess, struct app_conference_info *info, struct app_conference_guest *guest)
{
    // Register a Filter to get Generated Channel
    Filter *channel_filter = filter_create_async(sess, conference_guest_state);
    filter_new_condition(channel_filter, MATCH_EXACT, "Event", "VarSet");
    filter_new_condition(channel_filter, MATCH_EXACT, "Variable", "ACTIONID");
    filter_new_condition(channel_filter, MATCH_EXACT, "Value", "%s", guest->actionid);
    filter_set_userdata(channel_filter, (void *) info);
    filter_register_oneshot(channel_filter);

    // Construct a Request message
    AmiMessage msg;
    memset(&msg, 0, sizeof(AmiMessage));
    message_add_header(&msg, "Action: Originate");
    message_add_header(&msg, "CallerID: %s", guest->extension);
    message_add_header(&msg, "Channel: Local/%s@%s", guest->extension, conference_config.guest_incontext);
    message_add_header(&msg, "Context: %s", conference_config.guest_outcontext);
    message_add_header(&msg, "Priority: 1");
    message_add_header(&msg, "ActionID: %s", guest->actionid);
    message_add_header(&msg, "Exten: %s", guest->extension);
    message_add_header(&msg, "Async: 1");
    message_add_header(&msg, "Variable: ACTIONID=%s", guest->actionid);
    message_add_header(&msg, "Variable: AUTOANSWER=%d", conference_config.autoanswer);
    message_add_header(&msg, "Variable: CONFERENCE_MUTE=%d", info->mute);
    message_add_header(&msg, "Variable: CONFERENCE_ID=%s", info->conference_id);

    // Send this message to ami
    manager_write_message(manager, &msg);

    return 0;
}

/**
 * @brief Handles Host Conference Status
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
int
conference_host_state(Filter *filter, AmiMessage *msg)
{
    int i;
    struct app_conference_info *info = (struct app_conference_info *) filter_get_userdata(filter);
    const char *event = message_get_header(msg, "Event");

    if (!strcasecmp(event, "VarSet")) {
        const char *varname = message_get_header(msg, "Variable");

        // A channel has set ACTIONID var, this is our leg1 channel. It will Dial soon!
        if (!strcasecmp(varname, "ACTIONID")) {
            // Get the UniqueId from the agent channel
            isaac_strcpy(info->host_uid, message_get_header(msg, "UniqueID"));

            // Register a Filter for the agent status the custom manager application PlayDTMF.
            Filter *host_filter = filter_create_async(filter->sess, conference_host_state);
            filter_new_condition(host_filter, MATCH_REGEX, "Event", "Hangup|MeetmeJoin");
            filter_new_condition(host_filter, MATCH_REGEX, "UniqueID", info->host_uid);
            filter_set_userdata(host_filter, (void *) info);
            filter_register_oneshot(host_filter);

            Filter *conference_end_filter = filter_create_async(filter->sess, conference_host_state);
            filter_new_condition(conference_end_filter, MATCH_EXACT, "Event", "MeetmeEnd");
            filter_new_condition(conference_end_filter, MATCH_EXACT, "Meetme", info->conference_id);
            filter_set_userdata(conference_end_filter, (void *) info);
            filter_register_oneshot(conference_end_filter);
        }
    } else if (!strcasecmp(event, "Hangup")) {
        session_write(filter->sess,
                      "CONFERENCEERROR %s HANGUP %s\n",
                      info->actionid,
                      message_get_header(msg, "Cause")
        );
    } else if (!strcasecmp(event, "MeetmeJoin")) {
        session_write(filter->sess,
                      "CONFERENCEOK %s CONFERENCE CREATED \n",
                      info->actionid
        );

        for (i = 0; i < info->guestcnt; i++) {
            conference_guest_invite(filter->sess, info, &info->guests[i]);
        }
    } else if (!strcasecmp(event, "MeetmeEnd")) {
        session_write(filter->sess,
                      "CONFERENCESTATUS %s CONFERENCE ENDED\n",
                      info->actionid
        );
    }

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
 * @param argstr Call action argstr "ActionID DestNum"
 * @return 0 in call cases
 */
int
conference_exec(Session *sess, Application *app, const char *argstr)
{
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Command length
    size_t clen = strlen(argstr);

    // Allocate memory for read input
    char *actionid = malloc(clen);
    char *extensions = malloc(clen);
    char *options = malloc(clen);

    // Get Call parameters
    if (sscanf(argstr, "%s %s %[^\n]", actionid, extensions, options) < 2) {
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
        strcpy(info->guests[info->guestcnt].extension, exten);
        sprintf(info->guests[info->guestcnt].actionid, "%s#%s#", actionid, exten);
        info->guestcnt++;
        exten = strtok_r(NULL, ",", &saveptr);
    }

    // Validate we have at least one extension
    if (info->guestcnt == 0) {
        free(actionid);
        free(extensions);
        free(options);
        free(info);
        return INVALID_ARGUMENTS;
    }

    // Check if uniqueid info is requested
    GSList *parsed = application_parse_args(options);

    if (application_arg_exists(parsed, "MUTE")) {
        info->mute = 1;
    }

    // Register a Filter to get Generated Channel
    Filter *channel_filter = filter_create_async(sess, conference_host_state);
    filter_new_condition(channel_filter, MATCH_EXACT, "Event", "VarSet");
    filter_new_condition(channel_filter, MATCH_EXACT, "Variable", "ACTIONID");
    filter_new_condition(channel_filter, MATCH_EXACT, "Value", actionid);
    filter_set_userdata(channel_filter, (void *) info);
    filter_register_oneshot(channel_filter);

    // Get the logged agent
    const char *agent = info->conference_id = session_get_variable(sess, "AGENT");

    // Construct a Request message
    AmiMessage msg;
    memset(&msg, 0, sizeof(AmiMessage));
    message_add_header(&msg, "Action: Originate");
    message_add_header(&msg, "CallerID: %s", agent);
    message_add_header(&msg, "Channel: Local/%s@%s", agent, conference_config.host_incontext);
    message_add_header(&msg, "Context: %s", conference_config.host_outcontext);
    message_add_header(&msg, "Priority: 1");
    message_add_header(&msg, "ActionID: %s", actionid);
    message_add_header(&msg, "Exten: %s", agent);
    message_add_header(&msg, "Async: 1");
    message_add_header(&msg, "Variable: ACTIONID=%s", actionid);
    message_add_header(&msg, "Variable: AUTOANSWER=%d", conference_config.autoanswer);
    message_add_header(&msg, "Variable: CONFERENCE_MUTE=%d", info->mute);
    message_add_header(&msg, "Variable: CONFERENCE_ID=%s", info->conference_id);

    // Send this message to ami
    manager_write_message(manager, &msg);

    // Free parsed app arguments
    application_free_args(parsed);

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
