#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libconfig.h>
#include "app.h"
#include "session.h"
#include "manager.h"
#include "filter.h"
#include "log.h"

struct app_call_config
{
    char incontext[80];
    char outcontext[80];
    char rol[20];
    int autoanswer;
} call_config;

struct app_call_info
{
    char actionid[20];
    filter_t *callfilter;
    filter_t *ofilter;
    char ouid[50];
    char ochannel[50];
    filter_t *dfilter;
    char duid[50];
    char dchannel[50];
};

struct app_call_info *
get_call_info_from_id(session_t *sess, const char *id)
{
    filter_t *filter;
    struct app_call_info *info = NULL;
    // Get session filter and search the one with that id
    while ((filter = get_session_filter(sess))) {
        info = (struct app_call_info *) filter_get_userdata(filter);
        // We found the requested action!
        if (info && !strcasecmp(id, info->actionid)){
            break;
        }
    }
    return info;
}

int
call_state(filter_t *filter, ami_message_t *msg)
{
    struct app_call_info *info = (struct app_call_info *) filter_get_userdata(filter);
    const char *event = message_get_header(msg, "Event");
    const char *from, *to;

    // So this leg is ?
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
        const char *value = message_get_header(msg, "Value");
        if (!strcasecmp(value, "SIP 183 Session Progress")) {
            session_write(filter->sess, "CALLSTATUS %s %s PROGRESS\n", info->actionid, to);
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
        filter_add_condition2(info->dfilter, MATCH_EXACT, "UniqueID", info->duid);
        filter_register(info->dfilter);

        // Say we have the remote channel
        session_write(filter->sess, "CALLSTATUS %s REMOTE STARTING\n", info->actionid);
    }
}

int
call_response(filter_t *filter, ami_message_t *msg)
{
    struct app_call_info *info = (struct app_call_info *) filter_get_userdata(filter);

    // Get the UniqueId from the agent channel
    strcpy(info->ouid, message_get_header(msg, "UniqueID"));

    // Register a Filter for the agent status
    info->ofilter = filter_create(filter->sess, FILTER_SYNC_CALLBACK, call_state);
    filter_add_condition2(info->ofilter, MATCH_EXACT, "UniqueID", info->ouid);
    filter_set_userdata(info->ofilter, (void*) info);
    filter_register(info->ofilter);

    // Tell the client the channel is going on!
    session_write(filter->sess, "CALLSTATUS %s AGENT STARTING\n", info->actionid);

    // Remove this filter, we have the uniqueID
    filter_unregister(info->callfilter);
}

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
    info->callfilter = filter_create(sess, FILTER_SYNC_CALLBACK, call_response);
    filter_add_condition2(info->callfilter, MATCH_EXACT, "Event", "VarSet");
    filter_add_condition2(info->callfilter, MATCH_EXACT, "Variable", "ACTIONID");
    filter_add_condition2(info->callfilter, MATCH_EXACT, "Value", actionid);
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

int
read_call_config(const char *cfile)
{
    config_t cfg;
    // Initialize configuration
    config_init(&cfg);
    const char *value;
    long int intvalue;

    // Read configuraiton file
    if (config_read_file(&cfg, cfile) == CONFIG_FALSE) {
        isaac_log(LOG_ERROR, "Error parsing configuration file %s on line %d: %s\n", cfile,
                config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return -1;
    }

    // Read known configuration options
    if (config_lookup_string(&cfg, "originate.incontext", &value) == CONFIG_TRUE) {
        strcpy(call_config.incontext, value);
    }
    if (config_lookup_string(&cfg, "originate.outcontext", &value) == CONFIG_TRUE) {
        strcpy(call_config.outcontext, value);
    }
    if (config_lookup_string(&cfg, "originate.rol", &value) == CONFIG_TRUE) {
        strcpy(call_config.rol, value);
    }
    if (config_lookup_int(&cfg, "originate.autoanswer", &intvalue) == CONFIG_TRUE) {
        call_config.autoanswer = intvalue;
    }

    return 0;
}

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
    if ((info = get_call_info_from_id(sess, actionid)) && !isaac_strlen_zero(info->dchannel) ){
        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: PlayDTMF");
        message_add_header(&msg, "Channel: %s", info->dchannel);
        message_add_header(&msg, "Digit: %s", digit);
        manager_write_message(manager, &msg);
        session_write(sess, "DTMFOK\n");
    } else {
        session_write(sess, "DTMFFAILED ID NOT FOUND\n");
        return 1;
    }
    return 0;
}

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
    if ((info = get_call_info_from_id(sess, actionid)) && !isaac_strlen_zero(info->ochannel) ){
        ami_message_t msg;
        memset(&msg, 0, sizeof(ami_message_t));
        message_add_header(&msg, "Action: Hangup");
        message_add_header(&msg, "Channel: %s", info->ochannel);
        manager_write_message(manager, &msg);
        session_write(sess, "HANGUPOK\n");
    } else {
        session_write(sess, "HANGUPFAILED ID NOT FOUND\n");
        return 1;
    }
    return 0;
}

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

int
unload_module()
{
    int res = 0;
    res |= application_unregister("Call");
    res |= application_unregister("Hangup");
    res |= application_unregister("Dtmf");
    return res;
}
