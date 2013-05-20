#include <stdlib.h>
#include "app.h"
#include "session.h"
#include "manager.h"
#include "filter.h"
#include "util.h"
#include "log.h"

struct app_status_info
{
    char plat[20];
    char clidnum[20];
};

int
status_print(filter_t *filter, ami_message_t *msg)
{
    struct app_status_info *info = (struct app_status_info *) filter_get_userdata(filter);
    const char *event = message_get_header(msg, "Event");

    // Send ExternalCallStatus message depending on received event
    if (!strcasecmp(event, "NewState")) {
        // Print status message depending on Channel Status
        const char *state = message_get_header(msg, "ChannelState");
        if (!strcasecmp(state, "5")) {
            session_write(filter->sess, "EXTERNALCALLSTATUS %s %s RINGING\n", info->plat,
                    info->clidnum);
        } else if (!strcasecmp(state, "6")) {
            session_write(filter->sess, "EXTERNALCALLSTATUS %s %s ANSWERED\n", info->plat,
                    info->clidnum);
         }
    } else if (!strcasecmp(event, "Hangup")) {
        // We dont expect more info about this filter, it's safe to unregister it here
        session_write(filter->sess, "EXTERNALCALLSTATUS %s %s HANGUP\n", info->plat,
                info->clidnum);
        isaac_free(info);
        filter_unregister(filter);
    }
}

int
status_call(filter_t *filter, ami_message_t *msg)
{
    // Get the interesting channel name, we will fetch the rest of the messages
    // that match that ID
    const char *dest = message_get_header(msg, "Destination");

    // Initialize application info
    struct app_status_info *info = malloc(sizeof(struct app_status_info));
    isaac_strcpy(info->plat, message_get_header(msg, "CallerIDName"));
    isaac_strcpy(info->clidnum, message_get_header(msg, "CallerIDNum"));

    // Register a Filter for notifying this call
    filter_t *callfilter = filter_create(filter->sess, FILTER_SYNC_CALLBACK, status_print);
    filter_add_condition2(callfilter, MATCH_EXACT, "Channel", dest);
    filter_set_userdata(callfilter, (void*) info);
    filter_register(callfilter);
}

int
status_exec(session_t *sess, const char *args)
{
    char channame[20];
    const char *agent = session_get_variable(sess, "AGENT");

    // Check we are logged in.
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Check we havent run this application before
    if (session_get_variable(sess, "APPSTATUS")) {
        session_write(sess, "STATUSOK Already showing status for this agent.\n");
        return 0;
    }

    // Build the channel name we will be searching
    sprintf(channame, "Local/%s@agentes", agent);

    // Register a Filter to get All generated channels for
    filter_t *channelfilter = filter_create(sess, FILTER_SYNC_CALLBACK, status_call);
    filter_add_condition2(channelfilter, MATCH_EXACT, "Event", "Dial");
    filter_add_condition2(channelfilter, MATCH_EXACT, "SubEvent", "Begin");
    filter_add_condition2(channelfilter, MATCH_START_WITH, "Channel", channame);
    filter_register(channelfilter);
    session_write(sess, "STATUSOK Agent %s status will be printed.\n", agent);

    session_set_variable(sess, "APPSTATUS", "1");

    return 0;
}

int
load_module()
{
    return application_register("Status", status_exec);
}

int
unload_module()
{
    return application_unregister("Status");
}
