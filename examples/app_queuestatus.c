#include <stdio.h>
#include "app.h"
#include "session.h"
#include "manager.h"
#include "filter.h"
#include "log.h"

struct QueueAppInfo
{
    filter_t *paramfilter;
    filter_t *memberfilter;
    filter_t *endfilter;
};

int print_queue_status(filter_t *filter, ami_message_t *msg)
{
    session_write(filter->sess, "QUEUEPARAMS %s %s %s\n",
            message_get_header(msg, "Queue"),
            message_get_header(msg, "Strategy"),
            message_get_header(msg, "Calls"));
}

int print_queue_member(filter_t *filter, ami_message_t *msg)
{
    session_write(filter->sess, "QUEUEMEMBER %s %s %s\n",
            message_get_header(msg, "Queue"),
            message_get_header(msg, "Name"),
            message_get_header(msg, "Paused"));
}

int print_queue_end(filter_t *filter, ami_message_t *msg)
{
    session_write(filter->sess, "QUEUESTATUS END\n");

    struct QueueAppInfo *info = (struct QueueAppInfo *) filter->app_info;
    filter_unregister(info->paramfilter);
    filter_unregister(info->memberfilter);
    filter_unregister(info->endfilter);
}

int queuestatus_exec(session_t *sess, const char *args)
{
    char actionid[ACTIONID_LEN];

    // Generate a random Hash
    srand(time(NULL));
    sprintf(actionid, "%d", rand());

    // Generate a structure to unregister all this filters at once
    struct QueueAppInfo *info = malloc(sizeof(struct QueueAppInfo));

    // Create a new filter for QueueParams
    info->paramfilter = filter_create(sess, FILTER_SYNC_CALLBACK, print_queue_status);
    filter_new_condition(info->paramfilter, MATCH_EXACT, "Event", "QueueParams");
    filter_new_condition(info->paramfilter, MATCH_EXACT, "ActionID", actionid);
    filter_set_userdata(info->paramfilter, (void*)info);
    filter_register(info->paramfilter);

    // Create a new filter for QueueMember
    info->memberfilter = filter_create(sess, FILTER_SYNC_CALLBACK, print_queue_member);
    filter_new_condition(info->memberfilter, MATCH_EXACT, "Event", "QueueMember");
    filter_new_condition(info->memberfilter, MATCH_EXACT, "ActionID", actionid);
    filter_set_userdata(info->memberfilter, (void*)info);
    filter_register(info->memberfilter);

    // Create a new filter for QueueStatusComplete
    info->endfilter = filter_create(sess, FILTER_SYNC_CALLBACK, print_queue_end);
    filter_new_condition(info->endfilter, MATCH_EXACT, "Event", "QueueStatusComplete");
    filter_new_condition(info->endfilter, MATCH_EXACT, "ActionID", actionid);
    filter_set_userdata(info->endfilter, (void*)info);
    filter_register(info->endfilter);

    // Construct a Request message
    ami_message_t msg;
    memset(&msg, 0, sizeof(ami_message_t));
    message_add_header(&msg, "Action: QueueStatus");
    message_add_header(&msg, "ActionID: %s", actionid);
    manager_write_message(get_manager(), &msg);
}

int load_module()
{
    return application_register("QueueStatus", queuestatus_exec);
}

int unload_module()
{
    return application_unregister("QueueStatus");
}
