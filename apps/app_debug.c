#include <stdio.h>
#include "app.h"
#include "session.h"
#include "manager.h"
#include "filter.h"
#include "log.h"

int debug_message(filter_t *filter, ami_message_t *msg)
{
    session_write(filter->sess, "%s\n", message_to_text(msg));
}

int debug_exec(session_t *sess, const char *args)
{
    // Create a new filter for ALL Messages
    filter_register(filter_create(sess, FILTER_SYNC_CALLBACK, debug_message));

    // Some feedback
    session_write(sess, "DEBUG ENABLED\n");
}

int classic_message(filter_t *filter, ami_message_t *msg)
{
    int i;
    for (i = 0; i < msg->hdrcount; i++) {
        session_write(filter->sess, "%s\r\n", msg->headers[i]);
    }
    session_write(filter->sess, "\r\n");
}

int classic_exec(session_t *sess, const char *args)
{
    // Create a new filter for ALL Messages
    filter_register(filter_create(sess, FILTER_SYNC_CALLBACK, classic_message));

    // Some feedback
    session_write(sess, "CLASSIC MODE ENABLED\n");
}

int load_module()
{
    int res = 0;
    res |= application_register("Debug", debug_exec);
    res |= application_register("Classic", classic_exec);
    return res;
}

int unload_module()
{
    int res = 0;
    res |= application_unregister("Debug");
    res |= application_unregister("Classic");
    return res;
}

