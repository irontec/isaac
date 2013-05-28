#include <stdio.h>
#include "app.h"
#include "session.h"

/* Application List */
extern app_t *apps;
/* Application List Mutex */
extern pthread_mutex_t apps_lock;

int help_exec(session_t *sess, app_t *app, const char *args)
{
    session_write(sess, "Available applications: ");
    pthread_mutex_lock(&apps_lock);
    app_t* cur = apps;
    while (cur) {
        session_write(sess, "%s ", cur->name);
        cur = cur->next;
    }
    session_write(sess, "\n");
    pthread_mutex_unlock(&apps_lock);
    return 0;
}

int load_module()
{
    return application_register("Help", help_exec);
}

int unload_module()
{
    return application_unregister("Help");
}
