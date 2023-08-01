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
 * @file filter.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source code for funtions defined in filter.h
 *
 */
#include "config.h"
#include "filter.h"
#include "manager.h"
#include "session.h"
#include "log.h"
#include "util.h"

static void
filter_condition_destroy(Condition *cond)
{
    if (cond->type == MATCH_REGEX) {
        regfree(&cond->regex);
    }
    g_free(cond->header);
    g_free(cond->value);
    g_free(cond);
}

Filter *
filter_create_async(Session *sess, Application *app, const gchar *name, FilterFunc callback)
{
    g_return_val_if_fail(sess != NULL, NULL);

    // Allocate memory for a new filter
    Filter *filter = g_malloc0(sizeof(Filter));
    g_return_val_if_fail(filter != NULL, NULL);

    filter->active = TRUE;
    filter->sess = sess;
    filter->app = app;
    filter->name = name;
    filter->conditions = g_ptr_array_new_with_free_func((GDestroyNotify) filter_condition_destroy);
    filter->callback = callback;
    filter->oneshot = 0;

    // Return the allocated filter (or NULL ;p)
    return filter;
}

void
filter_new_condition(Filter *filter, enum ConditionType type, const char *hdr, const char *fmt, ...)
{
    char condva[MAX_CONDLEN];
    va_list ap;

    // Get the message from the format string
    va_start(ap, fmt);
    vsprintf(condva, fmt, ap);
    va_end(ap);

    // Allocate memory for this filter
    Condition *cond = g_malloc0(sizeof(Condition));

    // Compile given values for Regex conditions
    if (type == MATCH_REGEX || type == MATCH_REGEX_NOT) {
        if (regcomp(&cond->regex, condva, REG_EXTENDED | REG_NOSUB)) {
            isaac_log(LOG_WARNING, "Unable to compile regex %s for filter\n", condva);
            return;
        }
    }

    // Copy condition data
    cond->type = type;
    cond->header = g_strdup(hdr);
    cond->value = g_strdup(condva);

    // Add the condition to the array
    g_ptr_array_add(filter->conditions, cond);
}

int
filter_register_oneshot(Filter *filter)
{
    filter->oneshot = 1;
    return filter_register(filter);
}

static gboolean
filter_is_oneshot(Filter *filter)
{
    g_return_val_if_fail(filter != NULL, FALSE);
    return filter->oneshot;
}

void
filter_inactivate(Filter *filter)
{
    g_return_if_fail(filter != NULL);
    filter->active = FALSE;
}

int
filter_register(Filter *filter)
{
    if (session_test_flag(filter->sess, SESS_FLAG_DEBUG)) {
        isaac_log(LOG_DEBUG, "[Session#%s] Registering filter \033[1;32m[%s] %s\033[0m [%p] with %d conditions\n",
                  filter->sess->id,
                  filter->app->name,
                  filter->name,
                  filter,
                  filter->conditions->len);
    }

    // Add filter to session
    filter->sess->filters = g_slist_append(filter->sess->filters, filter);
    return 0;
}

void
filter_destroy(Filter *filter)
{
    g_return_if_fail(filter != NULL);

    // Some debug info
    if (session_test_flag(filter->sess, SESS_FLAG_DEBUG)) {
        isaac_log(LOG_DEBUG, "[Session#%s] Destroying filter \033[1;31m[%s] %s\033[0m [%p]\n",
                  filter->sess->id,
                  filter->app->name,
                  filter->name,
                  filter
        );
    }

    // Remove filter from session
    filter->sess->filters = g_slist_remove(filter->sess->filters, filter);

    // Free info data, call destroy notify if required
    if (filter->destroy_func) {
        g_rc_box_release_full(filter->app_info, filter->destroy_func);
    }

    // Deallocate filter memory
    g_ptr_array_free(filter->conditions, TRUE);
    g_free(filter);
}

int
filter_exec_async(Filter *filter, AmiMessage *msg)
{
    int ret = 1;

    // Invoke callback right now!
    if (filter->callback) {
        if (session_test_flag(filter->sess, SESS_FLAG_DEBUG)) {
            gboolean oneshot = filter_is_oneshot(filter);
            g_autofree gchar *text = message_to_text(msg);
            isaac_log(LOG_DEBUG,
                      "[Session#%s] Executing filter \033[1;33m[%s] %s\033[0m [%p] %s triggered by message [%p]\n%s\n",
                      filter->sess->id,
                      filter->app->name,
                      filter->name,
                      filter,
                      (oneshot) ? "(oneshot)" : "",
                      msg,
                      text);
        }
        ret = filter->callback(filter, msg);
    }
    return ret;
}

void
filter_set_userdata(Filter *filter, gpointer user_data)
{
    g_return_if_fail(filter != NULL);
    filter->app_info = user_data;
}

void
filter_set_userdata_full(Filter *filter, gpointer user_data, GDestroyNotify destroy_func)
{
    g_return_if_fail(filter != NULL);
    filter->app_info = g_rc_box_acquire(user_data);
    filter->destroy_func = destroy_func;
}

gpointer
filter_get_userdata(Filter *filter)
{
    g_return_val_if_fail(filter != NULL, NULL);
    return filter->app_info;
}

gpointer
filter_from_userdata(Session *sess, void *userdata)
{
    g_return_val_if_fail(sess != NULL, NULL);
    g_return_val_if_fail(userdata != NULL, NULL);

    for (GSList *l = sess->filters; l; l = l->next) {
        Filter *filter = l->data;
        if (filter_get_userdata(filter) == userdata) {
            return filter;
        }
    }

    return NULL;
}

void
filter_inject_message(Filter *filter, AmiMessage *msg)
{
    Session *sess;
    const char *agent = session_get_variable(filter->sess, "AGENT");

    GSList *sessions = sessions_adquire_lock();
    for (GSList *l = sessions; l; l = l->next) {
        sess = l->data;
        const char *session_agent = session_get_variable(sess, "AGENT");
        if (session_agent && !strcasecmp(session_agent, agent)) {
            if (session_id(sess) < session_id(filter->sess)) {
                break;
            }
        }
    }
    sessions_release_lock();

    // FIXME Create a ref counted AMI message
    AmiMessage *message = manager_create_message();
    message->hdrcount = msg->hdrcount;
    message->in_command = msg->in_command;
    memcpy(message->headers, msg->headers, sizeof(msg->headers));

    // Show some log
    isaac_log(LOG_NOTICE, "[Session#%s] Injecting fake %s message\n", filter->sess->id,
              message_get_header(msg, "Event"));
    isaac_log(LOG_DEBUG, "[Session#%s] Injecting fake %s message: %s\n", filter->sess->id,
              message_get_header(msg, "Event"), message_to_text(msg));

    // Add this message to all session queues
    sessions_enqueue_message(message);

    // Remove initial reference
    g_atomic_rc_box_release_full(message, (GDestroyNotify) mamanger_unref_message);
}

gboolean
filter_check_message(Filter *filter, AmiMessage *msg)
{
    // Initialize the matching headers count
    gint matches = 0;

    // Loop through all filter conditions
    for (gint i = 0; i < filter->conditions->len; i++) {
        Condition *cond = g_ptr_array_index(filter->conditions, i);
        const gchar *msgvalue = message_get_header(msg, cond->header);
        gchar *condvalue = cond->value;

        // Depending on condition type, do the proper check
        switch (cond->type) {
            case MATCH_EXACT:
                if (!isaac_strcmp(msgvalue, condvalue)) {
                    matches++;
                }
                break;
            case MATCH_EXACT_CASE:
                if (!isaac_strcasecmp(msgvalue, condvalue)) {
                    matches++;
                }
                break;
            case MATCH_START_WITH:
                if (!isaac_strncmp(msgvalue, condvalue, strlen(condvalue) - 1)) {
                    matches++;
                }
                break;
            case MATCH_REGEX:
                if (!regexec(&cond->regex, msgvalue, 0, NULL, 0)) {
                    matches++;
                }
                break;
            case MATCH_REGEX_NOT:
                if (regexec(&cond->regex, msgvalue, 0, NULL, 0)) {
                    matches++;
                }
                break;
            default:
                break;
        }

        // If at this point, matches equals the loop counter, the last condition
        // has not matched. No sense to continue checking.
        if (matches == i) break;
    }

    // All condition matched! We have a winner!
    return matches == filter->conditions->len;
}

gboolean
filter_check_and_exec(Filter *filter, AmiMessage *msg)
{
    if (!filter->active) {
        filter_destroy(filter);
        return TRUE;
    }

    if (filter_check_message(filter, msg)) {
        // Exec the filter callback with the current message
        filter_exec_async(filter, msg);

        // If the filter is marked for only triggering once, unregister it
        if (filter_is_oneshot(filter)) {
            filter_destroy(filter);
        }
    }

    return TRUE;
}