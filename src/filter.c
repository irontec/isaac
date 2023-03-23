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
#include "session.h"
#include "log.h"
#include "util.h"

Filter *
filter_create_async(Session *sess, int (*callback)(Filter *filter, AmiMessage *msg))
{
    Filter *filter = NULL;
    // Allocate memory for a new filter
    if ((filter = malloc(sizeof(Filter)))) {
        // Initialice basic fields
        memset(filter, 0, sizeof(Filter));
        filter->sess = sess;
        filter->condcount = 0;
        filter->type = FILTER_ASYNC;
        filter->data.async.callback = callback;
        filter->data.async.oneshot = 0;
    }

    // Return the allocated filter (or NULL ;p)
    return filter;
}

Filter *
filter_create_sync(Session *sess)
{
    Filter *filter = NULL;
    // Allocate memory for a new filter
    if ((filter = malloc(sizeof(Filter)))) {
        // Initialize basic fields
        memset(filter, 0, sizeof(Filter));
        filter->sess = sess;
        filter->condcount = 0;
        filter->type = FILTER_SYNC;
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
        pthread_mutex_init(&filter->data.sync.lock, &attr);
    }

    // Return the allocated filter (or NULL ;p)
    return filter;
}

void
filter_set_name(Filter *filter, const gchar *name)
{
    g_return_if_fail(filter != NULL);
    g_return_if_fail(name != NULL);
    filter->name = name;
}

int
filter_new_cooked_condition(Filter *filter, Condition cond)
{
    // Check if we have reached the maximum of conditions
    if (filter->condcount == MAX_CONDS) return 1;
    // Add the condition to the next slot
    filter->conds[filter->condcount] = cond;
    // And increase the conditions counter
    filter->condcount++;
    return 0;
}

int
filter_new_condition(Filter *filter, enum ConditionType type, const char *hdr, const char *fmt, ...)
{
    Condition cond;
    char condva[MAX_CONDLEN];
    va_list ap;

    // Get the message from the format string
    va_start(ap, fmt);
    vsprintf(condva, fmt, ap);
    va_end(ap);

    // Compile given values for Regex conditions
    if (type == MATCH_REGEX || type == MATCH_REGEX_NOT) {
        if (regcomp(&cond.regex, condva, REG_EXTENDED | REG_NOSUB)) {
            isaac_log(LOG_WARNING, "Unable to compile regex %s for filter\n", condva);
            return 1;
        }
    }

    // Copy condition data
    cond.type = type;
    strcpy(cond.hdr, hdr);
    strcpy(cond.val, condva);

    // Actually add the cooked condition to the filter
    return filter_new_cooked_condition(filter, cond);
}

void
filter_remove_conditions(Filter *filter)
{
    filter->condcount = 0;
}

int
filter_register_oneshot(Filter *filter)
{
    if (!filter) return 1;
    if (filter->type == FILTER_ASYNC)
        filter->data.async.oneshot = 1;

    return filter_register(filter);
}

int
filter_register(Filter *filter)
{
    if (session_test_flag(filter->sess, SESS_FLAG_DEBUG)) {
        isaac_log(LOG_DEBUG, "[Session %s] Registering %s filter [%p] with %d conditions\n",
                  filter->sess->id,
                  (filter->type == FILTER_ASYNC) ? "asnyc" : "sync",
                  filter,
                  filter->condcount);
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
        isaac_log(LOG_DEBUG, "[Session %s] Destroying filter [%p]\n", filter->sess->id, filter);
    }

    // Remove filter from session
    filter->sess->filters = g_slist_remove(filter->sess->filters, filter);

    // Check if the info is still being shared by someone
    gpointer user_data = filter_get_userdata(filter);
    gboolean shared = FALSE;
    if (user_data) {
        for (GSList *l = filter->sess->filters; l; l = l->next) {
            Filter *other = l->data;
            if (filter_get_userdata(other) == user_data) {
                shared = TRUE;
            }
        }
        if (!shared) {
            g_free(user_data);
        }
    }

    // Deallocate filter conditions
    for (gint i = 0; i < filter->condcount; i++) {
        if (filter->conds[i].type == MATCH_REGEX) {
            regfree(&filter->conds[i].regex);
        }
    }

    // Deallocate filter memory
    g_free(filter);
}

int
filter_exec_async(Filter *filter, AmiMessage *msg)
{
    int oneshot = filter->data.async.oneshot;
    int ret = 1;
    Session *sess = filter->sess;

    // Check we have a valid filter
    if (!filter || filter->type != FILTER_ASYNC)
        return 1;

    // If the debug is enabled in this session, print a message to
    // connected CLIs. LOG_NONE will not reach any file or syslog.
    if (session_test_flag(sess, SESS_FLAG_DEBUG)) {
        filter_print_message(filter, msg);
    }

    // Invoke callback right now!
    if (filter->data.async.callback) {
        if (session_test_flag(filter->sess, SESS_FLAG_DEBUG)) {
            isaac_log(LOG_DEBUG, "[Session %s] Executing filter callback [%p] %s\n",
                      filter->sess->id, filter, (oneshot) ? "(oneshot)" : "");
        }
        ret = filter->data.async.callback(filter, msg);
    }

    // If the filter is marked for only triggering once, unregister it
    if (oneshot) {
        filter_destroy(filter);
    }
    return ret;
}

int
filter_exec_sync(Filter *filter, AmiMessage *msg)
{
    // Check we have a valid filter
    if (!filter || filter->type != FILTER_SYNC)
        return 1;

    // This filter already contains a message
    if (filter->data.sync.triggered)
        return 1;

    // Lock the filter before updating
    pthread_mutex_lock(&filter->data.sync.lock);
    // Copy the message
    filter->data.sync.msg = *msg;
    // Mark as triggered
    filter->data.sync.triggered = 1;
    // Unlock and exit
    pthread_mutex_unlock(&filter->data.sync.lock);
    return 0;
}

int
filter_run(Filter *filter, int timeout, AmiMessage *ret)
{
    // Check we have a valid filter
    if (!filter || filter->type != FILTER_SYNC)
        return 1;

    int remaining = timeout * 1000;
    while (filter->data.sync.triggered == 0 && remaining) {
        usleep(500);
        remaining -= 500;
    }

    // Timeout!
    if (!remaining) {
        filter_destroy(filter);
        return 1;
    }
    if (session_test_flag(filter->sess, SESS_FLAG_DEBUG)) {
        isaac_log(LOG_DEBUG, "[Session %s] Storing sync filter data [%p]\n",
                  filter->sess->id, filter);
    }

    // Copy the message to be returned
    *ret = filter->data.sync.msg;

    // Unregister the filter
    filter_destroy(filter);
    return 0;
}

void
filter_set_userdata(Filter *filter, void *userdata)
{
    if (!filter || filter->type != FILTER_ASYNC)
        return;
    filter->data.async.app_info = userdata;
}

void *
filter_get_userdata(Filter *filter)
{
    if (!filter || filter->type != FILTER_ASYNC)
        return NULL;
    return filter->data.async.app_info;
}

void *
filter_from_userdata(Session *sess, void *userdata)
{
    Filter *filter = NULL;
    // Sanity check
    if (!sess) return NULL;

    // Unregister all this connection filters
    while ((filter = filter_from_session(sess, filter))) {
        if (filter_get_userdata(filter) == userdata)
            break;
    }

    return filter;
}

Filter *
filter_from_session(Session *sess, Filter *from)
{
    g_return_val_if_fail(sess != NULL, NULL);
    if (from == NULL) {
        return g_slist_nth_data(sess->filters, 0);
    } else {
        return g_slist_nth_data(
                sess->filters,
                g_slist_index(sess->filters, from)
        );
    }
}

int
filter_print_message(Filter *filter, AmiMessage *msg)
{
    return 1;
    // Only for debuging purposes
    // Write a dump version of AMI message back to the session
    return session_write(filter->sess, "D> %s\r\n", message_to_text(msg));
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

    // Show some log
    isaac_log(LOG_NOTICE, "[Session %s] Injecting fake %s message\n", filter->sess->id,
              message_get_header(msg, "Event"));
    isaac_log(LOG_DEBUG, "[Session %s] Injecting fake %s message: %s\n", filter->sess->id,
              message_get_header(msg, "Event"), message_to_text(msg));

    // Add this message to all session queues
    sessions_enqueue_message(msg);
}

gboolean
filter_check_message(Filter *filter, AmiMessage *msg)
{
    // Initialize the matching headers count
    gint matches = 0;

    // Loop through all filter conditions
    for (gint i = 0; i < filter->condcount; i++) {
        const gchar *msgvalue = message_get_header(msg, filter->conds[i].hdr);
        gchar *condvalue = filter->conds[i].val;

        // Depending on condition type, do the proper check
        switch (filter->conds[i].type) {
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
                if (!regexec(&filter->conds[i].regex, msgvalue, 0, NULL, 0)) {
                    matches++;
                }
                break;
            case MATCH_REGEX_NOT:
                if (regexec(&filter->conds[i].regex, msgvalue, 0, NULL, 0)) {
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
    return matches == filter->condcount;
}