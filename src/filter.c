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
#include "log.h"
#include "util.h"

//! Filters registered list. Only this fillter will be triggered
filter_t *filters = NULL;
//! Lock for concurrent access to filters list
pthread_mutex_t filters_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

filter_t *
filter_create_async(session_t *sess, int (*callback)(filter_t *filter, ami_message_t *msg))
{
    filter_t *filter = NULL;
    // Allocate memory for a new filter
    if ((filter = malloc(sizeof(filter_t)))) {
        // Initialice basic fields
        memset(filter, 0, sizeof(filter_t));
        filter->sess = sess;
        filter->condcount = 0;
        filter->type = FILTER_ASYNC;
        filter->data.async.callback = callback;
        filter->data.async.oneshot = 0;
    }
    // Return the allocated filter (or NULL ;p)
    return filter;

}

filter_t *
filter_create_sync(session_t *sess)
{
    filter_t *filter = NULL;
    // Allocate memory for a new filter
    if ((filter = malloc(sizeof(filter_t)))) {
        // Initialice basic fields
        memset(filter, 0, sizeof(filter_t));
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

int
filter_new_cooked_condition(filter_t *filter, cond_t cond)
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
filter_new_condition(filter_t *filter, enum condtype type, const char *hdr, const char *fmt, ...)
{
    cond_t cond;
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
filter_remove_conditions(filter_t *filter)
{
    filter->condcount = 0;
}

int
filter_register_oneshot(filter_t *filter)
{
    if (!filter) return 1;
    if (filter->type == FILTER_ASYNC)
        filter->data.async.oneshot = 1;

    return filter_register(filter);
}

int
filter_register(filter_t *filter)
{
    pthread_mutex_lock(&filters_mutex);
    if (session_test_flag(filter->sess, SESS_FLAG_DEBUG)) {
        isaac_log(LOG_DEBUG, "[Session %s] Registering %s filter [%p] with %d conditions\n",
                  filter->sess->id,
                  (filter->type == FILTER_ASYNC) ? "asnyc" : "sync",
                  filter,
                  filter->condcount);
    }

    filter->next = filters;
    filters = filter;
    pthread_mutex_unlock(&filters_mutex);
    return 0;
}

int
filter_unregister(filter_t *filter)
{
    pthread_mutex_lock(&filters_mutex);
    // Sanity check
    if (!filter) return 1;

    // Some debug info
    if (session_test_flag(filter->sess, SESS_FLAG_DEBUG))
        isaac_log(LOG_DEBUG, "[Session %s] Unregistering filter [%p]\n", filter->sess->id, filter);

    // Mark this filter as not valid
    filter->sess = 0;
    pthread_mutex_unlock(&filters_mutex);

    return 0;
}

int
filter_unregister_session(session_t *sess)
{
    filter_t *filter;
    // Sanity check
    if (!sess) return 1;

    pthread_mutex_lock(&filters_mutex);
    // Unregister all this connection filters
    while ((filter = filter_from_session(sess, NULL))) {
        filter_unregister(filter);
    }
    pthread_mutex_unlock(&filters_mutex);

    return 0;
}

int
filter_destroy(filter_t *filter)
{
    int i;
    pthread_mutex_lock(&filters_mutex);
    // Sanity check
    if (!filter) return 1;
    filter_t *cur = filters, *prev = NULL;

    // Remove the filter from the filters list
    while (cur) {
        if (cur == filter) {
            if (!prev) filters = cur->next;
            else
                prev->next = cur->next;
            break;
        }
        prev = cur;
        cur = cur->next;
    }

    // Check if the info is still being shared by someone
    void *userdata = filter_get_userdata(filter);
    if (userdata) {
        for (cur = filters; cur; cur = cur->next) {
            if (filter_get_userdata(cur) == userdata) break;
        }
        if (!cur) isaac_free(userdata);
    }

    // Deallocate filter conditions
    for (i = 0; i < filter->condcount; i++) {
        if (filter->conds[i].type == MATCH_REGEX) {
            regfree(&filter->conds[i].regex);
        }
    }

    // Deallocate filter memory
    isaac_free(filter);

    pthread_mutex_unlock(&filters_mutex);
    //@todo remove conditions and filter allocated memory
    return 0;
}

int
filter_exec_async(filter_t *filter, ami_message_t *msg)
{
    int oneshot = filter->data.async.oneshot;
    int ret = 1;
    session_t *sess = filter->sess;

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
    if (oneshot) filter_unregister(filter);
    return ret;
}

int
filter_exec_sync(filter_t *filter, ami_message_t *msg)
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
filter_run(filter_t *filter, int timeout, ami_message_t *ret)
{
    // Check we have a valid filter
    if (!filter || filter->type != FILTER_SYNC)
        return 1;

    int remaining = timeout * 1000;
    while (filter->data.sync.triggered == 0 && remaining) {
        usleep(500);
        remaining -= 500;
    }

    // Tiemout!
    if (!remaining) {
        filter_unregister(filter);
        return 1;
    }
    if (session_test_flag(filter->sess, SESS_FLAG_DEBUG)) {
        isaac_log(LOG_DEBUG, "[Session %s] Storing sync filter data [%p]\n",
                  filter->sess->id, filter);
    }

    // Copy the message to be returned
    *ret = filter->data.sync.msg;

    // Unregister the filter
    filter_unregister(filter);
    return 0;
}

void
filter_set_userdata(filter_t *filter, void *userdata)
{
    if (!filter || filter->type != FILTER_ASYNC)
        return;
    filter->data.async.app_info = userdata;
}

void *
filter_get_userdata(filter_t *filter)
{
    if (!filter || filter->type != FILTER_ASYNC)
        return NULL;
    return filter->data.async.app_info;
}

void *
filter_from_userdata(session_t *sess, void *userdata)
{
    filter_t *filter = NULL;
    // Sanity check
    if (!sess) return NULL;

    pthread_mutex_lock(&filters_mutex);
    // Unregister all this connection filters
    while ((filter = filter_from_session(sess, filter))) {
        if (filter_get_userdata(filter) == userdata)
            break;
    }
    pthread_mutex_unlock(&filters_mutex);

    return filter;
}

filter_t *
filter_from_session(session_t *sess, filter_t *from)
{
    filter_t *cur = NULL;
    pthread_mutex_lock(&filters_mutex);
    // From which filter will search onward?
    if (!from) {
        // Start from the beginning
        cur = filters;
    } else {
        // Continue searching
        cur = from->next;
    }
    while (cur) {
        // This filter belongs to the given session
        if (cur->sess == sess) {
            break;
        }
        cur = cur->next;
    }
    pthread_mutex_unlock(&filters_mutex);
    // Return the next found filter (or NULL if none found)
    return cur;
}

int
filter_print_message(filter_t *filter, ami_message_t *msg)
{
    return 1;
    // Only for debuging purposes
    // Write a dump version of AMI message back to the session
    return session_write(filter->sess, "D> %s\r\n", message_to_text(msg));
}

int
filter_inject_message(filter_t *filter, ami_message_t *msg)
{
    session_t *sess;
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
    return check_filters_for_message(msg);
}

int
check_filters_for_message(ami_message_t *msg)
{
    filter_t *cur, *next;
    int i, matches;
    const char *msgvalue, *condvalue;

    pthread_mutex_lock(&filters_mutex);
    cur = filters;
    // Let's start checking if the given message match any registered filter!
    while (cur) {
        // Save here the next filter for the loop. This is required because the pointer
        // can disappear during the loop process (unregisted oneshot filters)
        next = cur->next;

        // Check if this filter can be triggered
        if (cur->sess == 0) {
            // Clean this filter allocated memory
            filter_destroy(cur);
        } else {
            // Initialize the matching headers count
            matches = 0;
            // Loop through all filter conditions
            for (i = 0; i < cur->condcount; i++) {
                msgvalue = message_get_header(msg, cur->conds[i].hdr);
                condvalue = cur->conds[i].val;

                // Depending on condition type, do the proper check
                switch (cur->conds[i].type) {
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
                        if (!regexec(&cur->conds[i].regex, msgvalue, 0, NULL, 0)) {
                            matches++;
                        }
                        break;
                    case MATCH_REGEX_NOT:
                        if (regexec(&cur->conds[i].regex, msgvalue, 0, NULL, 0)) {
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
            if (matches == cur->condcount) {
                if (cur->type == FILTER_ASYNC) {
                    // Exec the filter callback with the current message
                    filter_exec_async(cur, msg);
                } else {
                    // Store the message and leave
                    filter_exec_sync(cur, msg);
                }
            }
        }

        // Go on with the next message
        cur = next;
    }
    pthread_mutex_unlock(&filters_mutex);
    return 0;
}
