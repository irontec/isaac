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
 * \file filter.c
 * \author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * \brief Source code for funtions defined in filter.h
 *
 *
 */
#include "config.h"
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include "manager.h"
#include "filter.h"
#include "log.h"
#include "util.h"

filter_t *filters = NULL;
pthread_mutex_t filters_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

filter_t *
filter_create(session_t *sess, enum callbacktype cbtype, int
(*callback)(filter_t *filter, ami_message_t *msg))
{

    filter_t *filter = NULL;

    if ((filter = malloc(sizeof(filter_t)))) {
        filter->sess = sess;
        filter->oneshot = 0;
        filter->condcount = 0;
        filter->cbtype = cbtype;
        filter->callback = callback;
    }
    return filter;

}
int
filter_add_condition(filter_t *filter, cond_t cond)
{
    if (filter->condcount == MAX_CONDS) return 1;

    if (cond.type == MATCH_REGEX) {
        if (regcomp(&filter->conds[filter->condcount].regex, cond.val, REG_EXTENDED) != 0) {
            return 1;
        }
    }

    filter->conds[filter->condcount].type = cond.type;
    strcpy(filter->conds[filter->condcount].hdr, cond.hdr);
    strcpy(filter->conds[filter->condcount].val, cond.val);
    filter->condcount++;

    return 0;
}

int
filter_new_condition(filter_t *filter, enum condtype type, char *hdr, const char *fmt, ...)
{
    char condva[MAX_CONDLEN];
    va_list ap;

    // Get the message from the format string
    va_start(ap, fmt);
    vsprintf(condva, fmt, ap);
    va_end(ap);

    if (filter->condcount == MAX_CONDS) return 1;

    if (type == MATCH_REGEX) {
        if (regcomp(&filter->conds[filter->condcount].regex, condva, REG_EXTENDED) != 0) {
            return 1;
        }
    }

    filter->conds[filter->condcount].type = type;
    strcpy(filter->conds[filter->condcount].hdr, hdr);
    strcpy(filter->conds[filter->condcount].val, condva);
    filter->condcount++;
    return 0;
}

void
filter_remove_conditions(filter_t *filter)
{
    filter->condcount = 0;
}

int
filter_register_oneshot(filter_t *filter)
{
    filter->oneshot = 1;
    return filter_register(filter);
}

int
filter_register(filter_t *filter)
{
    pthread_mutex_lock(&filters_mutex);
    isaac_log(LOG_DEBUG, "[Session %s] Registering filter [%p] with %d conditions\n",
            filter->sess->id, filter, filter->condcount);
    filter->next = filters;
    filters = filter;
    pthread_mutex_unlock(&filters_mutex);
    return 0;
}

int
filter_unregister(filter_t *filter)
{
    pthread_mutex_lock(&filters_mutex);
    isaac_log(LOG_DEBUG, "[Session %s] Unregistering filter [%p]\n", filter->sess->id, filter);
    filter_t *cur = filters, *prev = NULL;
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
    pthread_mutex_unlock(&filters_mutex);
    //@todo remove conditions and filter memory
    return 0;
}

int
filter_exec_callback(filter_t *filter, ami_message_t *msg)
{

    switch (filter->cbtype) {
    case FILTER_SYNC_CALLBACK:
        return filter->callback(filter, msg);
    default:
        /* FILTER_ASYNC_CALLBACK */
        break;
    }
    return 1;
}

void
filter_set_userdata(filter_t *filter, void *userdata)
{
    filter->app_info = userdata;
}
void *
filter_get_userdata(filter_t *filter)
{
    return filter->app_info;
}

filter_t *
get_session_filter(session_t *sess, filter_t *from)
{
    filter_t *cur = NULL;
    pthread_mutex_lock(&filters_mutex);
    if (!from) {
        cur = filters;
    } else {
        cur = from->next;
    }
    while (cur) {
        if (cur->sess == sess) {
            break;
        }
        cur = cur->next;
    }
    pthread_mutex_unlock(&filters_mutex);
    return cur;
}

int
check_message_filters(ami_message_t *msg)
{
    filter_t * cur;
    int i, matches;

    pthread_mutex_lock(&filters_mutex);
    cur = filters;
    while (cur) {
        matches = 0;
        for (i = 0; i < cur->condcount; i++) {
            switch (cur->conds[i].type) {
            case MATCH_EXACT:
                if (!isaac_strcmp(message_get_header(msg, cur->conds[i].hdr), cur->conds[i].val)) {
                    matches++;
                }
                break;
            case MATCH_START_WITH:
                if (!isaac_strncmp(message_get_header(msg, cur->conds[i].hdr), cur->conds[i].val,
                        strlen(cur->conds[i].val) - 1)) {
                    matches++;
                }
                break;
            case MATCH_REGEX:
                if (!regexec(&cur->conds[i].regex, message_get_header(msg, cur->conds[i].hdr), 0,
                        NULL, REG_EXTENDED)) {
                    matches++;
                }
                break;
            default:
                break;
            }
        }

        if (matches == cur->condcount) {
            filter_exec_callback(cur, msg);
            if (cur->oneshot) {
                filter_unregister(cur);
            }
        }

        cur = cur->next;
    }
    pthread_mutex_unlock(&filters_mutex);
    return 0;
}

int
filter_print_message(filter_t *filter, ami_message_t *msg)
{
    return session_write(filter->sess, "%s\n", message_to_text(msg));
}

