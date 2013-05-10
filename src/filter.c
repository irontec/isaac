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

filter_t *filters = NULL;
pthread_mutex_t filters_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

filter_t *filter_create(session_t *sess, enum callbacktype cbtype, int(*callback)(filter_t *filter,
        ami_message_t *msg))
{

    filter_t *filter = NULL;

    if ((filter = malloc(sizeof(filter_t)))) {
        filter->sess = sess;
        filter->condcount = 0;
        filter->cbtype = cbtype;
        filter->callback = callback;
    }
    return filter;

}
int filter_add_condition(filter_t *filter, cond_t cond)
{
    if (filter->condcount == MAX_CONDS) return 1;
    filter->conds[filter->condcount].type = cond.type;
    strcpy(filter->conds[filter->condcount].hdr, cond.hdr);
    strcpy(filter->conds[filter->condcount].val, cond.val);
    filter->condcount++;
    return 0;
}

int filter_add_condition2(filter_t *filter, enum condtype type, char *hdr, char *val)
{
    if (filter->condcount == MAX_CONDS) return 1;
    filter->conds[filter->condcount].type = type;
    strcpy(filter->conds[filter->condcount].hdr, hdr);
    strcpy(filter->conds[filter->condcount].val, val);
    filter->condcount++;
    return 0;
}

int filter_register(filter_t *filter)
{
    isaac_log(LOG_DEBUG, "[Session %d] Registering filter [%p] with %d conditions\n",
            filter->sess->id, filter, filter->condcount);
    pthread_mutex_lock(&filters_mutex);
    filter->next = filters;
    filters = filter;
    pthread_mutex_unlock(&filters_mutex);
    return 0;
}

int filter_unregister(filter_t *filter)
{
    isaac_log(LOG_DEBUG, "[Session %d] Unregistering filter [%p]\n", filter->sess->id, filter);
    pthread_mutex_lock(&filters_mutex);
    filter_t *cur = filters, *prev = NULL;
    while (cur) {
        if (cur == filter) {
            if (!prev)
                filters = cur->next;
            else
                prev->next = cur->next;
            break;
        }
        prev = cur;
        cur = cur->next;
    }
    pthread_mutex_unlock(&filters_mutex);
    return 0;
}

int filter_exec_callback(filter_t *filter, ami_message_t *msg)
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

void filter_set_userdata(filter_t *filter, void *userdata)
{
    filter->app_info = userdata;
}
void *filter_get_userdata(filter_t *filter)
{
    return filter->app_info;
}

filter_t *get_session_filter(session_t *sess)
{
    filter_t *cur = NULL;
    pthread_mutex_lock(&filters_mutex);
    cur = filters;
    while (cur) {
        if (cur->sess == sess) {
            break;
        }
        cur = cur->next;
    }
    pthread_mutex_unlock(&filters_mutex);
    return cur;
}

int check_message_filters(ami_message_t *msg)
{
    filter_t *cur;
    int i, matches;

    pthread_mutex_lock(&filters_mutex);
    cur = filters;
    while (cur) {
        matches = 0;
        for (i = 0; i < cur->condcount; i++) {
            switch (cur->conds[i].type) {
            case MATCH_EXACT:
                if (message_get_header(msg, cur->conds[i].hdr) && !strcmp(message_get_header(msg,
                        cur->conds[i].hdr), cur->conds[i].val)) {
                    matches++;
                }
                break;
            default:
                /* TODO MATCH_REGEX MATCH_START_WITH */
                break;
            }
        }

        if (matches == cur->condcount) {
            filter_exec_callback(cur, msg);
        }

        cur = cur->next;
    }
    pthread_mutex_unlock(&filters_mutex);
    return 0;
}

