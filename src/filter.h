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
 * @file filter.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 * @brief Functions for creating and managin AMI message filters
 *
 * A filter is acts as hooks for applications. When a message from manager
 * is received, it will check against all registered filters. If a filter
 * match its conditions with the message format, it will trigger the
 * application callback.
 *
 * There are two ways of trigger a callback: Sync and Async.
 * In Sync mode, the manager thread will block until the callback has
 * finished. That way, the callback can register new filters that will match
 * following events.
 * Async mode is more designed for events that wont depend on other events.
 * That callbacks are executed by a scheduler thread.
 *
 * Filters condition are used to determine witch manager messages will trigger
 * the filter callback, comparing each header and value with the defined in the
 * condition.
 *
 * @warning This include requires manager.h to be previously declared
 */

#ifndef __ISAAC_FILTER_H_
#define __ISAAC_FILTER_H_

/**
 * This filre requires manager.h declarations to work, it must be included
 * before or it wont compile :)
 */
#ifndef __ISAAC_MANAGER_H_
#error Include manager.h before using filter.h
#endif
#include "session.h"

//! Maximum number of conditions a filter can contain
#define MAX_CONDS       10
//! Max length of header and value of conditions
#define MAX_CONDLEN     512

typedef struct isaac_filter filter_t;
typedef struct isaac_condition cond_t;

/**
 * @brief Determine how to match the filter condition
 */
enum condtype
{
    MATCH_EXACT = 0,
    MATCH_EXACT_CASE,
    MATCH_START_WITH,
    MATCH_REGEX,

};

struct isaac_condition
{
    char hdr[MAX_CONDLEN];
    char val[MAX_CONDLEN];
    enum condtype type;
};


enum callbacktype
{
    FILTER_ASYNC_CALLBACK = 0,
    FILTER_SYNC_CALLBACK,
};

struct isaac_filter
{
    session_t *sess;
    cond_t conds[MAX_CONDS];
    unsigned int condcount;
    enum callbacktype cbtype;
    int (*callback)(filter_t *filter, ami_message_t *msg);
    void *app_info;
    filter_t *next;
};


filter_t *filter_create(session_t *sess, enum callbacktype cbtype, int(*callback)(filter_t *filter,
        ami_message_t *msg));
int filter_add_condition(filter_t *filter, cond_t cond);
int filter_add_condition2(filter_t *filter, enum condtype type, char *hdr, const char *val);
void filter_remove_conditions(filter_t *filter);
int filter_register(filter_t *filter);
int filter_unregister(filter_t *filter);
int filter_exec_callback(filter_t *filter, ami_message_t *msg);
void filter_set_userdata(filter_t *filter, void *userdata);
void *filter_get_userdata(filter_t *filter);
filter_t *get_session_filter(session_t *sess);
int check_message_filters(ami_message_t *msg);

#endif /* __ISAAC_FILTER_H_ */
