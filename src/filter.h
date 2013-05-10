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
 * \file filter.h
 * \brief Functions to manage connection with Asterisk Manager Interface
 *
 * \warning This incldue requires manager.h to be previously declared
 *
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



#define MAX_CONDS       10
#define MAX_CONDLEN     512

enum condtype
{
    MATCH_EXACT = 0,
    MATCH_EXACT_CASE,
    MATCH_START_WITH,
    MATCH_REGEX,

};

struct condition
{
    char hdr[MAX_CONDLEN];
    char val[MAX_CONDLEN];
    enum condtype type;
};
typedef struct condition cond_t;

enum callbacktype
{
    FILTER_ASYNC_CALLBACK = 0,
    FILTER_SYNC_CALLBACK,
};

struct filter
{
    session_t *sess;
    struct condition conds[MAX_CONDS];
    unsigned int condcount;
    enum callbacktype cbtype;
    int (*callback)(struct filter *filter, ami_message_t *msg);
    void *app_info;
    struct filter *next;
};
typedef struct filter filter_t;

filter_t *filter_create(session_t *sess, enum callbacktype cbtype, int(*callback)(filter_t *filter,
        ami_message_t *msg));
int filter_add_condition(filter_t *filter, cond_t cond);
int filter_add_condition2(filter_t *filter, enum condtype type, char *hdr, char *val);
int filter_register(filter_t *filter);
int filter_unregister(filter_t *filter);
int filter_exec_callback(filter_t *filter, ami_message_t *msg);
void filter_set_userdata(filter_t *filter, void *userdata);
void *filter_get_userdata(filter_t *filter);
filter_t *get_session_filter(session_t *sess);
int check_message_filters(ami_message_t *msg);

#endif /* __ISAAC_FILTER_H_ */
