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
 * \file manager.h
 * \brief Functions to manage connection with Asterisk Manager Interface
 *
 *
 *
 */

#ifndef __ISAAC_MANAGER_H_
#define __ISAAC_MANAGER_H_

#include <arpa/inet.h>

#define MAX_HEADERS             256
#define MAX_LEN                 1024
#define MAX_EVENTS              100
#define MANAGER_CFILE           "manager.conf"

/**
 * \brief This is the Connection Session structure and stores all related information
 * to the asterisk connection. There will be one of these for each manager satelite
 */
struct isaac_manager
{
    //! AMI Connection Data
    struct sockaddr_in addr;
    //! AMI Connection File descriptor
    int fd;
    //! Buffer to Read data from AMI
    char inbuf[MAX_LEN];
    //! Buffer readed bytes from AMI
    int inlen;
    //! User for AMI Login event
    const char *username;
    //! Secret for AMI Login event
    const char *secret;
};
typedef struct isaac_manager isaac_manager_t;

/**
 * \brief Structure containing all data of a single message sent or recv from AMI
 *
 * This structure stores all information about one single message sent
 * or received through asterisk manager interface.
 *
 */
struct ami_message
{
    //! Number of headers of this message
    int hdrcount;
    //! Headers array with format Header: Value
    char headers[MAX_HEADERS][MAX_LEN];
    //! XXX ???
    int in_command;
};
typedef struct ami_message ami_message_t;

char *message_to_text(ami_message_t *m);
isaac_manager_t *get_manager();
int manager_read_header(isaac_manager_t *s, char *output);
int manager_read_message(isaac_manager_t *s, struct ami_message *m);
int manager_write_header(isaac_manager_t *s, char *header, int hdrlen);
int manager_write_message(isaac_manager_t *s, ami_message_t *m);
int message_add_header(ami_message_t *m, const char *fmt, ...);
char *message_get_header(ami_message_t *m, const char *var);
int manager_connect(isaac_manager_t *s);
void *manager_do(void *man);
int start_manager(const char* addrstr, const int port, const char* username, const char *secret);

#endif /* __ISAAC_MANAGER_H_ */
