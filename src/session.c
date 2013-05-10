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
 * \file session.c
 * \author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * \brief Source code for funtions defined in session.h
 *
 * A session contains all information about an incoming connection.
 * All applications use the session structure to control the state of the
 * client connection and be able to read and write from its socket.
 *
 * Session data should not be access directly, unless you know what you
 * are really doing. In that case, be sure to lock and unlock the session
 * mutex properly to make the session thread-safe.
 *
 */
#include "config.h"
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include "manager.h"
#include "filter.h"
#include "session.h"
#include "log.h"

//! Last created session id
unsigned int last_sess_id = 0;

/*****************************************************************************/
session_t *session_create(const int fd, const struct sockaddr_in addr)
{

    session_t *sess;

    // Get some memory for this session
    if (!(sess = (session_t *) malloc(sizeof(session_t)))) {
        return NULL;
    }

    // Initialize session fields
    sess->id = last_sess_id++;
    sess->fd = fd;
    sess->addr = addr;
    sess->flags = 0x00;
    sess->varcount = 0;
    memset(sess->vars, 0, sizeof(session_var_t)*MAX_VARS);
    pthread_mutex_init(&sess->lock, NULL);

    // Return created session;
    return sess;
}

/*****************************************************************************/
void session_destroy(session_t *sess)
{
    filter_t *filter;
    // Unregister all this connection filters
    while((filter = get_session_filter(sess))){
        filter_unregister(filter);
    }
    // Destroy the session mutex
    pthread_mutex_destroy(&sess->lock);
    // Free the session allocated memory
    free(sess);
}

/*****************************************************************************/
int session_finish(session_t *sess)
{
    int res;
    // Close the session socket thread-safe way
    pthread_mutex_lock(&sess->lock);
    res = close(sess->fd);
    pthread_mutex_unlock(&sess->lock);
    return res;
}

/*****************************************************************************/
int session_write(session_t *sess, const char *fmt, ...)
{
    int wbytes = 0;
    va_list ap;
    char msgva[512];

    // Sanity Check.
    if (!sess) {
        isaac_log(LOG_WARNING, "Trying to write into non-existant session. Bug!?\n");
        return -1;
    }

    // Built the message with the given variables
    va_start(ap, fmt);
    vsprintf(msgva, fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&sess->lock);
    // If the debug is enabled in this session, print a message to
    // connected CLIs. LOG_NONE will not reach any file or syslog.
    if (session_test_flag(sess, SESS_FLAG_DEBUG)) {
        isaac_log(LOG_NONE, "\e[1;31m>> %s\e[0m", msgva);
    }

    // Write the built message into the socket
    if ((wbytes = send(sess->fd, msgva, strlen(msgva) + 1, 0) == -1)) {
        isaac_log(LOG_WARNING, "Unable to write on session %d: %s\n", sess->id, strerror(errno));
    }
    pthread_mutex_unlock(&sess->lock);
    // Return written bytes
    return wbytes;
}

/*****************************************************************************/
int session_read(session_t *sess, char *msg)
{
    int rbytes = 0;
    char buffer[1024]; // XXX This should be enough in most cases...
    ssize_t n;
    char c;

    // Sanity check.
    if (!sess){
        isaac_log(LOG_WARNING, "Trying to read from non-existant session. Bug!?\n");
        return -1;
    }

    // Initialize the buffer
    memset(buffer, 0, sizeof(buffer));

    // Read character by character until the next CR
    for(n = 0; n < sizeof(buffer); n++){
        if (recv(sess->fd, &c, 1, 0) == 1) {
            // Add this character to the buffer
            buffer[n] = c;
            // Increase the readed bytes counter
            rbytes++;
            // If end of line, stop reading
            if (c == '\n')
                break;
        } else{
            // Interruption is not an error
            if (errno == EINTR) continue;
            return -1;
        }
    }

    // Copy the readed buffer to the output var
    strncpy(msg, buffer, rbytes);

    // If the debug is enabled in this session, print a message to
    // connected CLIs. LOG_NONE will not reach any file or syslog.
    if (session_test_flag(sess, SESS_FLAG_DEBUG)) {
        isaac_log(LOG_NONE, "\e[1;32m<< %s\e[0m", buffer);
    }

    return rbytes;
}

/*****************************************************************************/
int session_test_flag(session_t *sess, int flag)
{
    return sess->flags & flag;
}

/*****************************************************************************/
void session_set_flag(session_t *sess, int flag)
{
    sess->flags |= flag;
}

/*****************************************************************************/
void session_clear_flag(session_t *sess, int flag)
{
    sess->flags &= ~flag;
}

/*****************************************************************************/
// TODO Implement linked lists
void session_set_variable(session_t *sess, char *varname, char *varvalue)
{
    strcpy(sess->vars[sess->varcount].varname, varname);
    strcpy(sess->vars[sess->varcount].varvalue, varvalue);
    sess->varcount++;
}

/*****************************************************************************/
// TODO Implement linked lists
const char *session_get_variable(session_t *sess, char *varname)
{
    int i;
    for (i = 0; i < sess->varcount; i++) {
        if (!strcasecmp(sess->vars[i].varname, varname)) {
            return sess->vars[i].varvalue;
        }
    }
    return NULL;
}
