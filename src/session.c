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
#include "isaac.h"
#include "manager.h"
#include "filter.h"
#include "session.h"
#include "log.h"
#include "util.h"

//! Session list
session_t *sessions;
//! Session List (and ID) lock
pthread_mutex_t sessionlock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
//! Last created session id
unsigned int last_sess_id = 0;

/*****************************************************************************/
session_t *
session_create(const int fd, const struct sockaddr_in addr)
{

    session_t *sess;

    // Get some memory for this session
    if (!(sess = (session_t *) malloc(sizeof(session_t)))) {
        return NULL;
    }

    sess->fd = fd;
    sess->addr = addr;
    sess->flags = 0x00;
    sess->varcount = 0;
    memset(sess->vars, 0, sizeof(session_var_t) * MAX_VARS);
    sprintf(sess->addrstr, "%s:%d", inet_ntoa(sess->addr.sin_addr), ntohs(sess->addr.sin_port));

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&sess->lock, &attr);

    // Initialize session fields
    if (addr.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
        // Special ID for this sessions
        sprintf(sess->id, "%s", "local");
        // Local session, this does not count as a session
        session_set_flag(sess, SESS_FLAG_LOCAL);
    } else {
        // Create a new session id 
        sprintf(sess->id, "%d", last_sess_id++);
        // Increase session count in stats
        stats.sessioncnt++;
    }

    //session_set_flag(sess, SESS_FLAG_DEBUG);

    // Add it to the begining of session list
    pthread_mutex_lock(&sessionlock);
    sess->next = sessions;
    sessions = sess;
    pthread_mutex_unlock(&sessionlock);

    // Return created session;
    return sess;
}

/*****************************************************************************/
void
session_destroy(session_t *sess)
{
    filter_t *filter;
    session_t *cur, *prev = NULL;
    // Unregister all this connection filters
    while ((filter = filter_from_session(sess, NULL))) {
        filter_unregister(filter);
    }

    // Remove this session from the list
    pthread_mutex_lock(&sessionlock);
    cur = sessions;
    while (cur) {
        if (cur == sess) {
            if (prev) prev->next = cur->next;
            else
                sessions = cur->next;
            break;
        }
        prev = cur;
        cur = cur->next;
    }
    pthread_mutex_unlock(&sessionlock);

    // Mark this session as leaving
    session_set_flag(sess, SESS_FLAG_LEAVING);
}

/*****************************************************************************/
int
session_finish(session_t *sess)
{
    int res = -1;
    if (sess) {
        // Close the session socket thread-safe way
        pthread_mutex_lock(&sess->lock);
        shutdown(sess->fd, SHUT_RD);
        res = close(sess->fd);
        pthread_mutex_unlock(&sess->lock);
    }
    return res;
}

/*****************************************************************************/
int
session_write(session_t *sess, const char *fmt, ...)
{
    int wbytes = 0;
    va_list ap;
    char msgva[512];

    // Sanity Check.
    if (!sess) {
        isaac_log(LOG_WARNING, "Trying to write into non-existant session. Bug!?\n");
        return -1;
    }

    pthread_mutex_lock(&sess->lock);
    // Built the message with the given variables
    va_start(ap, fmt);
    vsprintf(msgva, fmt, ap);
    va_end(ap);

    // If the debug is enabled in this session, print a message to
    // connected CLIs. LOG_NONE will not reach any file or syslog.
    if (session_test_flag(sess, SESS_FLAG_DEBUG)) {
        isaac_log(LOG_VERBOSE_3, "\e[1;31mSession %s >> \e[0m%s", sess->id, msgva);
    }

    // Write the built message into the socket
    if ((wbytes = send(sess->fd, msgva, strlen(msgva), 0) == -1)) {
        isaac_log(LOG_WARNING, "Unable to write on session %s: %s\n", sess->id, strerror(errno));
    }
    pthread_mutex_unlock(&sess->lock);
    // Return written bytes
    return wbytes;
}

int
session_write_broadcast(session_t *sender, const char *fmt, ...)
{
    // Write to the original session
    session_iter_t *iter;
    session_t *sess = NULL;
    va_list ap;
    char msgva[512];
    const char *orig_agent = session_get_variable(sender, "AGENT");

    // Built the message with the given variables
    va_start(ap, fmt);
    vsprintf(msgva, fmt, ap);
    va_end(ap);

    iter = session_iterator_new();
    while ((sess = session_iterator_next(iter))) {
        const char *agent = session_get_variable(sess, "AGENT");
        //const char *broadcast = session_get_variable(sess, "CALLBRD");
        if (sender == sess ||
            (agent && !isaac_strcmp(agent, orig_agent))) {
            session_write(sess, msgva);
        }
    }
    session_iterator_destroy(iter);
    return 0;

}

/*****************************************************************************/
int
session_read(session_t *sess, char *msg)
{
    int rbytes = 0;
    char buffer[1024]; // XXX This should be enough in most cases...
    ssize_t n;
    char c;

    // Sanity check.
    if (!sess) {
        isaac_log(LOG_WARNING, "Trying to read from non-existant session. Bug!?\n");
        return -1;
    }

    // If session is being shutdown, we're done
    if (session_test_flag(sess, SESS_FLAG_LEAVING)) 
        return -1;

    // Initialize the buffer
    memset(buffer, 0, sizeof(buffer));

    // Read character by character until the next CR
    for (n = 0; n < sizeof(buffer); n++) {
        if (recv(sess->fd, &c, 1, 0) == 1) {
            // Add this character to the buffer
            buffer[n] = c;
            // Increase the readed bytes counter
            rbytes++;
            // If end of line, stop reading
            if (c == '\n') break;
        } else {
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
        isaac_log(LOG_VERBOSE_3, "\e[1;32mSession %s << \e[0m%s", sess->id, buffer);
    }

    return rbytes;
}

/*****************************************************************************/
int
session_test_flag(session_t *sess, int flag)
{
    int ret = 0;
    if (!sess) return -1;
    pthread_mutex_lock(&sess->lock);
    ret = sess->flags & flag;
    pthread_mutex_unlock(&sess->lock);
    return ret;
}

/*****************************************************************************/
void
session_set_flag(session_t *sess, int flag)
{
    if (!sess) return;
    pthread_mutex_lock(&sess->lock);
    sess->flags |= flag;
    pthread_mutex_unlock(&sess->lock);
}

/*****************************************************************************/
void
session_clear_flag(session_t *sess, int flag)
{
    if (!sess) return;
    pthread_mutex_lock(&sess->lock);
    sess->flags &= ~flag;
    pthread_mutex_unlock(&sess->lock);
}

/*****************************************************************************/
// TODO Implement linked lists
void
session_set_variable(session_t *sess, char *varname, char *varvalue)
{
    if (!sess) return;
    pthread_mutex_lock(&sess->lock);
    strcpy(sess->vars[sess->varcount].varname, varname);
    strcpy(sess->vars[sess->varcount].varvalue, varvalue);
    sess->varcount++;
    pthread_mutex_unlock(&sess->lock);
}

/*****************************************************************************/
// TODO Implement linked lists
const char *
session_get_variable(session_t *sess, const char *varname)
{
    char *varvalue = NULL;
    if (!sess) return NULL;
    int i;
    pthread_mutex_lock(&sess->lock);
    for (i = 0; i < sess->varcount; i++) {
        if (!strcasecmp(sess->vars[i].varname, varname)) {
            varvalue = sess->vars[i].varvalue;
            break;
        }
    }
    pthread_mutex_unlock(&sess->lock);
    return varvalue;
}

/*****************************************************************************/
session_iter_t *
session_iterator_new()
{
    session_iter_t *iter;

    /* Reserve memory for iterator */
    iter = malloc(sizeof(session_iter_t));
    /* Lock the list, preventing anyone from editing it */
    pthread_mutex_lock(&sessionlock);
    /* Start with the first session */
    iter->next = sessions;
    /* Return iterator */
    return iter;
}

session_t *
session_iterator_next(session_iter_t *iter)
{
    session_t *next = iter->next;
    // If not reached the last one, store the next iteration pointer
    if (next) {
        iter->next = next->next;
    }
    return next;
}

session_t *
session_iterator_next_by_variable(session_iter_t *iter, const char *variable, const char *value)
{
    session_t *next = NULL;
    if (!variable || !value) 
        return NULL;

    while ((next = session_iterator_next(iter))) {
        const char* sessvalue = session_get_variable(next, variable);
        if (sessvalue && !strcasecmp(sessvalue, value)) {
            break;
        }
    }

    return next;
}

void
session_iterator_destroy(session_iter_t *iter)
{
    /* Destroy iterator */
    isaac_free(iter);
    /* Just unlock the Sessions List lock */
    pthread_mutex_unlock(&sessionlock);
}

session_t *
session_by_id(const char *id)
{
    session_iter_t *iter;
    session_t *sess = NULL;

    iter = session_iterator_new();
    while ((sess = session_iterator_next(iter))) {
        if (!strcmp(sess->id, id)) break;
    }
    session_iterator_destroy(iter);
    return sess;
}

session_t *
session_by_variable(const char *varname, const char *varvalue)
{
    session_iter_t *iter;
    session_t *sess = NULL;

    iter = session_iterator_new();
    while ((sess = session_iterator_next(iter))) {
        if (!isaac_strcmp(session_get_variable(sess, varname), varvalue)) {
            break;
        }
    }
    session_iterator_destroy(iter);
    return sess;
}

int
session_finish_all(const char *message)
{
    session_iter_t *iter;
    session_t *sess = NULL;
    char bye[256];
    sprintf(bye, "BYE %s\r\n", message);

    iter = session_iterator_new();
    while ((sess = session_iterator_next(iter))) {
        session_write(sess, bye);
        session_finish(sess);
    }
    session_iterator_destroy(iter);
    return 0;
}

int
session_id(session_t *sess)
{
    return atoi(sess->id);
}
