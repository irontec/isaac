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
#include <glib.h>
#include <glib-unix.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include "manager.h"
#include "filter.h"
#include "session.h"
#include "app.h"
#include "log.h"
#include "util.h"

//! Session list
GSList *sessions;
//! Session List (and ID) lock
static GRecMutex session_mutex;
//! Last created session id
guint session_last_id = 0;

GSList *
sessions_adquire_lock()
{
    g_rec_mutex_lock(&session_mutex);
    return sessions;
}

void
sessions_release_lock()
{
    g_rec_mutex_unlock(&session_mutex);
}

static gboolean
session_handle_command(gint fd, GIOCondition condition, gpointer user_data)
{
    char msg[512];
    char action[20], args[256];
    session_t *sess = (session_t *) user_data;
    app_t *app;
    int ret;

    // While connection is up
    if (session_read(sess, msg) > 0) {
        // Store the last action time
        sess->last_cmd_time = isaac_tvnow();
        // Get message action
        if (sscanf(msg, "%s %[^\n]", action, args)) {
            if (!strlen(action))
                return FALSE;

            if ((app = application_find(action))) {
                // Run the application
                if ((ret = application_run(app, sess, args)) != 0) {
                    // If a generic error has occurred write it to the client
                    if (ret > 100) session_write(sess, "ERROR %s\r\n", apperr2str(ret));
                }
            } else {
                // What? Me no understand
                session_write(sess, "%s\r\n", apperr2str(UNKNOWN_ACTION));
            }
        } else {
            // A message must have at least... one word
            session_write(sess, "%s\r\n", apperr2str(INVALID_FORMAT));
        }
    } else {
        // Connection closed, Thanks all for the fish
        if (!session_test_flag(sess, SESS_FLAG_LOCAL))
            isaac_log(LOG_DEBUG, "[Session %s] Closed connection from %s\n", sess->id, sess->addrstr);


        // Remove all filters for this session
        filter_unregister_session(sess);

        // Deallocate session memory
        session_finish(sess);
        session_destroy(sess);
    }

    return FALSE;
}

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

    // Initialize session fields
    if (addr.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
        // Special ID for this sessions
        sprintf(sess->id, "%s", "local");
        // Local session, this does not count as a session
//        session_set_flag(sess, SESS_FLAG_LOCAL);
    } else {
        // Create a new session id
        sprintf(sess->id, "%d", session_last_id++);
    }

    // Create a main loop for this session thread
    sess->loop = g_main_loop_new(g_main_context_new(), FALSE);

    // Create a source from session client file descriptor
    sess->commands = g_unix_fd_source_new(sess->fd, G_IO_IN | G_IO_ERR | G_IO_HUP);
    g_source_set_callback(
            sess->commands,
            (GSourceFunc) G_SOURCE_FUNC(session_handle_command),
            sess,
            NULL
    );

    // Add FD source to session main loop context
    g_source_attach(sess->commands, g_main_loop_get_context(sess->loop));

    //session_set_flag(sess, SESS_FLAG_DEBUG);

    // Add it to the begining of session list
    g_rec_mutex_lock(&session_mutex);
    sessions = g_slist_append(sessions, sess);
    g_rec_mutex_unlock(&session_mutex);

    // Return created session;
    return sess;
}

/*****************************************************************************/
void
session_destroy(session_t *session)
{
    // Mark this session as leaving
    session_set_flag(session, SESS_FLAG_LEAVING);

    // Remove this session from the list
    g_rec_mutex_lock(&session_mutex);
    sessions = g_slist_remove(sessions, session);
    g_rec_mutex_unlock(&session_mutex);

    // Free all session data
    g_source_destroy(session->commands);

    // Break thread loop
    g_main_loop_quit(session->loop);

    // Free session memory
    g_free(session);
}

/*****************************************************************************/
int
session_finish(session_t *sess)
{
    int res = -1;
    if (sess) {
        // Close the session socket thread-safe way
        shutdown(sess->fd, SHUT_RD);
        res = close(sess->fd);
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

    // If session is being shutdown, we're done
    if (session_test_flag(sess, SESS_FLAG_LEAVING))
        return -1;

    // Built the message with the given variables
    va_start(ap, fmt);
    vsprintf(msgva, fmt, ap);
    va_end(ap);

    // If the debug is enabled in this session, print a message to
    // connected CLIs. LOG_NONE will not reach any file or syslog.
    if (session_test_flag(sess, SESS_FLAG_DEBUG)) {
        isaac_log(LOG_VERBOSE_3, "\e[1;31mSession %s >> \e[0m%s", sess->id, msgva);
    }

    // LOG Debug info
    if (!session_test_flag(sess, SESS_FLAG_LOCAL))
        isaac_log(LOG_DEBUG, "[Session %s] --> %s", sess->id, msgva);

    // Write the built message into the socket
    if ((wbytes = send(sess->fd, msgva, strlen(msgva), 0) == -1)) {
        isaac_log(LOG_WARNING, "Unable to write on session %s: %s\n", sess->id, strerror(errno));
    }
    // Return written bytes
    return wbytes;
}

int
session_write_broadcast(session_t *sender, const char *fmt, ...)
{
    // Write to the original session
    va_list ap;
    char msgva[512];
    const char *orig_agent = session_get_variable(sender, "AGENT");

    // Built the message with the given variables
    va_start(ap, fmt);
    vsprintf(msgva, fmt, ap);
    va_end(ap);

    g_rec_mutex_lock(&session_mutex);
    for (GSList *l = sessions; l; l = l->next) {
        session_t *sess = l->data;
        const char *agent = session_get_variable(sess, "AGENT");
        if (sender == sess ||
            (agent && !isaac_strcmp(agent, orig_agent))) {
            session_write(sess, msgva);
        }
    }
    g_rec_mutex_unlock(&session_mutex);

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
    ret = sess->flags & flag;
    return ret;
}

/*****************************************************************************/
void
session_set_flag(session_t *sess, int flag)
{
    if (!sess) return;
    sess->flags |= flag;
}

/*****************************************************************************/
void
session_clear_flag(session_t *sess, int flag)
{
    if (!sess) return;
    sess->flags &= ~flag;
}

/*****************************************************************************/
// TODO Implement linked lists
void
session_set_variable(session_t *sess, char *varname, char *varvalue)
{
    if (!sess) return;

    if (!varname) {
        isaac_log(LOG_ERROR, "No variable name supplied in session %d\n", sess->id);
        return;
    }

    if (strlen(varname) >= 128) {
        isaac_log(LOG_ERROR, "Too big variable name %s supplied in session %d\n", varname, sess->id);
        return;
    }

    int id = session_variable_idx(sess, varname);
    if (id == -1) {
        if (sess->varcount == MAX_VARS) {
            isaac_log(LOG_ERROR, "Max Variable limit (%d) reached in session %d\n", MAX_VARS, sess->id);
            return;
        }
        strcpy(sess->vars[sess->varcount].varname, varname);
        strcpy(sess->vars[sess->varcount].varvalue, varvalue);
        sess->varcount++;
    } else {
        strcpy(sess->vars[id].varname, varname);
        strcpy(sess->vars[id].varvalue, varvalue);
    }
}

/*****************************************************************************/
// TODO Implement linked lists
const char *
session_get_variable(session_t *sess, const char *varname)
{
    char *varvalue = NULL;
    if (!sess) return NULL;
    int i;
    for (i = 0; i < sess->varcount; i++) {
        if (!strcasecmp(sess->vars[i].varname, varname)) {
            varvalue = sess->vars[i].varvalue;
            break;
        }
    }
    return varvalue;
}

int
session_variable_idx(session_t *sess, const char *varname)
{
    if (!sess) return 0;
    int i;
    for (i = 0; i < sess->varcount; i++) {
        if (!strcasecmp(sess->vars[i].varname, varname)) {
            return i;
        }
    }
    return -1;
}

session_t *
session_by_id(const char *id)
{
    session_t *sess = NULL;

    g_rec_mutex_lock(&session_mutex);
    for (GSList *l = sessions; l; l = l->next) {
        sess = l->data;
        if (!strcmp(sess->id, id)) break;
    }
    g_rec_mutex_unlock(&session_mutex);
    return sess;
}

session_t *
session_by_variable(const char *varname, const char *varvalue)
{
    session_t *sess = NULL;

    g_rec_mutex_lock(&session_mutex);
    for (GSList *l = sessions; l; l = l->next) {
        sess = l->data;
        if (!isaac_strcmp(session_get_variable(sess, varname), varvalue)) {
            break;
        }
    }
    g_rec_mutex_unlock(&session_mutex);
    return sess;
}

int
session_finish_all(const char *message)
{
    char bye[256];
    sprintf(bye, "BYE %s\r\n", message);

    g_rec_mutex_lock(&session_mutex);
    for (GSList *l = sessions; l; l = l->next) {
        session_t *sess = l->data;
        session_write(sess, bye);
        session_finish(sess);
    }
    g_rec_mutex_unlock(&session_mutex);
    return 0;
}

int
session_id(session_t *sess)
{
    return atoi(sess->id);
}

