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
#include <gio/gio.h>
#include <unistd.h>
#include <errno.h>
#include "manager.h"
#include "filter.h"
#include "session.h"
#include "app.h"
#include "log.h"
#include "util.h"
#include "cfg.h"
#include "gasyncqueuesource.h"

//! Session list
GSList *sessions = NULL;
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
    char msg[1024];
    Session *sess = (Session *) user_data;

    // Initialize message data
    memset(&msg, 0, sizeof(msg));

    // While connection is up
    if (session_read(sess, msg) > 0) {
        // Store the last action time
        sess->last_cmd_time = g_get_monotonic_time();

        // Split the input in command + args
        gchar **command = g_strsplit(g_strstrip(msg), " ", 2);
        if (g_strv_length(command) < 1) {
            // A message must have at least... one word
            session_write(sess, "%s\r\n", apperr2str(INVALID_FORMAT));
            g_strfreev(command);
            return TRUE;
        }

        Application *app = application_find_by_name(command[0]);
        if (!app) {
            // What? Me no understand
            session_write(sess, "%s\r\n", apperr2str(UNKNOWN_ACTION));
            g_strfreev(command);
            return TRUE;
        }

        int ret = application_run(app, sess, command[1]);
        if (ret > 100) {
            session_write(sess, "ERROR %s\r\n", apperr2str(ret));
        }

        g_strfreev(command);
    } else {
        // Connection closed, Thanks all for the fish
        if (!session_test_flag(sess, SESS_FLAG_LOCAL))
            isaac_log(LOG_DEBUG, "[Session#%s] Closed connection from %s\n", sess->id, sess->addrstr);

        // Deallocate session memory
        session_finish(sess);
        session_destroy(sess);
    }

    return TRUE;
}

static gboolean
session_check_message(AmiMessage *msg, gpointer user_data)
{
    Session *session = (Session *) user_data;
    // Check message against all session filters
    g_slist_foreach(session->filters, (GFunc) filter_check_and_exec, msg);
    // We are done with this message
    g_atomic_rc_box_release_full(msg, (GDestroyNotify) mamanger_unref_message);
    return TRUE;
}

static gboolean
session_check_idle(Session *session)
{
    g_return_val_if_fail(session != NULL, FALSE);
    gint64 idle_secs = (g_get_monotonic_time() - session->last_cmd_time) / G_USEC_PER_SEC;
    if (idle_secs > cfg_get_idle_timeout()) {
        session_write(session, "BYE Session is no longer active\r\n");
        session_finish(session);
    }
}

/*****************************************************************************/
void
session_destroy(Session *session)
{
    // Mark this session as leaving
    session_set_flag(session, SESS_FLAG_LEAVING);

    // Remove this session from the list
    g_rec_mutex_lock(&session_mutex);
    sessions = g_slist_remove(sessions, session);
    g_rec_mutex_unlock(&session_mutex);

    // Detach and free sources
    if (session->timeout) {
        g_source_destroy(session->timeout);
        g_source_unref(session->timeout);
    }
    g_source_destroy(session->commands);
    g_source_unref(session->commands);
    g_source_destroy(session->messages);
    g_source_unref(session->messages);

    // Remove queue pending messages
    while (g_async_queue_length(session->queue) != 0) {
        AmiMessage *msg = g_async_queue_pop(session->queue);
        g_atomic_rc_box_release_full(msg, (GDestroyNotify) mamanger_unref_message);
    }
    g_async_queue_unref(session->queue);

    // Remove all session variables
    while (g_slist_length(session->vars) != 0) {
        SessionVar *var = g_slist_nth_data(session->vars, 0);
        session->vars = g_slist_remove(session->vars, var);
        g_free(var->name);
        g_free(var->value);
        g_free(var);
    }
    g_slist_free(session->vars);

    // Remove all session filters
    g_slist_foreach(session->filters, (GFunc) filter_destroy, NULL);
    g_slist_free(session->filters);

    // Free session memory
    g_object_unref(session->connection);
    g_free(session->addrstr);
    g_free(session);
}

/*****************************************************************************/
Session *
session_create(GSocketConnection *connection)
{
    GError *error = NULL;

    GSocket *socket = g_socket_connection_get_socket(connection);
    g_return_val_if_fail(socket != NULL, FALSE);

    // Configure socket keep-alive
    g_socket_set_keepalive(socket, cfg_get_keepalive());

    // Get some memory for this session
    Session *sess = g_malloc0(sizeof(Session));
    g_return_val_if_fail(sess != NULL, NULL);

    // Get Local address
    g_autoptr(GSocketAddress) address = g_socket_get_remote_address(socket, &error);
    g_return_val_if_fail(address != NULL, NULL);

    GInetAddress *inet = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(address));
    g_autofree gchar *addrstr = g_inet_address_to_string(inet);
    sess->addrstr = g_strdup_printf(
        "%s:%d",
        addrstr,
        g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(address))
    );

    sess->connection = connection;
    sess->fd = g_socket_get_fd(socket);
    sess->flags = 0x00;
    sess->queue = g_async_queue_new();
    sess->last_cmd_time = g_get_monotonic_time();
    sess->vars = NULL;
    sess->filters = NULL;

    // Initialize session fields
    if (g_inet_address_get_is_loopback(inet)) {
        // Special ID for this sessions
        sprintf(sess->id, "%s", "local");
        // Local session, this does not msg_read_count as a session
//        session_set_flag(sess, SESS_FLAG_LOCAL);
        sprintf(sess->id, "%d", session_last_id++);
    } else {
        // Create a new session id
        sprintf(sess->id, "%d", session_last_id++);
    }

    // Create a source from session client file descriptor
    sess->commands = g_unix_fd_source_new(sess->fd, G_IO_IN | G_IO_ERR | G_IO_HUP);
    g_source_set_callback(
        sess->commands,
        (GSourceFunc) G_SOURCE_FUNC(session_handle_command),
        sess,
        NULL
    );
    g_source_attach(sess->commands, g_main_context_get_thread_default());

    // Create a source from AMI message async queue
    sess->messages = g_async_queue_source_new(sess->queue, NULL);
    g_source_set_callback(
        sess->messages,
        (GSourceFunc) G_SOURCE_FUNC(session_check_message),
        sess,
        NULL
    );
    g_source_attach(sess->messages, g_main_context_get_thread_default());

    // If there is idle timeout configured
    gint idle_timeout = cfg_get_idle_timeout();
    if (idle_timeout) {
        sess->timeout = g_timeout_source_new_seconds(5);
        g_source_set_callback(
            sess->timeout,
            (GSourceFunc) G_SOURCE_FUNC(session_check_idle),
            sess,
            NULL
        );
        g_source_attach(sess->timeout, g_main_context_get_thread_default());
    }

    // Add it to the beginning of session list
    g_rec_mutex_lock(&session_mutex);
    sessions = g_slist_append(sessions, sess);
    g_rec_mutex_unlock(&session_mutex);

    // Return created session;
    return sess;
}

/*****************************************************************************/
int
session_finish(Session *sess)
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
session_write(Session *sess, const char *fmt, ...)
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
        isaac_log(LOG_VERBOSE_3, "\033[1;31mSession#%s >> \033[0m%s", sess->id, msgva);
    }

    // LOG Debug info
    if (!session_test_flag(sess, SESS_FLAG_LOCAL))
        isaac_log(LOG_DEBUG, "[Session#%s] --> %s", sess->id, msgva);

    // Write the built message into the socket
    if ((wbytes = send(sess->fd, msgva, strlen(msgva), 0) == -1)) {
        isaac_log(LOG_WARNING, "Unable to write on session %s: %s\n", sess->id, strerror(errno));
    }
    // Return written bytes
    return wbytes;
}

int
session_write_broadcast(Session *sender, const char *fmt, ...)
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
        Session *sess = l->data;
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
session_read(Session *sess, char *msg)
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
        isaac_log(LOG_VERBOSE_3, "\033[1;32mSession#%s << \033[0m%s", sess->id, buffer);
    }

    return rbytes;
}

/*****************************************************************************/
int
session_test_flag(Session *sess, int flag)
{
    int ret = 0;
    if (!sess) return -1;
    ret = sess->flags & flag;
    return ret;
}

/*****************************************************************************/
void
session_set_flag(Session *sess, int flag)
{
    if (!sess) return;
    sess->flags |= flag;
}

/*****************************************************************************/
void
session_clear_flag(Session *sess, int flag)
{
    if (!sess) return;
    sess->flags &= ~flag;
}

/*****************************************************************************/
void
session_set_variable(Session *sess, const gchar *varname, const gchar *varvalue)
{
    g_return_if_fail(sess != NULL);

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
        SessionVar *var = g_malloc0(sizeof(SessionVar));
        var->name = g_strdup(varname);
        var->value = g_strdup(varvalue);
        sess->vars = g_slist_append(sess->vars, var);
    } else {
        GSList *l = g_slist_nth(sess->vars, id);
        SessionVar *var = l->data;
        g_free(var->value);
        var->value = g_strdup(varvalue);
    }
}

/*****************************************************************************/
const char *
session_get_variable(Session *sess, const gchar *varname)
{
    g_return_val_if_fail(sess != NULL, NULL);

    for (GSList *l = sess->vars; l; l = l->next) {
        SessionVar *var = l->data;
        if (!strcasecmp(var->name, varname)) {
            return var->value;
        }
    }
    return NULL;
}

int
session_variable_idx(Session *sess, const char *varname)
{
    g_return_val_if_fail(sess != NULL, -1);

    for (GSList *l = sess->vars; l; l = l->next) {
        SessionVar *var = l->data;
        if (!strcasecmp(var->name, varname)) {
            return g_slist_index(sess->vars, var);
        }
    }

    return -1;
}

Session *
session_by_id(const char *id)
{
    Session *sess = NULL;

    g_rec_mutex_lock(&session_mutex);
    for (GSList *l = sessions; l; l = l->next) {
        Session *candidate = l->data;
        if (g_ascii_strcasecmp(candidate->id, id) == 0) {
            sess = candidate;
            break;
        }
    }
    g_rec_mutex_unlock(&session_mutex);
    return sess;
}

Session *
session_by_variable(const char *varname, const char *varvalue)
{
    Session *sess = NULL;

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
        Session *sess = l->data;
        session_write(sess, bye);
        session_finish(sess);
    }
    g_rec_mutex_unlock(&session_mutex);
    return 0;
}

int
session_id(Session *sess)
{
    return atoi(sess->id);
}

void
sessions_enqueue_message(AmiMessage *msg)
{
    g_rec_mutex_lock(&session_mutex);
    for (GSList *l = sessions; l; l = l->next) {
        Session *sess = l->data;
        g_async_queue_push(sess->queue, (gpointer) g_atomic_rc_box_acquire(msg));
    }
    g_rec_mutex_unlock(&session_mutex);
}