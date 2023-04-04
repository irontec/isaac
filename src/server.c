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
 * \file server.c
 * \author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * \brief Source code for functions defined in server.h
 *
 */
#include "config.h"
#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include "gasyncqueuesource.h"
#include "log.h"
#include "server.h"
#include "session.h"
#include "cli.h"
#include "cfg.h"

//! GIO TCP Socket server
Server *server;

#define SERVER_THREADS 1

#ifdef SERVER_THREADS
static gboolean
server_thread_manage_connection(GSocketConnection *connection, G_GNUC_UNUSED gpointer user_data)
{
    // Create a new session for this connection
    Session *sess = session_create(connection);
    g_return_val_if_fail(sess != NULL, FALSE);

    if (!session_test_flag(sess, SESS_FLAG_LOCAL)) {
        isaac_log(LOG_DEBUG,
                  "[Session#%s] Received connection from %s [socket: %d][ID %ld].\n",
                  sess->id,
                  sess->addrstr,
                  sess->fd,
                  TID);
    }

    // Write the welcome banner
    if (session_write(sess, "%s/%s\r\n", CLI_BANNER, PACKAGE_VERSION) == -1) {
        isaac_log(LOG_ERROR, "Error sending welcome banner.");
    }

    return TRUE;
}

static gpointer
server_thread_run(ServerThread *thread)
{
    g_assert_nonnull(thread);
    // Set default thread context
    g_main_context_push_thread_default(thread->context);
    // Run thread loop
    g_main_loop_run(thread->loop);
}
# else
static gpointer
server_session_manage_run(GSocketConnection *connection)
{
    GSocket *socket = g_socket_connection_get_socket(connection);
    g_return_val_if_fail(socket != NULL, NULL);

    // Create context to attach sources to main loop
    GMainContext  *context = g_main_context_new();
    g_return_val_if_fail(context != NULL, FALSE);
    GMainLoop *loop = g_main_loop_new(context, FALSE);
    g_return_val_if_fail(loop != NULL, FALSE);

    // Set default thread context
    g_main_context_push_thread_default(context);

    // Configure socket keep-alive
    g_socket_set_keepalive(socket, cfg_get_keepalive());

    // Create a new session for this connection
    Session *sess = session_create(socket);
    g_return_val_if_fail(sess != NULL, NULL);

    if (!session_test_flag(sess, SESS_FLAG_LOCAL)) {
        isaac_log(LOG_DEBUG,
                  "[Session#%s] Received connection from %s [socket: %d][ID %ld].\n",
                  sess->id,
                  sess->addrstr,
                  sess->fd,
                  TID);
    }

    // Write the welcome banner
    if (session_write(sess, "%s/%s\r\n", CLI_BANNER, PACKAGE_VERSION) == -1) {
        isaac_log(LOG_ERROR, "Error sending welcome banner.");
    }

    g_main_loop_run(loop);
}
#endif

static gboolean
server_incoming_connection(G_GNUC_UNUSED GSocketService *service,
                           GSocketConnection *connection,
                           G_GNUC_UNUSED GObject *source_object,
                           G_GNUC_UNUSED gpointer user_data)
{
    // Add a ref to the connection so it keeps alive after this callback
    g_object_ref(connection);

    // Get first thread of the queue
    ServerThread *thread = g_queue_pop_head(server->threads);
    g_queue_push_tail(server->threads, thread);

#ifdef SERVER_THREADS
    // Add the connection to the thread queue
    g_async_queue_push(thread->queue, connection);
#else
    g_thread_new(
        "Session Thread",
        (GThreadFunc) server_session_manage_run,
        connection
    );
#endif

    return TRUE;
}

gboolean
server_start()
{
    GError *error = NULL;

    // Allocate server memory
    server = g_malloc0(sizeof(Server));
    g_return_val_if_fail(server != NULL, FALSE);

    // Get Server address and port from configuration
    g_autoptr(GInetAddress) address = g_inet_address_new_from_string(cfg_get_server_address());
    g_autoptr(GSocketAddress) socket_address = g_inet_socket_address_new(address, cfg_get_server_port());

    // Allocate memory for the Socket service
    server->service = g_socket_service_new();

    // Configure server listen address
    if (!g_socket_listener_add_address(
        G_SOCKET_LISTENER(server->service),
        socket_address,
        G_SOCKET_TYPE_STREAM,
        G_SOCKET_PROTOCOL_TCP,
        NULL,
        NULL,
        &error
    )) {
        g_printerr("Failed to server socket: '%s'\n", error->message);
        return FALSE;
    }

    // Connect signal on new connections
    g_signal_connect (server->service, "incoming", G_CALLBACK(server_incoming_connection), NULL);

#ifdef SERVER_THREADS
    // Allocate memory for threads queue
    server->threads = g_queue_new();

    // Launch Server threads
    for (gint i = 0; i < cfg_get_server_threads(); i++) {
        ServerThread *thread = g_malloc0(sizeof(ServerThread));
        g_return_val_if_fail(thread != NULL, FALSE);

        // Create context to attach sources to main loop
        thread->context = g_main_context_new();
        g_return_val_if_fail(thread->context != NULL, FALSE);
        thread->loop = g_main_loop_new(thread->context, FALSE);
        g_return_val_if_fail(thread->loop != NULL, FALSE);

        // Add queue to handle incoming connections
        thread->queue = g_async_queue_new();
        thread->source = g_async_queue_source_new(thread->queue, NULL);
        g_source_set_callback(
            thread->source,
            (GSourceFunc) G_SOURCE_FUNC(server_thread_manage_connection),
            NULL,
            NULL
        );
        g_source_attach(thread->source, thread->context);

        // Build a thread name for debugging
        g_autofree gchar *thread_name = g_strdup_printf("Server Thread %d", i);
        // Launch thread loop
        thread->thread = g_thread_new(
            thread_name,
            (GThreadFunc) server_thread_run,
            thread
        );
        g_return_val_if_fail(thread->thread != NULL, FALSE);
        // Add Server to the queue
        g_queue_push_tail(server->threads, thread);
    }
#endif

    // Successfully initialized server
    isaac_log(LOG_VERBOSE, "Server listening for connections on %s:%d\n",
              cfg_get_server_address(),
              cfg_get_server_port()
    );

    return TRUE;
}

void
server_stop()
{
    // Notify all CLI connections
    isaac_log(LOG_VERBOSE, "Shutting down TCP server.\n");
    // Stop Socket service
    g_socket_service_stop(server->service);
    // Close the underlying socket
    g_socket_listener_close(G_SOCKET_LISTENER(server->service));
    // Deallocate its memory
    g_object_unref(server->service);

#ifdef SERVER_THREADS
    ServerThread *thread;
    while ((thread = g_queue_pop_head(server->threads)) != NULL) {
        g_source_destroy(thread->source);
        g_source_unref(thread->source);
        g_main_loop_quit(thread->loop);
        g_main_loop_unref(thread->loop);
        g_main_context_unref(thread->context);
        g_async_queue_unref(thread->queue);
        g_thread_join(thread->thread);
        g_free(thread);
    }
    g_queue_free(server->threads);
#endif

    g_free(server);
}
