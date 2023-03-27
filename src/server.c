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
 * \author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * \brief Source code for funtions defined in server.h
 *
 */
#include "config.h"
#include <glib.h>
#include <gio/gio.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include "log.h"
#include "server.h"
#include "session.h"
#include "cli.h"
#include "cfg.h"

//! GIO TCP Socket server
GSocketService *server;

static gboolean
accept_connections(G_GNUC_UNUSED GSocketService *service,
                   GSocketConnection *connection,
                   G_GNUC_UNUSED GObject *source_object,
                   G_GNUC_UNUSED gpointer user_data)
{
    GError *error = NULL;

    // Add a ref to the connection so it keeps alive after this callback
    g_object_ref (connection);

    GSocket *socket = g_socket_connection_get_socket(connection);
    g_return_val_if_fail(socket != NULL, TRUE);

    // Get Local address
    GSocketAddress *address = g_socket_get_remote_address(socket, &error);
    if (!address) {
        isaac_log(LOG_WARNING, "Unable to get Socket local address\n");
        return TRUE;
    }

    // Create a new session for this connection
    Session *sess = session_create(g_socket_get_fd(socket), address);
    if (sess == NULL) {
        isaac_log(LOG_WARNING, "Unable to create a new session\n");
        return TRUE;
    }

    // Configure socket keep-alive
    g_socket_set_keepalive(socket, cfg_get_keepalive());

    // Create a new thread for this client and manage its connection
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&sess->thread, &attr, manage_session, (void *) sess) != 0) {
        isaac_log(LOG_WARNING, "Error creating session thread: %s\n", strerror(errno));
        pthread_attr_destroy(&attr);
        session_destroy(sess);
        return TRUE;
    }
    pthread_attr_destroy(&attr);

    return TRUE;
}

gboolean
server_start()
{
    GError *error = NULL;

    // Get Server address and port from configuration
    GInetAddress *address = g_inet_address_new_from_string(cfg_get_server_address());
    GSocketAddress *socket_address = g_inet_socket_address_new(address, cfg_get_server_port());

    // Allocate memory for the Socket service
    server = g_socket_service_new();

    // Configure server listen address
    if (!g_socket_listener_add_address(
        G_SOCKET_LISTENER(server),
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
    g_signal_connect (server, "incoming", G_CALLBACK(accept_connections), NULL);

    // Remove allocated memory
    g_object_unref(socket_address);
    g_object_unref(address);

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
    g_socket_service_stop(server);
    // Close the underlying socket
    g_socket_listener_close(G_SOCKET_LISTENER(server));
    // Deallocate its memory
    g_object_unref(server);
}

void *
manage_session(void *session)
{
    Session *sess = (Session *) session;

    if (!session_test_flag(session, SESS_FLAG_LOCAL))
        isaac_log(LOG_DEBUG,
                  "[Session %s] Received connection from %s [socket: %d][ID %ld].\n",
                  sess->id,
                  sess->addrstr,
                  sess->fd,
                  TID);

    // Write the welcome banner
    if (session_write(sess, "%s/%s\r\n", CLI_BANNER, PACKAGE_VERSION) == -1) {
        isaac_log(LOG_ERROR, "Error sending welcome banner.");
        return NULL;
    }

    g_main_loop_run(sess->loop);


    return NULL;
}
