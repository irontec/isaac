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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include "util.h"
#include "log.h"
#include "server.h"
#include "session.h"
#include "app.h"
#include "filter.h"
#include "cli.h"
#include "cfg.h"

//! Server socket
int server_sock = 0;
//! Server accept connections thread
pthread_t accept_thread;
//! Running flag
static int running;

gboolean
start_server()
{
    struct in_addr addr;
    struct sockaddr_in srvaddr;
    int reuse = 1;

    // Create a socket for a new TCP IPv4 connection
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        isaac_log(LOG_ERROR, "Error creating server socket: %s\n", strerror(errno));
        return FALSE;
    }

    // Force reuse address (in case there are ending connections in TIME_WAIT)
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) == -1) {
        isaac_log(LOG_ERROR, "Error setting socket options: %s\n", strerror(errno));
        return FALSE;
    }

    // Get network address
    if (inet_aton(cfg_get_server_address(), &addr) == 0) {
        isaac_log(LOG_ERROR, "Error getting network address: %s\n", strerror(errno));
        return FALSE;
    }

    // Bind that socket to the requested address and port
    bzero(&srvaddr, sizeof(srvaddr));
    srvaddr.sin_family = AF_INET;
    srvaddr.sin_addr = addr;
    srvaddr.sin_port = htons(cfg_get_server_port());
    if (bind(server_sock, (struct sockaddr *) &srvaddr, sizeof(srvaddr)) == -1) {
        isaac_log(LOG_ERROR, "Error binding address: %s\n", strerror(errno));
        return FALSE;
    }

    // Listen for new connections (Max queue 512)
    if (listen(server_sock, 512) == -1) {
        isaac_log(LOG_ERROR, "Error listening on address: %s\n", strerror(errno));
        return FALSE;
    }

    // Create a new thread for accepting client connections
    if (pthread_create(&accept_thread, NULL, accept_connections, NULL) != 0) {
        isaac_log(LOG_WARNING, "Error creating accept thread: %s\n", strerror(errno));
        return FALSE;
    }

    if (cfg_get_idle_timeout() > 0) {
        // Create a new thread for removing stalled client connections
        if (pthread_create(&accept_thread, NULL, check_connections, NULL) != 0) {
            isaac_log(LOG_WARNING, "Error creating check connections thread: %s\n", strerror(errno));
            return FALSE;
        }
    }

    // Successfully initialized server
    isaac_log(LOG_VERBOSE, "Server listening for connections on %s:%d\n",
              cfg_get_server_address(),
              cfg_get_server_port()
    );
    return TRUE;
}

int
stop_server()
{
    // Mark ourselfs as not running
    running = 0;
    // Say bye to all the sessions
    session_finish_all("Isaac has been stopped.");
    // Stop the socket from receiving new connections
    shutdown(server_sock, SHUT_RDWR);
    // Wait for the accept thread to finish
    if (accept_thread)
        pthread_join(accept_thread, NULL);

    return 0;
}

void *
accept_connections(void *sock)
{
    int clifd;
    struct sockaddr_in cliaddr;
    socklen_t clilen;
    Session *sess;
    pthread_attr_t attr;
    int keepalive = 1;

    // Give some feedback about us
    isaac_log(LOG_VERBOSE, "Launched server thread [ID %ld].\n", TID);

    // Start running
    running = 1;

    // Begin accepting connections
    while (running) {
        // Accept the next connections
        clilen = sizeof(cliaddr);
        if ((clifd = accept(server_sock, (struct sockaddr *) &cliaddr, &clilen)) == -1) {
            if (errno != EINVAL) {
                isaac_log(LOG_WARNING, "Error accepting new connection: %s\n", strerror(errno));
            }
            break;
        }

        // Create a new session for this connection
        if ((sess = session_create(clifd, cliaddr)) == NULL) {
            isaac_log(LOG_WARNING, "Unable to create a new session\n");
            continue;
        }

        if (cfg_get_keepalive()) {
            // Set keepalive in this client socket
            if (setsockopt(clifd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) == -1) {
                isaac_log(LOG_ERROR, "Error setting keepalive on socket %d: %s\n", clifd, strerror(errno));
            }
        }

        // Create a new thread for this client and manage its connection
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&sess->thread, &attr, manage_session, (void *) sess) != 0) {
            isaac_log(LOG_WARNING, "Error creating session thread: %s\n", strerror(errno));
            pthread_attr_destroy(&attr);
            session_destroy(sess);
            continue;
        }
        pthread_attr_destroy(&attr);
    }
    // Some goodbye logging
    isaac_log(LOG_VERBOSE, "Shutting down server thread...\n");
    // Leave the thread gracefully
    pthread_exit(NULL);
    return 0;
}

void *
check_connections(void *unused)
{
    int res = 0;
    // Start running
    running = 1;

    // Begin checking connections
    while (running) {
        GSList *sessions = sessions_adquire_lock();
        for (GSList *l = sessions; l; l = l->next) {
            Session *sess = l->data;
            struct timeval idle = isaac_tvsub(isaac_tvnow(), sess->last_cmd_time);
            if (idle.tv_sec > cfg_get_idle_timeout()) {
                session_write(sess, "BYE Session is no longer active\r\n");
                res = session_finish(sess);
                if (res == -1) {
                    session_destroy(sess);
                }
            }
        }
        sessions_release_lock();

        // Wait to next iteration
        sleep(5);
    }

    // Leave the thread gracefully
    pthread_exit(NULL);
    return 0;
}

/*****************************************************************************/
void *
manage_session(void *session)
{
    Session *sess = (Session *) session;

    // Store the connection time
    sess->last_cmd_time = isaac_tvnow();

    if (!session_test_flag(session, SESS_FLAG_LOCAL))
        isaac_log(LOG_DEBUG, "[Session %s] Received connection from %s [ID %ld].\n", sess->id, sess->addrstr, TID);

    // Write the welcome banner
    if (session_write(sess, "%s/%s\r\n", CLI_BANNER, PACKAGE_VERSION) == -1) {
        isaac_log(LOG_ERROR, "Error sending welcome banner.");
        return NULL;
    }

    g_main_loop_run(sess->loop);


    return NULL;
}
