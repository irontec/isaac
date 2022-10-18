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

//! General isaac configuration
extern cfg_t config;
//! Server socket
int server_sock = 0;
//! Server accept connections thread
pthread_t accept_thread;
//! Running flag
static int running;

int
start_server(const char *addrstr, const int port)
{
    struct in_addr addr;
    struct sockaddr_in srvaddr;
    int reuse = 1;

    // Create a socket for a new TCP IPv4 connection
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        isaac_log(LOG_ERROR, "Error creating server socket: %s\n", strerror(errno));
        return -1;
    }

    // Force reuse address (in case there are ending connections in TIME_WAIT)
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) == -1) {
        isaac_log(LOG_ERROR, "Error setting socket options: %s\n", strerror(errno));
        return -1;
    }

    // Get network address
    if (inet_aton(addrstr, &addr) == 0) {
        isaac_log(LOG_ERROR, "Error getting network address: %s\n", strerror(errno));
        return -1;
    }

    // Bind that socket to the requested address and port
    bzero(&srvaddr, sizeof(srvaddr));
    srvaddr.sin_family = AF_INET;
    srvaddr.sin_addr = addr;
    srvaddr.sin_port = htons(port);
    if (bind(server_sock, (struct sockaddr *) &srvaddr, sizeof(srvaddr)) == -1) {
        isaac_log(LOG_ERROR, "Error binding address: %s\n", strerror(errno));
        return -1;
    }

    // Listen for new connections (Max queue 512)
    if (listen(server_sock, 512) == -1) {
        isaac_log(LOG_ERROR, "Error listening on address: %s\n", strerror(errno));
        return -1;
    }

    // Create a new thread for accepting client connections
    if (pthread_create(&accept_thread, NULL, accept_connections, NULL) != 0) {
        isaac_log(LOG_WARNING, "Error creating accept thread: %s\n", strerror(errno));
        return -1;
    }

    if (config.idle_timeout > 0) {
        // Create a new thread for removing stalled client connections
        if (pthread_create(&accept_thread, NULL, check_connections, NULL) != 0) {
            isaac_log(LOG_WARNING, "Error creating check connections thread: %s\n", strerror(errno));
            return -1;
        }
    }

    // Successfully initialized server
    isaac_log(LOG_VERBOSE, "Server listening for connections on %s:%d\n", addrstr, port);
    return 0;
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
    session_t *sess;
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

        if (config.keepalive) {
            // Set keepalive in this client socket
            if(setsockopt(clifd, SOL_SOCKET, SO_KEEPALIVE, &keepalive , sizeof(keepalive)) == -1) {
                isaac_log(LOG_ERROR, "Error setting keepalive on socket %d: %s\n", clifd, strerror(errno));
            }
        }

        // Create a new thread for this client and manage its connection
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&sess->thread, &attr, manage_session, (void*) sess) != 0) {
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
    // Start running
    running = 1;

    // Begin checking connections
    while (running) {
        session_iter_t *iter = session_iterator_new();
        session_t *sess;

        /* Print available sessions */
        while ((sess = session_iterator_next(iter))) {
            struct timeval idle = isaac_tvsub(isaac_tvnow(), sess->last_cmd_time);
            if (idle.tv_sec > config.idle_timeout) {
                session_write(sess, "BYE Session is no longer active\r\n");
                session_finish(sess);
            }
        }
        /* Destroy iterator after finishing */
        session_iterator_destroy(iter);

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
    char msg[8192];
    char action[20], args[8192];
    session_t *sess = (session_t *) session;
    app_t *app;
    int ret;

    // Store the connection time
    sess->last_cmd_time = isaac_tvnow();

    if (!session_test_flag(session, SESS_FLAG_LOCAL))
        isaac_log(LOG_DEBUG, "[Session %s] Received connection from %s [ID %ld].\n", sess->id, sess->addrstr, TID);

    // Write the welcome banner
    if (session_write(sess, "%s/%s\r\n", CLI_BANNER, PACKAGE_VERSION) == -1) {
        isaac_log(LOG_ERROR, "Error sending welcome banner.");
        return NULL;
    }

    // While connection is up
    while (session_read(sess, msg) > 0) {
        // Store the last action time
        sess->last_cmd_time = isaac_tvnow();
        // Get message action
        if (sscanf(msg, "%s %[^\n]", action, args)) {
            if (!strlen(action))
                continue;

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
        // Clean the buffers for the next run
        memset(action, 0, sizeof(action));
        memset(args, 0, sizeof(args));
        memset(msg, 0, sizeof(msg));
    }

    // Connection closed, Thanks all for the fish
    if (!session_test_flag(session, SESS_FLAG_LOCAL))
        isaac_log(LOG_DEBUG, "[Session %s] Closed connection from %s\n", sess->id, sess->addrstr);


    // Remove all filters for this session
    filter_unregister_session(sess);

    // Deallocate session memory
    session_finish(sess);
    session_destroy(sess);

    return NULL;
}
