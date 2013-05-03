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
 * \brief Implementation of functions for managing incoming connections from clients.
 * 
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include "config.h"
#include "log.h"
#include "server.h"
#include "session.h"
#include "app.h"

/* Server socket */
int isaac_sockfd = 0;

int start_server(const char *addrstr, const int port)
{
    struct in_addr addr;
    struct sockaddr_in srvaddr;
    int reuse = 1;
    pthread_t accept_thread;

    // Create a socket for a new TCP IPv4 connection
    if ((isaac_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        isaac_log(LOG_ERROR, "Error creating server socket: %s\n", strerror(errno));
        return -1;
    }

    // Force reuse address (in case there are ending connections in TIME_WAIT)
    if (setsockopt(isaac_sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) == -1) {
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
    if (bind(isaac_sockfd, (struct sockaddr *) &srvaddr, sizeof(srvaddr)) == -1) {
        isaac_log(LOG_ERROR, "Error binding address: %s\n", strerror(errno));
        return -1;
    }

    // Listen for new connections (Max queue 512)
    if (listen(isaac_sockfd, 512) == -1) {
        isaac_log(LOG_ERROR, "Error listening on address: %s\n", strerror(errno));
        return -1;
    }

    // Create a new thread for accepting client connections
    if (pthread_create(&accept_thread, NULL, accept_connections, NULL) != 0) {
        isaac_log(LOG_WARNING, "Error creating accept thread: %s\n", strerror(errno));
        return -1;
    }

    // Successfully initialized server
    isaac_log(LOG_VERBOSE, "Server listening for connections on %s:%d\n", addrstr, port);
    return 0;
}

void *accept_connections(void *sock)
{

    int clifd;
    struct sockaddr_in cliaddr;
    socklen_t clilen;
    pthread_t cli_thread;
    session_t *sess;

    // Begin accepting connections
    for (;;) {
        // Accept the next connections
        clilen = sizeof(cliaddr);
        if ((clifd = accept(isaac_sockfd, (struct sockaddr *) &cliaddr, &clilen)) == -1) {
            isaac_log(LOG_WARNING, "Error accepting new connection: %s\n", strerror(errno));
            exit(1); // TODO Manage this errors
        }

        // Create a new session for this connection
        if ((sess = session_create(clifd, cliaddr)) == NULL) {
            isaac_log(LOG_WARNING, "Unable to create a new session\n");
            continue;
        }

        // Create a new thread for this client and manage its connection
        if (pthread_create(&cli_thread, NULL, manage_session, (void*) sess) != 0) {
            isaac_log(LOG_WARNING, "Error creating session thread: %s\n", strerror(errno));
            session_destroy(sess);
            continue;
        }
    }

    // Server ended quite well
    return 0;
}

void *manage_session(void *session)
{
    char msg[512];
    char action[20], args[256];
    session_t *sess = (session_t *) session;
    app_t *app;
    int ret;

    isaac_log(LOG_VERBOSE, "[Session %d] Received connection from %s:%d\n", sess->id, inet_ntoa(
            sess->addr.sin_addr), ntohs(sess->addr.sin_port));

    // Write the welcome banner
    if (session_write(sess, "%s v%s\n", PACKAGE_LNAME, VERSION) == -1) {
        isaac_log(LOG_ERROR, "Error sending welcome banner.");
        return NULL;
    }

    // While connection is up
    while (session_read(sess, msg) > 0) {
        // Get message action
        if (sscanf(msg, "%[^ \n] %[^\n]", action, args)) {
            if ((app = application_find(action))) {
                // Run the application
                if ((ret = application_run(app, session, args)) != 0) {
                    // If a generic error has occurred write it to the client
                    if (ret > 100) session_write(sess, "ERROR %s\n", apperr2str(ret));
                }
            } else {
                // What? Me no understand
                session_write(sess, "%s\n", apperr2str(UNKOWN_ACTION));
            }
        } else {
            // A message must have at least... one word
            session_write(sess, "%s\n", apperr2str(INVALID_FORMAT));
        }
    }

    // Connection closed, Thanks all for the fish
    isaac_log(LOG_VERBOSE, "[Session %d] Closed connection from %s:%d\n", sess->id, inet_ntoa(
            sess->addr.sin_addr), ntohs(sess->addr.sin_port));
    session_destroy(sess);

    return NULL;
}
