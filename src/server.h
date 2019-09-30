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
 * \file server.h
 * \author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * \brief Functions for managing incoming connections from clients.
 *
 * This file contains the functions that manage the server that manages incoming
 * connections from client.
 * The listen address and port can be configured in CFILE (@see config.h).
 *
 * Each incoming connection will spawn a new manage_session thread, that will
 * create a new session (@see session.h) and handle the user actions by running
 * applications (@see app.h).
 */
#ifndef __ISAAC_SERVER_H
#define __ISAAC_SERVER_H

/**
 * \brief Starts a TCP server on given address and port
 *
 * Create a server socket, bind on address and listen on given port,
 * then creates a new thread to accept connections.
 *
 * \param addr TCP IPv4 Address in format xxx.xxx.xxx.xxx
 * \param port Listening port
 * \returns -1 if server setup fails, 0 on success
 */
int
start_server(const char *addr, const int port);

/**
 * \brief Closes the TCP server socket, releasing all connections
 *
 * Closing this socket will cause all sessions to be destroyed (which means
 * disconnected and deallocated).
 *
 * \returns 0 in all cases;
 */
int
stop_server();

/**
 * \brief Accept new connections and dispatch them
 *
 * This function will accept incoming connections, create sessions for
 * them and launch a manage_session thread.
 *
 * \param sockfd Server socket descriptor
 */
void *
accept_connections(void *sockfd);


/**
 * \brief Check existing sessions idle timeout
 *
 */
void *
check_connections(void *unused);

/**
 * \brief Manages a new incoming connection
 *
 * Incomming connections (aka session) will handle actions in this
 * Thread function spawned by start_server.
 *
 * \param session session_t structure pointer with the new connection
 *                information.
 */
void *
manage_session(void *session);

#endif
