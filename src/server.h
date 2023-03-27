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

#include <glib.h>
#include <gio/gio.h>

typedef struct _ServerThread ServerThread;
typedef struct _Server Server;

struct _Server
{
    //! GIO TCP Socket server
    GSocketService *service;
    //! Server threads queue (ServerThreads*)
    GQueue *threads;
};

struct _ServerThread
{
    //! Thread running main loop
    GThread *thread;
    //! Incoming connection queue
    GAsyncQueue *queue;
    //! Incoming connection source
    GSource *source;
    //! Thread context
    GMainContext *context;
    //! Thread main loop
    GMainLoop *loop;
};

/**
 *
 * \brief Starts a TCP server on given address and port
 *
 * Create a server socket, bind on address and listen on given port,
 * then creates a new thread to accept connections.
 *
 * \returns FALSE if server setup fails, TRUE on success
 */
int
server_start();

/**
 * \brief Closes the TCP server socket, releasing all connections
 *
 * Closing this socket will cause all sessions to be destroyed (which means
 * disconnected and deallocated).
 */
void
server_stop();

/**
 * \brief Manages a new incoming connection
 *
 * Incoming connections (aka session) will handle actions in this
 * Thread function spawned by server_start.
 *
 * \param session Session structure pointer with the new connection
 *                information.
 */
void *
manage_session(void *session);

#endif
