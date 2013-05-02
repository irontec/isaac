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
 * \file session.h
 * \brief Functions to manage incoming connections to server
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
#ifndef __ISAAC_SESSION_H
#define __ISAAC_SESSION_H
#include <netinet/in.h>
#include <pthread.h>

/**
 * \brief Session related information. 
 * Contains all data from an incoming client connection
 */
struct session
{
    unsigned int id;            ///< Session ID.
    unsigned int flags;         ///< Session flags. @see session_flag
    int fd;                     ///< Session client file descriptor
    struct sockaddr_in addr;    ///< Socket address info
    pthread_mutex_t lock;       ///< Session lock
};

typedef struct session session_t; ///< For shorter declarations

/**
 * \brief Session generic flags.
 */
enum session_flag
{
    ///< Session autenticated
    SESS_FLAG_AUTHENTICATED = (1 << 1),
    ///< Print session debug in CLI
    SESS_FLAG_DEBUG = (1 << 2),
};

/**
 * \brief Create a new session from client connection
 *
 * Create a new session structure from the incoming connection
 * and add it to the session list.
 * Allocated memory must be free using session_destroy and usually
 * done by session_manage thread.
 *
 * \param fd 	Incoming connection socket descriptor
 * \param addr 	Address information of incoming connection
 * \return 		The new created session or NULL in case of alloc error
 */
session_t *session_create(const int fd, const struct sockaddr_in addr);

/**
 * \brief Free session memory
 * 
 * Free session memory and delete it from sessions list.
 * This function will also close any pending applications and manager
 * hooks. 
 *
 * \note Dont use this function from apps. Use session_finish instead.
 * \param sess Session structure to be freed	
 */
void session_destroy(session_t *sess);

/**
 * \brief Closes session socket
 *
 * Closes session socket finishing the connection.
 * This function will not free any of the session data or send any
 * message before closing the connection, but will trigger the end 
 * of the session thread (thus destroying the session)
 *
 * \param sess	Session to be finished
 * \return close function return
 */
int session_finish(session_t *sess);

/**
 * \brief Sends some text to client socket
 *
 * Writes some formated text to the session client.
 * The format used here follows the printf syntax.
 *
 * \param sess	Session structure 
 * \param fmt	String format in printf syntax 
 * \param ...	Zero or more vars to fill the fmt
 * \return 0 in case of success, -1 otherwise
 */
int session_write(session_t *sess, const char *fmt, ...);

/**
 * \brief Read some text from client socket
 * 
 * Waits until something can be readen from client socket and 
 * store it in msg variable.
 *
 * This function is executed in the manage_session thread to 
 * parse each of the actions, but if for some reason an application
 * requires more than one line to work, it can be used. In this
 * case, the extra lines wont be considered actions.
 * 
 * \note Message memory must be previously allocated
 * \note This is a blocking function.
 * \param sess	Session structure
 * \param msg	Variable to store readed message
 * \return readed bytes
 */
int session_read(session_t *sess, char *msg);

/**
 * \brief Checks if session has a flag enabled
 */
int session_test_flag(session_t *sess, int flag);

/**
 * \brief Enables a flag in the session
 */
void session_set_flag(session_t *sess, int flag);

/**
 * \brief DIsables a flag in the session
 */
void session_clear_flag(session_t *sess, int flag);

#endif
