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
#include <glib.h>
#include <netinet/in.h>
#include <pthread.h>

//! Maximun number of vars in a session
//TODO Make vars a linked list to remove this limitation
#define MAX_VARS        80

//! Sorter declaration of session_var struct
typedef struct session_var session_var_t;
//! Sorter declaration of session struct
typedef struct session session_t;
//! Sorter declaration of session_iterator
typedef struct session_iterator session_iter_t;

/**
 * \brief Session variable
 *
 * Structure to store session variables. Very useful for sharing
 * data between different applications.
 */
struct session_var
{
    char varname[128];
    char varvalue[8192];
};

/**
 * \brief Session related information.
 *
 * Contains all data from an incoming client connection
 * \todo Make the Session variable list a linked list
 */
struct session
{
    //! Session ID.
    char id[20];
    //! Session flags. @see session_flag
    unsigned int flags;
    //! Session variables, TODO Make this a linked list
    struct session_var vars[MAX_VARS];
    //! Session variable counter
    int varcount;
    //! Session client file descriptor
    int fd;
    //! Socket address info
    struct sockaddr_in addr;
    //! Address string IPv4:Port
    char addrstr[25];
    //! Time of last command (for idle calculation)
    struct timeval last_cmd_time;
    //! Session running thread
    pthread_t thread;
    //! Session main loop
    GMainLoop *loop;
    //! Sessions linked list
    session_t *next;
};

/**
 * \brief Session generic flags.
 */
enum session_flag
{
    //! Session is authenticated
        SESS_FLAG_AUTHENTICATED = (1 << 1),
    //! Session messages will be written to CLI
        SESS_FLAG_DEBUG = (1 << 2),
    //! Session is leaving
        SESS_FLAG_LEAVING = (1 << 3),
    //! Session has been started from localhost
        SESS_FLAG_LOCAL = (1 << 4),
};

/**
 * \brief Iterator structure for session loops
 *
 * This structure is used to store the actual iterator state.\n
 */
struct session_iterator
{
    session_t *next;
    char prefix[80];
    int prefix_len;
};

/**
 * \brief Create a new session from client connection
 *
 * Create a new session structure from the incoming connection
 * and add it to the session list.
 * Allocated memory must be free using session_destroy (what is usually
 * done by session_manage thread).
 *
 * \param fd 	Incoming connection socket descriptor
 * \param addr 	Address information of incoming connection
 * \return 		The new created session or NULL in case of alloc error
 */
session_t *
session_create(const int fd, const struct sockaddr_in addr);

/**
 * \brief Free session memory
 *
 * Free session memory and delete it from sessions list.
 * This function will also close any pending applications and manager
 * filters.
 *
 * \warning Dont use this function from apps. Use session_finish instead.
 * \param sess Session structure to be freed
 */
void
session_destroy(session_t *sess);

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
int
session_finish(session_t *sess);

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
extern int
session_write(session_t *sess, const char *fmt, ...);

/**
 * \brief Broadcast text to all sessions of an agent
 *
 * This function will broadcast the message to the given
 * session and also to all sessions of the same agent
 * with the broadcast allowed
 *
 * \param sess  Session structure
 * \param fmt   String format in printf syntax
 * \param ...   Zero or more vars to fill the fmt
 * \return 0 in case of success, -1 otherwise
 */
extern int
session_write_broadcast(session_t *sender, const char *fmt, ...);

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
 * \return readed bytes or -1 in case of error
 */
int
session_read(session_t *sess, char *msg);

/**
 * \brief Checks if session has a flag enabled
 */
int
session_test_flag(session_t *sess, int flag);

/**
 * \brief Enables a flag in the session
 */
void
session_set_flag(session_t *sess, int flag);

/**
 * \brief Disables a flag in the session
 */
void
session_clear_flag(session_t *sess, int flag);

/**
 * \brief Set a value in the given variable
 */
void
session_set_variable(session_t *sess, char *varname, char *varvalue);

/**
 * \brief Get a value of the given variable
 */
const char *
session_get_variable(session_t *sess, const char *varname);

/**
 * \brief Get index value of a given variable
 */
int
session_variable_idx(session_t *sess, const char *varname);

extern session_iter_t *
session_iterator_new();
extern session_t *
session_iterator_next(session_iter_t *iter);

extern session_t *
session_iterator_next_by_variable(session_iter_t *iter, const char *variable, const char *value);

extern void
session_iterator_destroy(session_iter_t *iter);

extern session_t *
session_by_id(const char *id);
extern session_t *
session_by_variable(const char *varname, const char *varvalue);

extern int
session_finish_all(const char *message);

extern int
session_id(session_t *sess);

#endif
