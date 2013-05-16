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
 * \file manager.h
 * \author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 * \brief Functions declaration to manage connection with Asterisk Manager Interface
 *
 * Most of this functions are copied or adapted from Asterisk or Astmanproxy
 * code (or at least the idea).
 *
 */
#ifndef __ISAAC_MANAGER_H_
#define __ISAAC_MANAGER_H_
#include <pthread.h>
#include <arpa/inet.h>
#include <stdlib.h>

//! Max number of headers a message can contain
#define MAX_HEADERS 256
//! Max length of a message header (including its value)
#define MAX_LEN 1024

//! Sorter declaration of isaac_manager struct
typedef struct isaac_manager manager_t;
//! Sorter declaration of ami_message struct
typedef struct ami_message ami_message_t;

/**
 * \brief Asterisk Manager Connection Session structure
 *
 * This structure stores all related information about the connection between
 * Isaac and Asterisk using the Manager Interface. Only one instance of this
 * structure should exist.
 *
 */
struct isaac_manager
{
    //! AMI Connection Data
    struct sockaddr_in addr;
    //! AMI Connection File descriptor
    int fd;
    //! Buffer to Read data from AMI
    char inbuf[MAX_LEN];
    //! Buffer readed bytes from AMI
    int inlen;
    //! User for AMI Login event
    const char *username;
    //! Secret for AMI Login event
    const char *secret;
    //! Starting time, used to count the uptime time
    struct timeval connectedtime;
    //! Connected flag
    int connected;
    //! Mutex to avoid simultaneous writting to manager
    pthread_mutex_t lock;
};

/**
 * \brief Structure containing all data of a single message sent or recv from AMI
 *
 * This structure stores all information about one single message sent
 * or received through asterisk manager interface.
 *
 */
struct ami_message
{
    //! Number of headers of this message
    int hdrcount;
    //! Headers array with format Header: Value
    char headers[MAX_HEADERS][MAX_LEN];
    //! Parsing a response command flag
    int in_command;
};

//! Manager connection singleton instance
extern manager_t *manager;

/**
 * \brief Read next header from Asterisk Manager connection
 *
 * This routine has been mostly taken from Dave Troy astmanproxy and is
 * based on get_input from Asterism manager.c
 *
 * Good generic line-based input routine for \r\n\r\n terminated input
 *
 * \warning Do not use in applications.
 *
 * \param man             Manager connection data
 * \param output        Where readed line will be stored
 * \retval 1    If a full header has been readed
 * \retval -1   If some error occurs while reading
 * \retval 0    If something has been readed, but not a full header
 */
extern int
manager_read_header(manager_t *man, char *output);

/**
 * \brief Read a full message from Asterisk Manager connection
 *
 * Function for reading generated AMI messages. It will read
 * header after header until a fully formated message is readed.
 * \warning Do not use in applications.
 *
 * \param man   Manager connection data
 * \param msg   AMI message structure with the readed data
 * \retval 1    If a full message has been readed
 * \retval -1   If some error occurs while reading
 */
extern int
manager_read_message(manager_t *man, ami_message_t *msg);

/**
 * \brief Write a header to Asterisk Manager connection
 *
 * This function is used inside manager_read_message to read header
 * by header a fully formated message.
 *
 * \warning Do not use in applications.
 *
 * \param man    Manager connection data
 * \param header Header text in format Header: Value
 * \param hdrlen Header length including eol
 * \return Written bytes
 *
 */
extern int
manager_write_header(manager_t *man, char *header, int hdrlen);

/**
 * \brief Writes a message to asterisk through AMI connection
 *
 * Function to write all headers from a message through AMI
 *
 * \TODO There should be some kind of locking here..
 *
 * \param man   Manager connection data
 * \param msg   AMI message structure with the readed data
 * \retval 0    If a full message has been written
 * \retval -1   If some error occurs while writing
 */
extern int
manager_write_message(manager_t *man, ami_message_t *msg);

/**
 * \brief Add a new header with formatted value to an ami message
 *
 * AMI messages are built by adding header after header using this
 * function.
 * This function will not check if the header name is already included
 * in the message, so duplicated headers are possible (which in some
 * cases is desirable)
 *
 * \param msg   Asterisk Manager message
 * \param fmt   Value format in printf syntax
 * \param ...   Variables for completing fmt parameters
 * \return 0 in case of success, 1 otherwise
 */
extern int
message_add_header(ami_message_t *msg, const char *fmt, ...);

/**
 * \brief Get a header value from ami message
 *
 * Get the value corresponding to the given header name. If the
 * message does not have that header, it will return an empty
 * string.
 *
 * \param msg     Asterisk Manager message
 * \param var   Header name
 * \return Header value, or empty string if header is not found.
 */
extern const char *
message_get_header(ami_message_t *msg, const char *var);

/**
 * \brief Connect and authenticate through Asterisk Manager Interface
 *
 * This worker function will try to connect to AMI and authenticate with the
 * given username and password in isaac_manager structure.
 *
 * \param man Isaac Manager structure
 * \return 0 in case of authentication success, -1 otherwise
 *
 */
extern int
manager_connect(manager_t *man);

/**
 * \brief Main Asterisk Manager read thread
 *
 * This worker function will try to connect to AMI and authenticate with the
 * given username and password in isaac_manager structure. It will keep on
 * trying and trying even if it fails.
 *
 * After a successfull authentication, it will read each event, check if
 * any filter matchs their conditions with check_message_filters (which in fact
 * will trigger its callback on success)
 *
 * \param man Isaac Manager structure
 *
 */
extern void *
manager_read_thread(void *man);

/**
 * \brief Create Isaac Manager instance  and launch an AMI Connection thread
 *
 * This function will spawn a manager_do thread that will try to connect
 * and authenticate against Asterisk AMI. Given parameters are readed
 * from configuration file.
 *
 * \param addrstr  Asterisk AMI Listening address
 * \param port     Asterisk AMI Listening port
 * \param username Asterisk AMI Username for Login action
 * \param secret   Asterisk AMI Secret for Login action
 * \return 0 in case of thread launch success, 1 otherwise
 */
extern int
start_manager(const char *addrstr, const int port, const char *username, const char *secret);

/**
 * \brief Get AMI message as a preformated string.
 *
 * This function is only for debugging purposes. The returned message
 * should be freed after use.
 *
 * \param msg  Asterisk Manager message
 * \return a string with all header and values of the message
 */
extern char *
message_to_text(ami_message_t *msg);

#endif /* __ISAAC_MANAGER_H_ */
