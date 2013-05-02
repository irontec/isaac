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
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/syscall.h>
#include <jansson.h>
#include <string.h>
#include "manager.h"
#include "log.h"

/* Manager information structure */
isaac_manager_t *manager;

/**
 * \brief Read a \r\n\r\n terminated input line from AMI
 *
 * This routine has been mostly taken from Dave Troy astmanproxy and is
 * based on get_input from Asterism manager.c
 *
 * Good generic line-based input routine for \r\n\r\n terminated input
 *
 * \param s             Manager connection data
 * \param output        Where readed line will be stored
 * \retval 1    If a full header has been readed
 * \retval -1   If some error occurs while reading
 * \retval 0    If something has been readed, but not a full header
 */
int manager_read_header(struct isaac_manager *s, char *output)
{
    // Output must have at least sizeof(s->inbuf) space
    int res;
    int x;

    // Look for \r\n from the front, our preferred end of line
    for (x = 0; x < s->inlen; x++) {
        int xtra = 0;
        if (s->inbuf[x] == '\n') {
            if (x && s->inbuf[x - 1] == '\r') {
                xtra = 1;
            }
            // Copy output data not including \r\n
            memcpy(output, s->inbuf, x - xtra);
            // Add trailing \0
            output[x - xtra] = '\0';
            // Move remaining data back to the front
            memmove(s->inbuf, s->inbuf + x + 1, s->inlen - x);
            s->inlen -= (x + 1);
            return 1;
        }
    }

    // If we have reached here, we have not readed a full header line
    // Verify the readed data is not higher than the buffer size
    if (s->inlen >= sizeof(s->inbuf) - 1) {
        s->inlen = 0;
    }

    do {
        // Continue (or start) reading from manager socket
        res = recv(s->fd, s->inbuf + s->inlen, sizeof(s->inbuf) - 1 - s->inlen, 0);
        if (res < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
    } while (res < 0);

    // We have some input, but it's not ready for processing,
    // store it in inbuf for the next call
    s->inlen += res;
    s->inbuf[s->inlen] = '\0';
    return 0;
}

/**
 * \brief Read a fully formed message from AMI.
 *
 * Read from AMI socket until a full message has been readed, and store the
 * readed data into an ami_message structure.
 *
 * \param s             Manager connection data
 * \param m     AMI message structure with the readed data
 * \retval 1    If a full message has been readed
 * \retval -1   If some error occurs while reading
 */
int manager_read_message(struct isaac_manager *s, struct ami_message *m)
{
    int res;

    // Initialize the message before reading
    memset(m, 0, sizeof(struct ami_message));

    for (;;) {
        res = manager_read_header(s, m->headers[m->hdrcount]);

        if (strstr(m->headers[m->hdrcount], "--END COMMAND--")) {
            m->in_command = 0;
        }
        if (strstr(m->headers[m->hdrcount], "Response: Follows")) {
            m->in_command = 1;
        }
        if (res > 0) {
            if (!m->in_command && *(m->headers[m->hdrcount]) == '\0') {
                break;
            } else if (m->hdrcount < MAX_HEADERS - 1) {
                m->hdrcount++;
            } else {
                m->in_command = 0; // reset when block full
            }
        } else if (res < 0) break;
    }
    return res;
}

/**
 * \brief Writes a header to asterisk through AMI connection
 *
 * Function to write all headers from a message through AMI
 *
 *
 * \param s             Manager connection data
 * \param m     AMI message structure with the readed data
 * \retval 0    If a full message has been written
 * \retval -1   If some error occurs while writing
 */
int manager_write_header(struct isaac_manager *s, char *header, int hdrlen)
{
    /* Try to write string, but wait no more than ms milliseconds
     before timing out */
    int res = 0;
    struct pollfd fds[1];
    // Keep trying writing until all message bytes has been writen
    while (hdrlen) {
        res = write(s->fd, header, hdrlen);
        if ((res < 0) && (errno != EAGAIN)) {
            return -1;
        }
        if (res < 0) res = 0;
        hdrlen -= res;
        s += res;
        res = 0;
        if (hdrlen) {
            fds[0].fd = s->fd;
            fds[0].events = POLLOUT;
            /* Wait until writable again */
            res = poll(fds, 1, 50);
            if (res < 1) return -1;
        }
    }
    return res;
}

/**
 * \brief Writes a message to asterisk through AMI connection
 *
 * Function to write all headers from a message through AMI
 *
 * \TODO There should be some kind of locking here..
 *
 * \param s             Manager connection data
 * \param m     AMI message structure with the readed data
 * \retval 0    If a full message has been written
 * \retval -1   If some error occurs while writing
 */
int manager_write_message(struct isaac_manager *s, struct ami_message *m)
{
    int i;

    for (i = 0; i < m->hdrcount; i++) {
        manager_write_header(s, m->headers[i], strlen(m->headers[i]));
        manager_write_header(s, "\r\n", 2);
    }
    return manager_write_header(s, "\r\n", 2);
}

/**
 * \brief Add a header with formated value to given message
 *
 * Add a new header to a message if there is enough space for it.
 *
 * \param m     AMI Message that will store the header
 * \param fmt   Format in printf syntax
 * \param ..    Rest of vars to complete the format
 * \return 0 If header has been successfuly added, 1 otherwise
 */
int message_add_header(struct ami_message *m, const char *fmt, ...)
{
    va_list ap;

    if (m->hdrcount > MAX_HEADERS) {
        return 1;
    }
    va_start(ap, fmt);
    vsprintf(m->headers[m->hdrcount], fmt, ap);
    va_end(ap);
    m->hdrcount++;
    return 0;
}

/*! \brief This function will get the value of the
 * requested header from message. */
char *message_get_header(struct ami_message *m, const char *var)
{
    char cmp[80];
    int x;
    snprintf(cmp, sizeof(cmp), "%s: ", var);
    for (x = 0; x < m->hdrcount; x++) {
        if (!strncasecmp(cmp, m->headers[x], strlen(cmp))) {
            return m->headers[x] + strlen(cmp);
        }
    }
    return "";
}

/*! \brief This function will try to connect to asterisk manager
 * interface and wait for authenticated message (in case we've the
 * credentials, of course). */
int manager_connect(struct isaac_manager *s)
{
    int r = 1, res = 0;
    struct ami_message msg;

    // Give some feedack
    isaac_log(LOG_NOTICE, "Manager: Connecting to AMI (host = %s, port = %d)\n", inet_ntoa(
            s->addr.sin_addr), ntohs(s->addr.sin_port));

    // Construct a Login message
    memset(&msg, 0, sizeof(struct ami_message));
    message_add_header(&msg, "Action: Login");
    message_add_header(&msg, "Username: %s", s->username);
    message_add_header(&msg, "Secret: %s", s->secret);

    for (;;) {
        /* Try to connect to AMI */
        if (connect(s->fd, (const struct sockaddr *) &s->addr, sizeof(s->addr)) == -1) {
            isaac_log(LOG_WARNING, "Manager: Connect failed, Retrying (%d) :%s [%d]\n", r++,
                    strerror(errno), errno);
            sleep(1);
        } else {
            /* Send login message */
            manager_write_message(s, &msg);

            /* Wait for response */
            if ((res = manager_read_message(s, &msg)) > 0) {
                /* Authentication success! Yay! */
                if (!strcmp("Authentication accepted", message_get_header(&msg, "Message"))) {
                    isaac_log(LOG_NOTICE, "Manager: Connected successfully!\n");
                    return 0;
                }
                /* Authentication failed! Boo! */
                if (!strcmp("Authentication failed", message_get_header(&msg, "Message"))) {
                    isaac_log(LOG_ERROR, "Manager: Authentication failure!\n");
                    return -1;
                }
                /* Keep reading */
                isaac_log(LOG_NOTICE, "Readed %d headers\n", msg.hdrcount);
                for (res = 0; res < msg.hdrcount; res++)
                    isaac_log(LOG_NOTICE, "Readed %s header\n", msg.headers[res]);
            } else {
                // Bad! Something bad has happen with our socket :(
                isaac_log(LOG_ERROR, "Manager: Read error %s [%d]\n", strerror(errno), errno);
            }
        }
    }
}

void *manager_do(void *man)
{
    ami_message_t msg;
    int res, connected = 0;
    struct isaac_manager *manager = (isaac_manager_t *) man;

    // Give some feedback about us
    isaac_log(LOG_VERBOSE, "Launched manager session thread [ID %ld].\n", TID);

    // Start reading messages
    for (;;) {
        if (!connected) {
            if (manager_connect(manager) != -1) {
                connected = 1;
            }
        }

        // Clean the message structure
        memset(&msg, 0, sizeof(ami_message_t));

        // Read the next message from AMI
        if ((res = manager_read_message(manager, &msg)) > 0) {
            // TODO Pass the readed msg to the H&C logic
            // TODO Is someone interested in this one?
            isaac_log(LOG_NOTICE, "Message with %s readed from AMI\n", message_get_header(&msg,
                    "Event"));
        } else if (res < 0) {
            // Something bad has happened with our socket :(
            isaac_log(LOG_WARNING, "Manager read error %s [%d]\n", strerror(errno), errno);
            // Try to connect again
            connected = 0;
        }
    }

    isaac_log(LOG_VERBOSE, "Manager: Leaving thread\n");
    pthread_exit(NULL);
    return NULL;
}

int start_manager(const char* addrstr, const int port, const char* username, const char *secret)
{
    pthread_t manager_thread;
    struct in_addr maddr;

    // Allocate memory for the manager data
    if (!(manager = malloc(sizeof(isaac_manager_t)))) {
        isaac_log(LOG_ERROR, "Failed to allocate server manager: %s\n", strerror(errno));
        return 1;
    }

    // Create a socket for a new TCP IPv4 connection
    if ((manager->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        isaac_log(LOG_ERROR, "Error creating manager socket: %s\n", strerror(errno));
        return -1;
    }

    // Get network address
    if (inet_aton(addrstr, &maddr) == 0) {
        isaac_log(LOG_ERROR, "Error getting network address: %s\n", strerror(errno));
        return -1;
    }

    // Fill Connection data
    bzero(&manager->addr, sizeof(manager->addr));
    manager->addr.sin_family = AF_INET;
    manager->addr.sin_addr = maddr;
    manager->addr.sin_port = htons(port);
    manager->username = username;
    manager->secret = secret;

    // Create the manager thread to do the rest of the process (Connection, Authentication,
    // and message reading)
    if (pthread_create(&manager_thread, NULL, (void *) manager_do, manager)) {
        isaac_log(LOG_WARNING, "Error creating manager thread: %s\n", strerror(errno));
        return 1;
    }

    return 0;
}
