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
 * \file manager.c
 * \author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 * \brief Source code for funtions defined in manager.h
 */
#include "config.h"
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include "cfg.h"
#include "manager.h"
#include "filter.h"
#include "log.h"
#include "util.h"

//! Manager connection singleton instance
manager_t *manager;
//! Manager accept connections thread
pthread_t manager_thread;

// Running flag
static int running;

int
manager_read_header(manager_t *man, char *output)
{
    // Output must have at least sizeof(man->inbuf) space
    int res;
    int x;
    struct pollfd fds[1];

    // Look for \r\n from the front, our preferred end of line
    for (x = 0; x < man->inlen; x++) {
        int xtra = 0;
        if (man->inbuf[x] == '\n') {
            if (x && man->inbuf[x - 1] == '\r') {
                xtra = 1;
            }
            // Copy output data not including \r\n
            memcpy(output, man->inbuf, x - xtra);
            // Add trailing \0
            output[x - xtra] = '\0';
            // Move remaining data back to the front
            memmove(man->inbuf, man->inbuf + x + 1, man->inlen - x);
            man->inlen -= (x + 1);
            return 1;
        }
    }

    // If we have reached here, we have not readed a full header line
    // Verify the readed data is not higher than the buffer size
    fds[0].fd = man->fd;
    fds[0].events = POLLIN;
    do {
        res = poll(fds, 1, -1);
        if (res < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        } else if (res > 0) {
            // Continue (or start) reading from manager socket
            res = recv(man->fd, man->inbuf + man->inlen, sizeof(man->inbuf) - 1 - man->inlen, 0);
            if (res < 1) return -1;
            break;
        }
    } while (res < 0);

    // We have some input, but it's not ready for processing,
    // store it in inbuf for the next call
    man->inlen += res;
    man->inbuf[man->inlen] = '\0';
    return 0;
}

int
manager_read_message(manager_t *man, AmiMessage *msg)
{
    int res;

    for (;;) {
        res = manager_read_header(man, msg->headers[msg->hdrcount]);

        if (strstr(msg->headers[msg->hdrcount], "--END COMMAND--")) {
            msg->in_command = 0;
        }
        if (strstr(msg->headers[msg->hdrcount], "Response: Follows")) {
            msg->in_command = 1;
        }
        if (res > 0) {
            if (!msg->in_command && *(msg->headers[msg->hdrcount]) == '\0') {
                break;
            } else if (msg->hdrcount < MAX_HEADERS - 1) {
                msg->hdrcount++;
            } else {
                msg->in_command = 0; // reset when block full
            }
        } else if (res < 0) break;
    }
    return res;
}

int
manager_write_header(manager_t *man, char *header, int hdrlen)
{
    // Try to write string, but wait no more than ms milliseconds
    // before timing out
    int res = 0;
    struct pollfd fds[1];
    // Keep trying writing until all message bytes has been writen
    while (hdrlen) {
        res = write(man->fd, header, hdrlen);
        if ((res < 0) && (errno != EAGAIN)) {
            return -1;
        }
        if (res < 0) res = 0;
        hdrlen -= res;
        header += res;
        res = 0;
        if (hdrlen) {
            fds[0].fd = man->fd;
            fds[0].events = POLLOUT;
            // Wait until writable again
            res = poll(fds, 1, 50);
            if (res < 1) return -1;
        }
    }
    return res;
}

int
manager_write_message(manager_t *man, AmiMessage *msg)
{
    int i, wbytes = 0;
    // Lock the manager before writting to avoid multiple threads
    // write at the same time
    g_rec_mutex_lock(&man->lock);

    // Write headers one by one followed by the end header AMI code
    for (i = 0; i < msg->hdrcount; i++) {
        wbytes += manager_write_header(man, msg->headers[i], strlen(msg->headers[i]));
        wbytes += manager_write_header(man, "\r\n", 2);
    }

    // After two CR Asterisk will treat this as a full message
    wbytes += manager_write_header(man, "\r\n", 2);
    g_rec_mutex_unlock(&man->lock);

    // Return the written bytes
    return wbytes;
}

int
message_add_header(AmiMessage *man, const char *fmt, ...)
{
    va_list ap;

    if (man->hdrcount > MAX_HEADERS) {
        return 1;
    }
    va_start(ap, fmt);
    vsprintf(man->headers[man->hdrcount], fmt, ap);
    va_end(ap);
    man->hdrcount++;
    return 0;
}

const char *
message_get_header(AmiMessage *man, const char *var)
{
    char cmp[80];
    int x;
    snprintf(cmp, sizeof(cmp), "%s: ", var);
    for (x = 0; x < man->hdrcount; x++) {
        if (!strncasecmp(cmp, man->headers[x], strlen(cmp))) {
            return man->headers[x] + strlen(cmp);
        }
    }
    return "";
}

int
manager_connect(manager_t *man)
{
    int r = 1, res = 0;
    AmiMessage msg;

    // Give some feedack
    isaac_log(LOG_NOTICE, "Manager: Connecting to AMI (host = %s, port = %d)\n", inet_ntoa(
        man->addr.sin_addr), ntohs(man->addr.sin_port));

    // Construct a Login message
    memset(&msg, 0, sizeof(AmiMessage));
    message_add_header(&msg, "Action: Login");
    message_add_header(&msg, "Username: %s", man->username);
    message_add_header(&msg, "Secret: %s", man->secret);

    for (;;) {
        // Try to connect to AMI
        if (connect(man->fd, (const struct sockaddr *) &man->addr, sizeof(man->addr)) == -1) {
            // Create a new socket if transport stands still
            if (errno == EISCONN || errno == ECONNABORTED || errno == ECONNREFUSED) {
                close(man->fd);
                man->fd = socket(AF_INET, SOCK_STREAM, 0);
            }
            isaac_log(LOG_WARNING, "Manager: Connect failed, Retrying (%d) :%s [%d]\n", r++,
                      strerror(errno), errno);
            sleep(1);
        } else {
            // Send login message
            manager_write_message(man, &msg);

            // Wait for response
            if ((res = manager_read_message(man, &msg)) > 0) {
                // Authentication success! Yay!
                if (!strcmp("Authentication accepted", message_get_header(&msg, "Message"))) {
                    isaac_log(LOG_NOTICE, "Manager: Connected successfully!\n");
                    return 0;
                }
                // Authentication failed! Boo!
                if (!strcmp("Authentication failed", message_get_header(&msg, "Message"))) {
                    isaac_log(LOG_ERROR, "Manager: Authentication failure!\n");
                    return -1;
                }
                // Keep reading
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

gpointer
manager_create_message()
{
    g_rec_mutex_lock(&manager->lock);
    gpointer msg = g_atomic_rc_box_new0(AmiMessage);
    manager->msg_read_count++;
    manager->msg_active_count++;
    g_rec_mutex_unlock(&manager->lock);
    return msg;
}

void
mamanger_unref_message(AmiMessage *msg)
{
    g_rec_mutex_lock(&manager->lock);
    manager->msg_active_count--;
    g_rec_mutex_unlock(&manager->lock);
}

void *
manager_read_thread(void *man)
{
    int res;
    manager_t *manager = (manager_t *) man;

    // Start disconnected
    manager->connected = 0;

    // Give some feedback about us
    isaac_log(LOG_VERBOSE, "Launched manager thread [ID %ld].\n", TID);

    // Marks us as running
    running = 1;

    // Start reading messages
    while (running) {
        if (!manager->connected) {
            // Close all sessions
            session_finish_all("Asterisk has gone.");
            // Try to connect
            if (manager_connect(manager) != -1) {
                manager->connected = 1;
                manager->connectedtime = isaac_tvnow();
            }
        }

        // Allocate memory to contain the new AMI message
        AmiMessage *msg = manager_create_message();

        // Read the next message from AMI
        if ((res = manager_read_message(manager, msg)) > 0) {
            // Add received message to all queues
            sessions_enqueue_message(msg);
            // Remove initial reference
            g_atomic_rc_box_release_full(msg, (GDestroyNotify) mamanger_unref_message);
        } else if (res < 0) {
            // If no error, maybe we are shutting down?
            if (!running) break;
            // Something bad has happened with our socket :(
            isaac_log(LOG_WARNING, "Manager read error %s [%d]\n", strerror(errno), errno);
            // Try to connect again
            manager->connected = 0;
        }
    }

    // Close manager socket
    close(manager->fd);

    isaac_log(LOG_VERBOSE, "Shutting down manager thread.\n");
    // Exit manager thread gracefully
    pthread_exit(NULL);
    return NULL;
}

static gboolean
manager_print_message_count(manager_t *manager)
{
    isaac_log(LOG_DEBUG, "%d messages processed in 5000 ms. Messages still in memory: %d\n",
              manager->msg_read_count, manager->msg_active_count);
    manager->msg_read_count = 0;
    return TRUE;
}

gboolean
start_manager()
{
    struct in_addr maddr;

    // Allocate memory for the manager data
    if (!(manager = g_malloc0(sizeof(manager_t)))) {
        isaac_log(LOG_ERROR, "Failed to allocate server manager: %s\n", strerror(errno));
        return 1;
    }

    // Create a socket for a new TCP IPv4 connection
    if ((manager->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        isaac_log(LOG_ERROR, "Error creating manager socket: %s\n", strerror(errno));
        return -1;
    }

    // Get network address
    if (inet_aton(cfg_get_manager_address(), &maddr) == 0) {
        isaac_log(LOG_ERROR, "Error getting network address: %s\n", strerror(errno));
        return -1;
    }

    // Fill Connection data
    bzero(&manager->addr, sizeof(manager->addr));
    manager->addr.sin_family = AF_INET;
    manager->addr.sin_addr = maddr;
    manager->addr.sin_port = htons(cfg_get_manager_port());
    manager->username = cfg_get_manager_user();
    manager->secret = cfg_get_manager_pass();
    g_rec_mutex_init(&manager->lock);

    // Create the manager thread to do the rest of the process (Connection, Authentication,
    // and message reading)
    if (pthread_create(&manager_thread, NULL, (void *) manager_read_thread, manager)) {
        isaac_log(LOG_WARNING, "Error creating manager thread: %s\n", strerror(errno));
        return FALSE;
    }

    // Manager statistics thread
    g_timeout_add(5000, (GSourceFunc) manager_print_message_count, manager);

    return TRUE;
}

int
stop_manager()
{
    // Marks us as not running
    running = 0;
    // Disconnect manager socket
    shutdown(manager->fd, SHUT_RDWR);
    // Wait for the accept thread to finish
    pthread_join(manager_thread, NULL);
    // Free manager memory
    isaac_free(manager);

    return 0;
}

char *
message_to_text(AmiMessage *msg)
{
    GString *text = g_string_new(NULL);
    for (gint i = 0; i < msg->hdrcount; i++) {
        g_string_append_printf(text, "\t\t%s\n", msg->headers[i]);
    }
    if (text->len > 1024) {
        g_string_truncate(text, 1024);
        g_string_append(text, "...");
    }
    return g_string_free(text, FALSE);
}

char *
random_actionid(char *actionid, int len)
{
    int i;
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (i = 0; i < len; ++i) {
        actionid[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    actionid[len] = 0;
    return actionid;
}
