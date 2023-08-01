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
 * @file remote.c
 * @author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source code for functions defined in remote.h
 */

#include "config.h"
#include <glib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include "util.h"
#include "cli.h"
#include "log.h"
#include "remote.h"

struct remote_sig_flags sig_flags;

//! Connection info to Isaac running process
CLIClient *remote_cli;
//! Command line history
History *el_hist;
//! Command line object
EditLine *el;

gint
remote_tryconnect()
{
    // Create unix socket address
    g_autoptr(GSocketAddress) socket_address = g_unix_socket_address_new(CLI_SOCKET);

    // Create Unix Socket client
    GSocketClient *client = g_socket_client_new();
    GSocketConnection *connection = g_socket_client_connect(client, G_SOCKET_CONNECTABLE(socket_address), NULL, NULL);
    if (connection == NULL) {
        return 1;
    }

    // Create a cli structure for this connection
    remote_cli = cli_create(connection);
    g_return_val_if_fail(remote_cli != NULL, 1);

    return 0;
}

void
remote_control(char *command)
{
    int res;
    char *ebuf;
    int num = 0;
    char filename[80] = "";
    struct pollfd fds;


    // Handle client signals
    memset(&sig_flags, 0, sizeof(sig_flags));
    signal(SIGINT, remote_quit_handler);
    signal(SIGTERM, remote_quit_handler);
    signal(SIGHUP, remote_quit_handler);

    // hack to print output then exit if asterisk -rx is used
    if (command) {
        char prefix[] = "cli quit after ";
        char *tmp = alloca(strlen(command) + strlen(prefix) + 1);
        // Add a prefix to tell Isaac that will exit after command
        sprintf(tmp, "%s%s", prefix, command);
        // Write the command to Isaac
        if (write(remote_cli->fd, tmp, strlen(tmp) + 1) < 0) {
            isaac_log(LOG_ERROR, "write() failed: %s\n", strerror(errno));
            if (sig_flags.need_quit) {
                return;
            }
        }
        // Wait for the answer
        fds.fd = remote_cli->fd;
        fds.events = POLLIN;
        fds.revents = 0;
        while (poll(&fds, 1, 60000) > 0) {
            char buffer[512] = "";
            int nbytes = 0;

            if (sig_flags.need_quit) {
                break;
            }
            // Read the answer from Isaac
            if ((nbytes = cli_read(remote_cli, buffer)) <= 0) {
                break;
            }

            // Write the answer to the client
            if (write(STDOUT_FILENO, buffer, nbytes) < 0) {
                isaac_log(LOG_WARNING, "write() failed: %s\n", strerror(errno));
            }
        }
        // We've done here
        return;
    }

    // Get running version
    if (write(remote_cli->fd, "core show version", 18) < 0) {
        isaac_log(LOG_ERROR, "write() failed: %s\n", strerror(errno));
        if (sig_flags.need_quit) {
            return;
        }
    }

    // Get history file from user's homedir
    if (getenv("HOME")) {
        snprintf(filename, sizeof(filename), "%s/.isaac_history", getenv("HOME"));
        remote_el_read_history(filename);
    }

    // Initialize linedit module
    if (el_hist == NULL || el == NULL) {
        remote_el_initialize();
    }

    // Add the character input handler
    el_set(el, EL_GETCFN, remote_el_read_char);

    // Start reading commands
    for (;;) {
        ebuf = (char *) el_gets(el, &num);

        if (sig_flags.need_quit) {
            break;
        }

        if (!ebuf && write(1, "", 1) < 0)
            break;

        if (!isaac_strlen_zero(ebuf)) {
            if (ebuf[strlen(ebuf) - 1] == '\n')
                ebuf[strlen(ebuf) - 1] = '\0';
            if (!remote_consolehandler(ebuf)) {
                /* Strip preamble from output */
                char *temp;
                for (temp = ebuf; *temp; temp++) {
                    if (*temp == 127) {
                        memmove(temp, temp + 1, strlen(temp));
                        temp--;
                    }
                }

                res = write(remote_cli->fd, ebuf, strlen(ebuf) + 1);
                if (res < 1) {
                    isaac_log(LOG_WARNING, "Unable to write: %s\n", strerror(errno));
                    break;
                }
            }
        }
    }

    // Write commands to history
    if (isaac_strlen(filename)) {
        remote_el_write_history(filename);
    }

    // Clean up our memory
    history_end(el_hist);
    el_end(el);
    printf("\nDisconnected from Isaac CLI.\n");

}

char *
remote_complete(EditLine *editline, int ch)
{
    int len = 0;
    char *ptr;
    int nummatches = 0;
    char **matches;
    int retval = CC_ERROR;
    char buf[2048];
    int res;

    LineInfo *lf = (LineInfo *) el_line(editline);

    *(char *) lf->cursor = '\0';
    ptr = (char *) lf->cursor;
    if (ptr) {
        while (ptr > lf->buffer) {
            if (isspace(*ptr)) {
                ptr++;
                break;
            }
            ptr--;
        }
    }

    g_rec_mutex_lock(&remote_cli->lock);

    len = lf->cursor - ptr;

    snprintf(buf, sizeof(buf), "_COMMAND NUMMATCHES \"%s\" \"%s\"", lf->buffer, ptr);
    cli_write(remote_cli, "%s", buf); // FIXME
    res = cli_read(remote_cli, buf);
    buf[res] = '\0';
    nummatches = atoi(buf);
    if (nummatches > 0) {
        char *mbuf;
        int mlen = 0, maxmbuf = 2048;
        /* Start with a 2048 byte buffer */
        if (!(mbuf = (char *) malloc(maxmbuf))) {
            return (char *) (CC_ERROR);
        }
        snprintf(buf, sizeof(buf), "_COMMAND MATCHESARRAY \"%s\" \"%s\"", lf->buffer, ptr);
        cli_write(remote_cli, "%s", buf); //FIXME
        res = 0;
        mbuf[0] = '\0';
        while (!strstr(mbuf, AST_CLI_COMPLETE_EOF) && res != -1) {
            if (mlen + 1024 > maxmbuf) {
                // Every step increment buffer 1024 bytes
                maxmbuf += 1024;
                if (!(mbuf = realloc(mbuf, maxmbuf))) {
                    return (char *) (CC_ERROR);
                }
            }
            // Only read 1024 bytes at a time
            res = cli_read(remote_cli, mbuf + mlen);
            if (res > 0)
                mlen += res;
        }
        mbuf[mlen] = '\0';

        matches = remote_el_strtoarr(mbuf);
        isaac_free(mbuf);
    } else
        matches = (char **) NULL;

    if (matches) {
        int i;
        int matches_num, maxlen, match_len;

        if (matches[0][0] != '\0') {
            el_deletestr(editline, (int) len);
            el_insertstr(editline, matches[0]);
            retval = CC_REFRESH;
        }

        if (nummatches == 1) {
            // Found an exact match
            el_insertstr(editline, " ");
            retval = CC_REFRESH;
        } else {
            // Must be more than one match
            for (i = 1, maxlen = 0; matches[i]; i++) {
                match_len = strlen(matches[i]);
                if (match_len > maxlen)
                    maxlen = match_len;
            }
            matches_num = i - 1;
            if (matches_num > 1) {
                fprintf(stdout, "\n");
                remote_display_match_list(matches, nummatches, maxlen);
                retval = CC_REDISPLAY;
            } else {
                el_insertstr(editline, " ");
                retval = CC_REFRESH;
            }
        }
        for (i = 0; matches[i]; i++)
            isaac_free(matches[i]);
        isaac_free(matches);
    }

    g_rec_mutex_unlock(&remote_cli->lock);

    return (char *) (long) retval;
}

int
remote_display_match_list(char **matches, int len, int max)
{
    int i, idx, limit, count;
    int numoutput = 0, numoutputline = 0;

    // Find out how many entries can be put on one line, with two spaces between strings
    limit = 10;
    if (limit == 0)
        limit = 1;

    // How many lines of output
    count = len / limit;
    if (count * limit < len)
        count++;

    idx = 1;

    qsort(&matches[0], (size_t) (len), sizeof(char *), remote_el_sort_compare);

    for (; count > 0; count--) {
        numoutputline = 0;
        for (i = 0; i < limit && matches[idx]; i++, idx++) {

            /* Don't print dupes */
            if ((matches[idx + 1] != NULL && strcmp(matches[idx], matches[idx + 1]) == 0)) {
                i--;
                isaac_free(matches[idx]);
                matches[idx] = NULL;
                continue;
            }

            numoutput++;
            numoutputline++;
            fprintf(stdout, "%-*s  ", max, matches[idx]);
            isaac_free(matches[idx]);
            matches[idx] = NULL;
        }
        if (numoutputline > 0)
            fprintf(stdout, "\n");
    }

    return numoutput;
}

int
remote_consolehandler(char *s)
{
    HistEvent ev;
    int ret = 0;

    // Add command to history
    if (isaac_strlen(s)) {
        history(el_hist, &ev, H_ENTER, isaac_strip(strdup(s)));
    }

    if ((strncasecmp(s, "quit", 4) == 0 || strncasecmp(s, "exit", 4) == 0) && (s[4] == '\0' || isspace(s[4]))) {
        remote_quit_handler(0);
        ret = 1;
    }
    return ret;
}

char *
remote_prompt(EditLine *e)
{
    char cli_promt[50];
    // Write application name into the prompt. Be proud!
    sprintf(cli_promt, "%s*CLI> ", PACKAGE_NAME);
    return strdup(cli_promt);
}

void
remote_quit_handler(int num)
{
    // Mark this CLI as leaving
    sig_flags.need_quit = 1;
}

int
remote_el_initialize(void)
{
    HistEvent ev;
    char *editor, *editrc = getenv("EDITRC");

    if (!(editor = getenv("ISAAC_EDITMODE"))) {
        if (!(editor = getenv("ISAAC_EDITOR"))) {
            editor = "emacs";
        }
    }

    if (el != NULL)
        el_end(el);
    if (el_hist != NULL)
        history_end(el_hist);

    el = el_init("Isaac", stdin, stdout, stderr);
    el_set(el, EL_PROMPT, remote_prompt);
    el_set(el, EL_EDITMODE, 1);
    el_set(el, EL_EDITOR, editor);
    el_hist = history_init();
    if (!el || !el_hist)
        return -1;

    // Setup history with 100 entries
    history(el_hist, &ev, H_SETSIZE, 100);
    el_set(el, EL_HIST, history, el_hist);

    el_set(el, EL_ADDFN, "ed-complete", "Complete argument", remote_complete);
    // Bind <tab> to command completion
    el_set(el, EL_BIND, "^I", "ed-complete", NULL);
    // Bind ? to command completion
    el_set(el, EL_BIND, "?", "ed-complete", NULL);
    // Bind ^D to redisplay
    el_set(el, EL_BIND, "^D", "ed-redisplay", NULL);
    // Bind Delete to delete char left
    el_set(el, EL_BIND, "\\033[3~", "ed-delete-next-char", NULL);
    // Bind Home and End to move to line start and end
    el_set(el, EL_BIND, "\\033[1~", "ed-move-to-beg", NULL);
    el_set(el, EL_BIND, "\\033[4~", "ed-move-to-end", NULL);
    // Bind C-left and C-right to move by word (not all terminals)
    el_set(el, EL_BIND, "\\eOC", "vi-next-word", NULL);
    el_set(el, EL_BIND, "\\eOD", "vi-prev-word", NULL);

    // Check if there is a resource file for editline
    if (editrc)
        el_source(el, editrc);

    return 0;
}

int
remote_el_read_char(EditLine *editline, wchar_t *cp)
{
    int num_read = 0;
    int lastpos = 0;
    struct pollfd fds[2];
    int res;
    char buf[EL_BUF_SIZE];

    for (;;) {
        if (sig_flags.need_quit) {
            break;
        }

        fds[0].fd = remote_cli->fd;
        fds[0].events = POLLIN;
        fds[1].fd = STDIN_FILENO;
        fds[1].events = POLLIN;
        res = poll(fds, 2, -1);

        if (res < 0) {
            if (errno == EINTR)
                continue;
            isaac_log(LOG_ERROR, "poll failed: %s\n", strerror(errno));
            break;
        }

        if (fds[1].revents) {
            num_read = read(STDIN_FILENO, cp, 1);
            if (num_read < 1) {
                break;
            } else
                return num_read;
        }
        if (fds[0].revents) {
            char *tmp;
            res = cli_read(remote_cli, buf);
            // if the remote side disappears exit
            if (res < 1) {
                remote_quit_handler(0);
                continue;
            }
            buf[res] = '\0';

            // Strip preamble from asynchronous events, too
            for (tmp = buf; *tmp; tmp++) {
                if (*tmp == 127) {
                    memmove(tmp, tmp + 1, strlen(tmp));
                    tmp--;
                    res--;
                }
            }

            // Write over the CLI prompt */
            if (!lastpos) {
                // REALLY FIXME if (write(STDOUT_FILENO, "\r^[[0K", 5) < 0) {
                int i;
                if (write(STDOUT_FILENO, "\r", 2) < 0) {
                }
                for (i = 0; i < strlen(remote_prompt(editline)); i++)
                    if (write(STDOUT_FILENO, " ", 1) < 0) {
                    }
                if (write(STDOUT_FILENO, "\r", 2) < 0) {
                }

            }
            if (write(STDOUT_FILENO, buf, res) < 0) {
            }
            if ((res < EL_BUF_SIZE - 1) && ((buf[res - 1] == '\n') || (buf[res - 2] == '\n'))) {
                *cp = CC_REFRESH;
                return 1;
            } else
                lastpos = 1;
        }
    }

    *cp = '\0';
    return 0;
}

char **
remote_el_strtoarr(char *buf)
{
    char **match_list = NULL, **match_list_tmp, *retstr;
    size_t match_list_len;
    int matches = 0;

    match_list_len = 1;
    while ((retstr = strsep(&buf, " ")) != NULL) {

        if (!strcmp(retstr, AST_CLI_COMPLETE_EOF))
            break;
        if (matches + 1 >= match_list_len) {
            match_list_len <<= 1;
            if ((match_list_tmp = realloc(match_list, match_list_len * sizeof(char *)))) {
                match_list = match_list_tmp;
            } else {
                if (match_list)
                    isaac_free(match_list);
                return (char **) NULL;
            }
        }

        match_list[matches++] = strdup(retstr);
    }

    if (!match_list)
        return (char **) NULL;

    if (matches >= match_list_len) {
        if ((match_list_tmp = realloc(match_list, (match_list_len + 1) * sizeof(char *)))) {
            match_list = match_list_tmp;
        } else {
            if (match_list)
                isaac_free(match_list);
            return (char **) NULL;
        }
    }

    match_list[matches] = (char *) NULL;

    return match_list;
}

int
remote_el_sort_compare(const void *i1, const void *i2)
{
    char *s1, *s2;

    s1 = ((char **) i1)[0];
    s2 = ((char **) i2)[0];

    return strcasecmp(s1, s2);
}

int
remote_el_write_history(char *filename)
{
    HistEvent ev;

    if (el_hist == NULL || el == NULL) {
        remote_el_initialize();
    }
    // Save session commands into Isaac cli history file
    return (history(el_hist, &ev, H_SAVE, filename));
}

int
remote_el_read_history(char *filename)
{
    HistEvent ev = { 0 };

    if (el_hist == NULL || el == NULL) {
        remote_el_initialize();
    }
    // Load session commands from Isaac cli history file
    return (history(el_hist, &ev, H_LOAD, filename));
}


