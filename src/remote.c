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
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include "util.h"
#include "cli.h"
#include "log.h"
#include "remote.h"

struct remote_sig_flags sig_flags;

//! Connection info to Isaac running process
cli_t *remote_cli;
//! Command line history
History *el_hist;
//! Command line object
EditLine *el;

int
remote_tryconnect()
{
    struct sockaddr_un sunaddr;
    int clisocket = socket(PF_LOCAL, SOCK_STREAM, 0);
    if (clisocket < 0) {
        fprintf(stderr, "Unable to create socket: %s\n", strerror(errno));
        return 1;
    }
    memset(&sunaddr, 0, sizeof(sunaddr));
    sunaddr.sun_family = AF_LOCAL;
    strcpy(sunaddr.sun_path, CLI_SOCKET);
    if (connect(clisocket, (struct sockaddr *) &sunaddr, sizeof(sunaddr))) {
        fprintf(stderr, "Unable to connect CLI socket %d: %s\n", errno, strerror(errno));
        return 1;
    }
    if (!(remote_cli = cli_create(clisocket, sunaddr))) {
        fprintf(stderr, "Failed to create remote CLI session\n");
        return 1;
    }
    return 0;
}

int
remote_display_match_list(char **matches, int len, int max)
{
    int i, idx, limit, count;
    int numoutput = 0, numoutputline = 0;

    /* find out how many entries can be put on one line, with two spaces between strings */
    limit = 10;
    if (limit == 0) limit = 1;

    /* how many lines of output */
    count = len / limit;
    if (count * limit < len) count++;

    idx = 1;

    qsort(&matches[0], (size_t)(len), sizeof(char *), remote_el_sort_compare);

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
        if (numoutputline > 0) fprintf(stdout, "\n");
    }

    return numoutput;
}

char *
remote_complete(EditLine *editline, int ch)
{
    int len = 0;
    char *ptr;
    int nummatches = 0;
    char **matches;
    int retval = CC_ERROR;
    char buf[2048], savechr;
    int res;

    LineInfo *lf = (LineInfo *) el_line(editline);

    savechr = *(char *) lf->cursor;
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

    pthread_mutex_lock(&remote_cli->lock);

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
        if (!(mbuf = (char*) malloc(maxmbuf))) {
            //lf->cursor[0] = savechr;
            return (char *) (CC_ERROR);
        }
        snprintf(buf, sizeof(buf), "_COMMAND MATCHESARRAY \"%s\" \"%s\"", lf->buffer, ptr);
        cli_write(remote_cli, "%s", buf); //FIXME
        res = 0;
        mbuf[0] = '\0';
        while (!strstr(mbuf, AST_CLI_COMPLETE_EOF) && res != -1) {
            if (mlen + 1024 > maxmbuf) {
                /* Every step increment buffer 1024 bytes */
                maxmbuf += 1024;
                if (!(mbuf = realloc(mbuf, maxmbuf))) {
                    //FIXME lf->cursor[0] = savechr;
                    return (char *) (CC_ERROR);
                }
            }
            /* Only read 1024 bytes at a time */
            res = read(remote_cli->fd, mbuf + mlen, 1024);
            if (res > 0) mlen += res;
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
            /* Found an exact match */
            el_insertstr(editline, " ");
            retval = CC_REFRESH;
        } else {
            /* Must be more than one match */
            for (i = 1, maxlen = 0; matches[i]; i++) {
                match_len = strlen(matches[i]);
                if (match_len > maxlen) maxlen = match_len;
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

    pthread_mutex_unlock(&remote_cli->lock);

    //lf->cursor[0] = savechr;
    return (char *) (long) retval;
}

int
remote_consolehandler(char *s)
{
    HistEvent ev;
    int ret = 0;

    /* Add command to history */
    if (isaac_strlen(s)) history(el_hist, &ev, H_ENTER, isaac_strip(strdup(s)));

    if ((strncasecmp(s, "quit", 4) == 0 || strncasecmp(s, "exit", 4) == 0) && (s[4] == '\0'
            || isspace(s[4]))) {
        remote_quit_handler(0);
        ret = 1;
    }
    return ret;
}

void
remote_control(char* data)
{
    int res;
    char *ebuf;
    int num = 0;
    char filename[80] = "";

    memset(&sig_flags, 0, sizeof(sig_flags));
    signal(SIGINT, remote_quit_handler);
    signal(SIGTERM, remote_quit_handler);
    signal(SIGHUP, remote_quit_handler);

    if (data) {
        char prefix[] = "cli quit after ";
        char *tmp = alloca(strlen(data) + strlen(prefix) + 1);
        sprintf(tmp, "%s%s", prefix, data);
        if (write(remote_cli->fd, tmp, strlen(tmp) + 1) < 0) {
            isaac_log(LOG_ERROR, "write() failed: %s\n", strerror(errno));
            if (sig_flags.need_quit || sig_flags.need_quit_handler) {
                return;
            }
        }
    } else {
        /* Get running version */
        if (write(remote_cli->fd, "core show version", 18) < 0) {
            isaac_log(LOG_ERROR, "write() failed: %s\n", strerror(errno));
            if (sig_flags.need_quit || sig_flags.need_quit_handler) {
                return;
            }
        }
    }

    if (data) { /* hack to print output then exit if asterisk -rx is used */
        struct pollfd fds;
        fds.fd = remote_cli->fd;
        fds.events = POLLIN;
        fds.revents = 0;
        while (poll(&fds, 1, 60000) > 0) {
            char buffer[512] = "", *curline = buffer, *nextline;
            int not_written = 1;

            if (sig_flags.need_quit || sig_flags.need_quit_handler) {
                break;
            }

            if (read(remote_cli->fd, buffer, sizeof(buffer) - 1) <= 0) {
                break;
            }

            do {
                if ((nextline = strchr(curline, '\n'))) {
                    nextline++;
                } else {
                    nextline = strchr(curline, '\0');
                }

                /* Skip verbose lines and two first lines*/
                if (*curline != 127) {
                    not_written = 0;
                    if (write(STDOUT_FILENO, curline, nextline - curline) < 0) {
                        isaac_log(LOG_WARNING, "write() failed: %s\n", strerror(errno));
                    }
                }
                curline = nextline;
            } while (!isaac_strlen_zero(curline));

            /* No non-verbose output in 60 seconds. */
            if (not_written) {
                break;
            }
        }
        return;
    }

    if (getenv("HOME")) snprintf(filename, sizeof(filename), "%s/.isaac_history", getenv("HOME"));

    if (el_hist == NULL || el == NULL) remote_el_initialize();

    el_set(el, EL_GETCFN, remote_el_read_char);

    if (!isaac_strlen_zero(filename)) remote_el_read_history(filename);

    for (;;) {
        ebuf = (char *) el_gets(el, &num);

        if (sig_flags.need_quit || sig_flags.need_quit_handler) {
            break;
        }

        if (!ebuf && write(1, "", 1) < 0) break;

        if (!isaac_strlen_zero(ebuf)) {
            if (ebuf[strlen(ebuf) - 1] == '\n') ebuf[strlen(ebuf) - 1] = '\0';
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

    if (isaac_strlen(filename)) {
        remote_el_write_history(filename);
    }

    /* Clean up our memory */
    history_end(el_hist);
    el_end(el);
    printf("\nDisconnected from Isaac CLI.\n");

}

char *
remote_prompt(EditLine *e)
{
    char cli_promt[50];
    sprintf(cli_promt, "%s*CLI> ", APP_NAME);
    return strdup(cli_promt);
}

void
remote_quit_handler(int num)
{
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

    if (el != NULL) el_end(el);
    if (el_hist != NULL) history_end(el_hist);

    el = el_init("Isaac", stdin, stdout, stderr);
    el_set(el, EL_PROMPT, remote_prompt);
    el_set(el, EL_EDITMODE, 1);
    el_set(el, EL_EDITOR, editor);
    el_hist = history_init();
    if (!el || !el_hist) return -1;

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
    el_set(el, EL_BIND, "\\e[3~", "ed-delete-next-char", NULL);
    // Bind Home and End to move to line start and end
    el_set(el, EL_BIND, "\\e[1~", "ed-move-to-beg", NULL);
    el_set(el, EL_BIND, "\\e[4~", "ed-move-to-end", NULL);
    // Bind C-left and C-right to move by word (not all terminals)
    el_set(el, EL_BIND, "\\eOC", "vi-next-word", NULL);
    el_set(el, EL_BIND, "\\eOD", "vi-prev-word", NULL);

    // Check if there is a resource file for editline
    if (editrc) el_source(el, editrc);

    return 0;
}

int
remote_el_write_history(char *filename)
{
    HistEvent ev;

    if (el_hist == NULL || el == NULL) remote_el_initialize();

    return (history(el_hist, &ev, H_SAVE, filename));
}

int
remote_el_read_history(char *filename)
{
    HistEvent ev = {
            0 };

    if (el_hist == NULL || el == NULL) remote_el_initialize();
    return (history(el_hist, &ev, H_LOAD, filename));
}

int
remote_el_read_char(EditLine *editline, char *cp)
{
    int num_read = 0;
    int lastpos = 0;
    struct pollfd fds[2];
    int res;
    int max;
    char buf[EL_BUF_SIZE];

    for (;;) {
        if (sig_flags.need_quit || sig_flags.need_quit_handler) break;

        max = 1;
        fds[0].fd = remote_cli->fd;
        fds[0].events = POLLIN;
        fds[1].fd = STDIN_FILENO;
        fds[1].events = POLLIN;
        res = poll(fds, 2, -1);

        pthread_mutex_lock(&remote_cli->lock);
        pthread_mutex_unlock(&remote_cli->lock);
        if (res < 0) {
            if (errno == EINTR) continue;
            isaac_log(LOG_ERROR, "poll failed: %s\n", strerror(errno));
            break;
        }

        if (fds[1].revents) {
            num_read = read(STDIN_FILENO, cp, 1);
            if (num_read < 1) {
                break;
            } else
                return (num_read);
        }
        if (fds[0].revents) {
            char *tmp;
            res = read(remote_cli->fd, buf, sizeof(buf) - 1);
            /* if the remote side disappears exit */
            if (res < 1) {
                remote_quit_handler(0);
                continue;
            }
            buf[res] = '\0';

            /* Strip preamble from asynchronous events, too */
            for (tmp = buf; *tmp; tmp++) {
                if (*tmp == 127) {
                    memmove(tmp, tmp + 1, strlen(tmp));
                    tmp--;
                    res--;
                }
            }

            /* Write over the CLI prompt */
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
                return (1);
            } else
                lastpos = 1;
        }
    }

    *cp = '\0';
    return (0);
}

char **
remote_el_strtoarr(char *buf)
{
    char **match_list = NULL, **match_list_tmp, *retstr;
    size_t match_list_len;
    int matches = 0;

    match_list_len = 1;
    while ((retstr = strsep(&buf, " ")) != NULL) {

        if (!strcmp(retstr, AST_CLI_COMPLETE_EOF)) break;
        if (matches + 1 >= match_list_len) {
            match_list_len <<= 1;
            if ((match_list_tmp = realloc(match_list, match_list_len * sizeof(char *)))) {
                match_list = match_list_tmp;
            } else {
                if (match_list) isaac_free(match_list);
                return (char **) NULL;
            }
        }

        match_list[matches++] = strdup(retstr);
    }

    if (!match_list) return (char **) NULL;

    if (matches >= match_list_len) {
        if ((match_list_tmp = realloc(match_list, (match_list_len + 1) * sizeof(char *)))) {
            match_list = match_list_tmp;
        } else {
            if (match_list) isaac_free(match_list);
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

