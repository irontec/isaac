/******************************************************************************
 **
 ** Copyright (C) 2011-2012 Irontec SL. All rights reserved.
 **
 ** This file may be used under the terms of the GNU General Public
 ** License version 3.0 as published by the Free Software Foundation
 ** and appearing in the file LICENSE.GPL included in the packaging of
 ** this file.  Please review the following information to ensure GNU
 ** General Public Licensing requirements will be met:
 **
 ** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
 ** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 **
 ******************************************************************************/
/**
 * \file cli.c
 * \author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * \brief Source code for functions defined in cli.h
 */

#include "isaac.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <ctype.h>
#include <unistd.h>
#include "util.h"
#include "log.h"
#include "cli.h"
#include "remote.h"
#include "session.h"

//! Incoming CLI clients linked list
struct isaac_cli *clilist = NULL;
//! Lock for concurrent access to \ref clilist "CLI client list"
pthread_mutex_t clilock;
//! Linked list of available CLI commands an their handleds
struct isaac_cli_entry *entries = NULL;
//! Lock for concurrent access to \ref entries "CLI commands list"
pthread_mutex_t entrieslock;
/// Thread for accepting new CLI client connections
/** Launched at \ref cli_server_start */
pthread_t accept_t;
//! Socket for accepting new CLI client connections
int isaac_sock;

//! Startup time defined in \ref main.c
extern struct timeval isaac_startuptime;
/// Binary running in CLI client mode flag.
/** Flag defined in \ref main.c to determine if binary is being executed as CLI client. */
extern int opt_remote;

/**
 * \brief Satelite list with all default CLI commands
 *
 * This linked list will have the CLI some core commands using
 * \ref AST_CLI_DEFINE macro.
 * This commands are added into the \ref entries "CLI command list" when
 * CLI servers starts using \ref isaac_cli_register_multiple
 */
static struct isaac_cli_entry cli_cli[] = {
        AST_CLI_DEFINE(handle_commandcomplete, "Internal use: Complete"),
        AST_CLI_DEFINE(handle_commandmatchesarray, "Internal use: Match Array"),
        AST_CLI_DEFINE(handle_commandnummatches, "Internal use: Match Array"),
        AST_CLI_DEFINE(handle_core_show_version, "Show Isaac version"),
        AST_CLI_DEFINE(handle_core_show_uptime, "Show Isaac uptime"),
        AST_CLI_DEFINE(handle_show_connections, "Show connected sessions"),
        AST_CLI_DEFINE(handle_kill_connection, "Stops a connected session"),
        AST_CLI_DEFINE(handle_debug_connection, "Mark debug flag to a connected session") };

//! Some regexp characters in cli arguments are reserved and used as separators.
static const char cli_rsvd[] = "[]{}|*%";

/******************************************************************************
 *****************************************************************************/
int
cli_server_start()
{
    struct sockaddr_un sunaddr;
    pthread_attr_t attr;

    /** Create a new Local socket for incoming connections */
    if ((isaac_sock = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
        isaac_log(LOG_ERROR, "Cannot create listener socket!: %s\n", strerror(errno));
        return -1;
    }
    memset(&sunaddr, 0, sizeof(sunaddr));
    sunaddr.sun_family = AF_LOCAL;
    strcpy(sunaddr.sun_path, CLI_SOCKET);

    // fixme Drop socket before starting. When ISC crashes it leaves the socket binded.
    unlink(CLI_SOCKET);

    /** Bind socket to local address */
    if (bind(isaac_sock, (struct sockaddr *) &sunaddr, sizeof(sunaddr)) < 0) {
        isaac_log(LOG_ERROR, "Cannot bind to listener socket!: %s\n", strerror(errno));
        return -1;
    }

    /** Open the socket to new incoming connections */
    if (listen(isaac_sock, 5) < 0) {
        fprintf(stderr, "Cannot listen on socket!\n");
        return -1;
    }
    isaac_log(LOG_VERBOSE_1, "CLI Server Started.\n");

    /** Register Core commands */
    isaac_cli_register_multiple(cli_cli, ARRAY_LEN(cli_cli));

    /** Start Accept connections thread */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&accept_t, &attr, (void *) cli_accept, NULL)) {
        fprintf(stderr, "Unable to create CLI Thread!\n");
    }
    pthread_attr_destroy(&attr);
    return 0;
}

/*****************************************************************************/
void
cli_server_stop()
{
    /** Avoid new incoming connections **/
    close(isaac_sock);
    unlink(CLI_SOCKET);
    /** Look for the current client in the client list **/
    while (clilist) {
        cli_destroy(clilist);
    }
    /** Destroy Listening thread */
    pthread_cancel(accept_t);
    //isaac_log(LOG_VERBOSE_1, "CLI Server stoped.\n");
}

/*****************************************************************************/
void
cli_accept()
{
    struct sockaddr_un sun;
    socklen_t sunlen;
    pthread_attr_t attr;
    struct isaac_cli *c;
    struct pollfd fds[1];
    int s;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    for (;;) {
        if (isaac_sock < 0) return;

        fds[0].fd = isaac_sock;
        fds[0].events = POLLIN;
        if ((s = poll(fds, 1, -1)) < 0) {
            if (errno != EINTR) isaac_log(LOG_WARNING, "Poll returned error: %s\n", strerror(errno));
            continue;
        }

        sunlen = sizeof(sun);
        if ((s = accept(isaac_sock, (struct sockaddr *) &sun, &sunlen)) < 0) {
            isaac_log(LOG_ERROR, "Accept returned -1: %s\n", strerror(errno));
            continue;
        }
        isaac_log(LOG_VERBOSE, "Remote UNIX connection\n");
        int sckopt = 1;
        if (setsockopt(s, SOL_SOCKET, SO_PASSCRED, &sckopt, sizeof(sckopt)) < 0) {
            isaac_log(LOG_WARNING, "Unable to turn on socket credentials passing\n");
            continue;
        }

        /** Reserve memory for this client **/
        if (!(c = malloc(sizeof(struct isaac_cli)))) {
            isaac_log(LOG_ERROR, "Failed to allocate client manager: %s\n", strerror(errno));
            continue;
        }

        /** Copy all required data to this client **/
        memset(c, 0, sizeof(struct isaac_cli));
        memcpy(&c->sun, &sun, sizeof(sun)); // Address Data
        pthread_mutex_init(&c->lock, NULL); // Lock
        c->fd = s; // File Descriptor

        /** Add client to the client list **/
        pthread_mutex_lock(&clilock);
        c->next = clilist;
        clilist = c;
        pthread_mutex_unlock(&clilock);

        if (pthread_create(&c->t, &attr, (void *) cli_do, c)) cli_destroy(c);
    }
    pthread_attr_destroy(&attr);
    return;
}

/*****************************************************************************/
void *
cli_do(struct isaac_cli *c)
{
    char command[256];
    int rbytes;

    for (;;) {
        /** Read requested data **/
        if ((rbytes = cli_read(c->fd, command)) <= 0) {
            break;
        }
        if (strncmp(command, "cli quit after ", 15) == 0) {
            isaac_cli_command_multiple_full(c->fd, rbytes - 15, command + 15);
            break;
        }
        isaac_cli_command_multiple_full(c->fd, rbytes, command);
    }
    cli_destroy(c);
    pthread_exit(NULL);
    return NULL;
}

/*****************************************************************************/
void
cli_destroy(struct isaac_cli *c)
{
    struct isaac_cli *cur, *prev = NULL;

    // todo Do this with an iterator
    pthread_mutex_lock(&clilock);
    cur = clilist;
    /** Look for the current client in the client list **/
    while (cur) {
        if (cur == c) {
            // Update CLI list
            if (prev) prev->next = cur->next;
            else
                clilist = cur->next;
            break;
        }
        prev = cur;
        cur = cur->next;
    }
    pthread_mutex_unlock(&clilock); // We have finished with the list

    if (cur) {
        // This message won't be notify to current isaac_cli cause it's no longer
        // in the cli list
        isaac_log(LOG_VERBOSE, "Remote UNIX connection disconnected\n");
        /** Destroy the client data **/
        close(c->fd);
        pthread_cancel(c->t);
        pthread_mutex_destroy(&c->lock);
        free(c);
    } else {
        // This should happen!!
        isaac_log(LOG_ERROR, "Trying to destroy non-existent CLI: %d\n", c->fd);
    }
}

/*****************************************************************************/
int
cli_read(int fd, char* readed)
{
    bzero(readed, 256);
    return read(fd, readed, 255);
}

/*****************************************************************************/
int
cli_write(int fd, const char *fmt, ...)
{
    char message[MAX_MSG_SIZE];
    va_list ap;

    va_start(ap, fmt);
    vsprintf(message, fmt, ap);
    va_end(ap);

    return write(fd, message, isaac_strlen(message) + 1);
}

/*****************************************************************************/
void
write_clis(const char *climsg)
{
    struct isaac_cli *cur;
    /* Write to clients **/
    for (cur = clilist; cur; cur = cur->next) {
        pthread_mutex_lock(&cur->lock);
        cli_write(cur->fd, climsg);
        //usleep(100); //fixme why?
        pthread_mutex_unlock(&cur->lock);
    }
}

/*****************************************************************************/
int
isaac_cli_register(struct isaac_cli_entry *e)
{
    int i;
    struct isaac_cli_args a; /* fake argument */
    char **dst = (char **) e->cmda; /* need to cast as the entry is readonly */
    char *s;

    memset(&a, '\0', sizeof(a));
    e->handler(e, CLI_INIT, &a);
    /* XXX check that usage and command are filled up */
    s = isaac_skip_blanks(e->command);
    s = e->command = strdup(s);
    for (i = 0; !isaac_strlen_zero(s) && i < 100 - 1; i++) {
        *dst++ = s; /* store string */
        s = isaac_skip_nonblanks(s);
        if (*s == '\0') /* we are done */
        break;
        *s++ = '\0';
        s = isaac_skip_blanks(s);
    }
    *dst++ = NULL;

    /** Check if already has been registered **/
    if (find_cli(e->cmda, 1)) {
        isaac_log(LOG_WARNING, "Command '%s' already registered (or something close enough)\n",
                (e->_full_cmd) ? e->_full_cmd : e->command);
        return -1;
    }
    if (set_full_cmd(e)) return -1;

    /** Push this entry in the top of the list */
    pthread_mutex_lock(&entrieslock);
    e->next = entries;
    entries = e;
    pthread_mutex_unlock(&entrieslock);

    isaac_log(LOG_VERBOSE_2, "Registered command '%s'\n", e->_full_cmd);
    return 0;
}

/*****************************************************************************/
int
isaac_cli_register_multiple(struct isaac_cli_entry *e, int len)
{
    int i, res = 0;
    for (i = 0; i < len; i++)
        res |= isaac_cli_register(e + i);
    return res;
}

/*****************************************************************************/
int
set_full_cmd(struct isaac_cli_entry *e)
{
    int i;
    char buf[80];

    /** Build the Full command field from Command Array **/
    isaac_join(buf, sizeof(buf), e->cmda);
    e->_full_cmd = strdup(buf);
    if (!e->_full_cmd) {
        isaac_log(LOG_WARNING, "-- cannot allocate <%s>\n", buf);
        return -1;
    }
    /** Return the comman part avoiding the Arguments **/
    e->cmdlen = strcspn(e->_full_cmd, cli_rsvd);
    for (i = 0; e->cmda[i]; i++)
        ;
    e->args = i;
    return 0;
}

/*****************************************************************************/
int
word_match(const char *cmd, const char *cli_word)
{
    int l;
    char *pos;
    if (isaac_strlen_zero(cmd) || isaac_strlen_zero(cli_word)) return -1;
    if (!strchr(cli_rsvd, cli_word[0])) /* normal match */
    return (strcasecmp(cmd, cli_word) == 0) ? 1 : -1;
    /* regexp match, takes [foo|bar] or {foo|bar} */
    l = strlen(cmd);
    /* wildcard match - will extend in the future */
    if (l > 0 && cli_word[0] == '%') {
        return 1; /* wildcard */
    }
    //FIXME pos = strcasestr(cli_word, cmd);
    pos = strstr(cli_word, cmd);
    if (pos == NULL) /* not found, say ok if optional */
    return cli_word[0] == '[' ? 0 : -1;
    if (pos == cli_word) /* no valid match at the beginning */
    return -1;
    if (strchr(cli_rsvd, pos[-1]) && strchr(cli_rsvd, pos[l])) return 1; /* valid match */
    return -1; /* not found */
}

/*****************************************************************************/
struct isaac_cli_entry *
find_cli(const char * const cmds[], int match_type)
{
    int matchlen = -1; /* length of longest match so far */
    struct isaac_cli_entry *cand = NULL, *e = NULL;

    for (e = entries; e; e = e->next) {

        /* word-by word regexp comparison *//* word-by word regexp comparison */
        const char * const *src = cmds;
        const char * const *dst = e->cmda;
        int n = 0;
        for (;; dst++, src += n) {
            n = word_match(*src, *dst);
            if (n < 0) break;
        }
        if (isaac_strlen_zero(*dst) || ((*dst)[0] == '[' && isaac_strlen_zero(dst[1]))) {
            /* no more words in 'e' */
            if (isaac_strlen_zero(*src)) /* exact match, cannot do better */
            break;
            /* Here, cmds has more words than the entry 'e' */
            if (match_type != 0) /* but we look for almost exact match... */
            continue; /* so we skip this one. */
            /* otherwise we like it (case 0) */
        } else { /* still words in 'e' */
            if (isaac_strlen_zero(*src)) continue; /* cmds is shorter than 'e', not good */
            /* Here we have leftover words in cmds and 'e',
             * but there is a mismatch. We only accept this one if match_type == -1
             * and this is the last word for both.
             */
            if (match_type != -1 || !isaac_strlen_zero(src[1]) || !isaac_strlen_zero(dst[1])) /* not the one we look for */
            continue;
            /* good, we are in case match_type == -1 and mismatch on last word */
        }
        if (src - cmds > matchlen) { /* remember the candidate */
            matchlen = src - cmds;
            cand = e;
        }

    }

    return e ? e : cand;
}

/*****************************************************************************/
char *
complete_number(const char *partial, unsigned int min, unsigned int max, int n)
{
    int i, count = 0;
    unsigned int prospective[2];
    unsigned int part = strtoul(partial, NULL, 10);
    char next[12];

    if (part < min || part > max) {
        return NULL;
    }

    for (i = 0; i < 21; i++) {
        if (i == 0) {
            prospective[0] = prospective[1] = part;
        } else if (part == 0 && !isaac_strlen_zero(partial)) {
            break;
        } else if (i < 11) {
            prospective[0] = prospective[1] = part * 10 + (i - 1);
        } else {
            prospective[0] = (part * 10 + (i - 11)) * 10;
            prospective[1] = prospective[0] + 9;
        }
        if (i < 11 && (prospective[0] < min || prospective[0] > max)) {
            continue;
        } else if (prospective[1] < min || prospective[0] > max) {
            continue;
        }

        if (++count > n) {
            if (i < 11) {
                snprintf(next, sizeof(next), "%u", prospective[0]);
            } else {
                snprintf(next, sizeof(next), "%u...", prospective[0] / 10);
            }
            return strdup(next);
        }
    }
    return NULL;
}

/*****************************************************************************/
char *
parse_args(const char *s, int *argc, const char *argv[], int max, int *trailingwhitespace)
{
    char *duplicate, *cur;
    int x = 0;
    int quoted = 0;
    int escaped = 0;
    int whitespace = 1;
    int dummy = 0;

    if (trailingwhitespace == NULL) trailingwhitespace = &dummy;
    *trailingwhitespace = 0;
    if (s == NULL) /* invalid, though! */
    return NULL;
    /* make a copy to store the parsed string */
    if (!(duplicate = strdup(s))) return NULL;

    cur = duplicate;
    /* scan the original string copying into cur when needed */
    for (; *s; s++) {
        if (x >= max - 1) {
            isaac_log(LOG_WARNING, "Too many arguments, truncating at %s\n", s);
            break;
        }
        if (*s == '"' && !escaped) {
            quoted = !quoted;
            if (quoted && whitespace) {
                /* start a quoted string from previous whitespace: new argument */
                argv[x++] = cur;
                whitespace = 0;
            }
        } else if ((*s == ' ' || *s == '\t') && !(quoted || escaped)) {
            /* If we are not already in whitespace, and not in a quoted string or
             processing an escape sequence, and just entered whitespace, then
             finalize the previous argument and remember that we are in whitespace
             */
            if (!whitespace) {
                *cur++ = '\0';
                whitespace = 1;
            }
        } else if (*s == '\\' && !escaped) {
            escaped = 1;
        } else {
            if (whitespace) {
                /* we leave whitespace, and are not quoted. So it's a new argument */
                argv[x++] = cur;
                whitespace = 0;
            }
            *cur++ = *s;
            escaped = 0;
        }
    }
    /* Null terminate */
    *cur++ = '\0';
    /* XXX put a NULL in the last argument, because some functions that take
     * the array may want a null-terminated array.
     * argc still reflects the number of non-NULL entries.
     */
    argv[x] = NULL;
    *argc = x;
    *trailingwhitespace = whitespace;
    return duplicate;
}

/*****************************************************************************/
char *
find_best(const char *argv[])
{
    static char cmdline[80];
    int x;
    /* See how close we get, then print the candidate */
    const char *myargv[400] = {
            NULL, };

    for (x = 0; argv[x]; x++) {
        myargv[x] = argv[x];
        if (!find_cli(myargv, -1)) break;
    }
    isaac_join(cmdline, sizeof(cmdline), myargv);
    return cmdline;
}

/*****************************************************************************/
int
isaac_cli_command_full(int fd, const char *s)
{
    const char *args[AST_MAX_ARGS + 1];
    struct isaac_cli_entry *e;
    int x;
    char *duplicate = parse_args(s, &x, args + 1, AST_MAX_ARGS, NULL);
    char *retval = NULL;
    struct isaac_cli_args a = {
            .fd = fd,
            .argc = x,
            .argv = args+1 };

    if (duplicate == NULL) return -1;

    if (x < 1) /* We need at least one entry, otherwise ignore */
    goto done;

    e = find_cli(args + 1, 0);
    if (e == NULL) {
        isaac_cli(fd,
                "\rNo such command '%s' (type 'core show help %s' for other possible commands)\n",
                s, find_best(args + 1));
        goto done;
    }

    /* Within the handler, argv[-1] contains a pointer to the isaac_cli_entry.
     * Remember that the array returned by parse_args is NULL-terminated.
     */
    args[0] = (char *) e;

    retval = e->handler(e, CLI_HANDLER, &a);

    if (retval == CLI_SHOWUSAGE) {
        isaac_cli(fd, "%s", (e->usage) ? e->usage
                : "Invalid usage, but no usage information available.\n");
    } else {
        if (retval == CLI_FAILURE) isaac_cli(fd, "Command '%s' failed.\n", s);
    }
    done: free(duplicate);
    return 0;
}

/*****************************************************************************/
int
isaac_cli_command_multiple_full(int fd, size_t size, const char *s)
{
    char cmd[512];
    int x, y = 0, count = 0;

    for (x = 0; x < size; x++) {
        cmd[y] = s[x];
        y++;
        if (s[x] == '\0') {
            isaac_cli_command_full(fd, cmd);
            y = 0;
            count++;
        }
    }
    return count;
}

/*****************************************************************************/
/*! \brief if word is a valid prefix for token, returns the pos-th
 * match as a malloced string, or NULL otherwise.
 * Always tell in *actual how many matches we got.
 */
char *
is_prefix(const char *word, const char *token, int pos, int *actual)
{
    int lw;
    char *s, *t1;

    *actual = 0;
    if (isaac_strlen_zero(token)) return NULL;
    if (isaac_strlen_zero(word)) word = ""; /* dummy */
    lw = strlen(word);
    if (strcspn(word, cli_rsvd) != lw) return NULL; /* no match if word has reserved chars */
    if (strchr(cli_rsvd, token[0]) == NULL) { /* regular match */
        if (strncasecmp(token, word, lw)) /* no match */
        return NULL;
        *actual = 1;
        return (pos != 0) ? NULL : strdup(token);
    }
    /* now handle regexp match */

    /* Wildcard always matches, so we never do is_prefix on them */

    t1 = strdup(token + 1); /* copy, skipping first char */
    while (pos >= 0 && (s = strsep(&t1, cli_rsvd)) && *s) {
        if (*s == '%') /* wildcard */
        continue;
        if (strncasecmp(s, word, lw)) /* no match */
        continue;
        (*actual)++;
        if (pos-- == 0) return strdup(s);
    }
    return NULL;
}

/*****************************************************************************/
int
more_words(const char * const *dst)
{
    int i;
    for (i = 0; dst[i]; i++) {
        if (dst[i][0] != '[') return -1;
    }
    return 0;
}

/*****************************************************************************/
/*
 * generate the entry at position 'state'
 */
char *
isaac_cli_generator(const char *text, const char *word, int state)
{
    const char *argv[AST_MAX_ARGS];
    struct isaac_cli_entry *e = NULL;
    int x = 0, argindex, matchlen;
    int matchnum = 0;
    char *ret = NULL;
    char matchstr[80] = "";
    int tws = 0;

    /* Split the argument into an array of words */
    char *duplicate = parse_args(text, &x, argv, ARRAY_LEN(argv), &tws);

    if (!duplicate) /* malloc error */
    return NULL;

    /* Compute the index of the last argument (could be an empty string) */
    argindex = (!isaac_strlen_zero(word) && x > 0) ? x - 1 : x;

    /* rebuild the command, ignore terminating white space and flatten space */
    isaac_join(matchstr, sizeof(matchstr) - 1, argv);
    matchlen = strlen(matchstr);
    if (tws) {
        strcat(matchstr, " "); /* XXX */
        if (matchlen) matchlen++;
    }
    for (e = entries; e; e = e->next) {
        /* XXX repeated code */
        int src = 0, dst = 0, n = 0;

        /** Skip internal commands **/
        if (e->command[0] == '_') continue;

        /*
         * Try to match words, up to and excluding the last word, which
         * is either a blank or something that we want to extend.
         */
        for (; src < argindex; dst++, src += n) {
            n = word_match(argv[src], e->cmda[dst]);
            if (n < 0) break;
        }

        if (src != argindex && more_words(e->cmda + dst)) /* not a match */
        continue;
        ret = is_prefix(argv[src], e->cmda[dst], state - matchnum, &n);
        matchnum += n; /* this many matches here */
        if (ret) {
            /*
             * argv[src] is a valid prefix of the next word in this
             * command. If this is also the correct entry, return it.
             */
            if (matchnum > state) break;
            free(ret);
            ret = NULL;
        } else if (isaac_strlen_zero(e->cmda[dst])) {
            /*
             * This entry is a prefix of the command string entered
             * (only one entry in the list should have this property).
             * Run the generator if one is available. In any case we are done.
             */
            if (e->handler) { /* new style command */
                struct isaac_cli_args a = {
                        .line = matchstr,
                        .word = word,
                        .pos = argindex,
                        .n = state - matchnum,
                        .argv = argv,
                        .argc = x };
                ret = e->handler(e, CLI_GENERATE, &a);
            }
            if (ret) break;
        }
    }
    free(duplicate);
    return ret;
}

/*****************************************************************************/
/*! \brief Return the number of unique matches for the generator */
int
isaac_cli_generatornummatches(const char *text, const char *word)
{
    int matches = 0, i = 0;
    char *buf = NULL, *oldbuf = NULL;

    while ((buf = isaac_cli_generator(text, word, i++))) {
        if (!oldbuf || strcmp(buf, oldbuf)) matches++;
        if (oldbuf) free(oldbuf);
        oldbuf = buf;
    }
    if (oldbuf) free(oldbuf);
    return matches;
}

/*****************************************************************************/
char **
isaac_cli_completion_matches(const char *text, const char *word)
{
    char **match_list = NULL, *retstr, *prevstr;
    size_t match_list_len, max_equal, which, i;
    int matches = 0;

    /* leave entry 0 free for the longest common substring */
    match_list_len = 1;
    while ((retstr = isaac_cli_generator(text, word, matches)) != NULL) {
        if (matches + 1 >= match_list_len) {
            match_list_len <<= 1;
            if (!(match_list = realloc(match_list, match_list_len * sizeof(*match_list)))) return NULL;
        }
        match_list[++matches] = retstr;
    }

    if (!match_list) return match_list; /* NULL */

    /* Find the longest substring that is common to all results
     * (it is a candidate for completion), and store a copy in entry 0.
     */
    prevstr = match_list[1];
    max_equal = strlen(prevstr);
    for (which = 2; which <= matches; which++) {
        for (i = 0; i <= max_equal; i++) {
            if (prevstr[i] != match_list[which][i]) {
                max_equal = i - 1;
                break;
            }
        }
    }

    if (!(retstr = malloc(max_equal + 1))) return NULL;

    isaac_strncpy(retstr, match_list[1], max_equal + 1);
    match_list[0] = retstr;

    /* ensure that the array is NULL terminated */
    if (matches + 1 >= match_list_len) {
        if (!(match_list = realloc(match_list, (match_list_len + 1) * sizeof(*match_list)))) return NULL;
    }
    match_list[matches + 1] = NULL;

    return match_list;
}

/*****************************************************************************/
void
print_uptimestr(struct timeval timeval, int printsec, char *out)
{
    int x; /* the main part - years, weeks, etc. */
    char year[256] = "", week[256] = "", day[256] = "", hour[256] = "", minute[256] = "";
#define SECOND (1)
#define MINUTE (SECOND*60)
#define HOUR (MINUTE*60)
#define DAY (HOUR*24)
#define WEEK (DAY*7)
#define YEAR (DAY*365)
#define NEEDCOMMA(x) ((x)? ",": "") /* define if we need a comma */
#define ESS(x) ((x>1)? "s": "")		/* define if we need final s in descriptors */

    if (timeval.tv_sec < 0) /* invalid, nothing to show */
    return;

    if (printsec) { /* plain seconds output */
        sprintf(out, "%lu", (u_long) timeval.tv_sec);
        return;
    }
    if (timeval.tv_sec > YEAR) {
        x = (timeval.tv_sec / YEAR);
        timeval.tv_sec -= (x * YEAR);
        sprintf(year, " %d year%s%s", x, ESS(x), NEEDCOMMA(timeval.tv_sec));
    }
    if (timeval.tv_sec > WEEK) {
        x = (timeval.tv_sec / WEEK);
        timeval.tv_sec -= (x * WEEK);
        sprintf(week, " %d week%s%s", x, ESS(x), NEEDCOMMA(timeval.tv_sec));
    }
    if (timeval.tv_sec > DAY) {
        x = (timeval.tv_sec / DAY);
        timeval.tv_sec -= (x * DAY);
        sprintf(day, " %d day%s%s", x, ESS(x), NEEDCOMMA(timeval.tv_sec));
    }
    if (timeval.tv_sec > HOUR) {
        x = (timeval.tv_sec / HOUR);
        timeval.tv_sec -= (x * HOUR);
        sprintf(hour, " %d hour%s%s", x, ESS(x), NEEDCOMMA(timeval.tv_sec));
    }
    if (timeval.tv_sec > MINUTE) {
        x = (timeval.tv_sec / MINUTE);
        timeval.tv_sec -= (x * MINUTE);
        sprintf(minute, " %d minute%s%s", x, ESS(x), NEEDCOMMA(timeval.tv_sec));
    }

    x = timeval.tv_sec;
    sprintf(out, "%s%s%s%s%s %d second%s ", year, week, day, hour, minute, x, ESS(x));
}

/*****************************************************************************/
/*****************************************************************************/
char *
isaac_complete_session(const char *line, const char *word, int pos, int state, int rpos)
{
    int which = 0;
    char notfound = '\0';
    char *ret = &notfound; /* so NULL can break the loop */
    session_iter_t *iter;
    session_t *s;

    if (pos != rpos) {
        return NULL;
    }

    //if (isaac_strlen_zero(word)) {
    iter = session_iterator_new();
    //} else {
    //  iter = satelite_iterator_by_name_new(word, strlen(word));
    //}
    while (ret == &notfound && (s = session_iterator_next(iter))) {
        if (++which > state) {
            ret = s->id;
        }
    }
    session_iterator_destroy(iter);
    return ret == &notfound ? NULL : ret;
}

/******************************************************************************
 *****************************************************************************/
char *
handle_commandmatchesarray(struct isaac_cli_entry *e, int cmd, struct isaac_cli_args *a)
{
    char *buf, *obuf;
    int buflen = 2048;
    int len = 0;
    char **matches;
    int x, matchlen;

    switch (cmd) {
    case CLI_INIT:
        e->command = "_command matchesarray";
        e->usage = "Usage: _command matchesarray \"<line>\" text \n"
            "       This function is used internally to help with command completion and should.\n"
            "       never be called by the user directly.\n";
        return NULL;
    case CLI_GENERATE:
        return NULL;
    }

    if (a->argc != 4) return CLI_SHOWUSAGE;
    if (!(buf = malloc(buflen))) return CLI_FAILURE;
    buf[len] = '\0';
    matches = isaac_cli_completion_matches(a->argv[2], a->argv[3]);
    if (matches) {
        for (x = 0; matches[x]; x++) {
            matchlen = strlen(matches[x]) + 1;
            if (len + matchlen >= buflen) {
                buflen += matchlen * 3;
                obuf = buf;
                if (!(buf = realloc(obuf, buflen)))
                /* Memory allocation failure...  Just free old buffer and be done */
                free(obuf);
            }
            if (buf) len += sprintf(buf + len, "%s ", matches[x]);
            free(matches[x]);
            matches[x] = NULL;
        }
        free(matches);
    }

    if (buf) {
        isaac_cli(a->fd, "%s%s", buf, AST_CLI_COMPLETE_EOF);
        free(buf);
    } else
        isaac_cli(a->fd, "NULL\n");

    return CLI_SUCCESS;
}

/*****************************************************************************/
char *
handle_commandcomplete(struct isaac_cli_entry *e, int cmd, struct isaac_cli_args *a)
{
    char *buf;
    switch (cmd) {
    case CLI_INIT:
        e->command = "_command complete";
        e->usage = "Usage: _command complete \"<line>\" text state\n"
            "       This function is used internally to help with command completion and should.\n"
            "       never be called by the user directly.\n";
        return NULL;
    case CLI_GENERATE:
        return NULL;
    }
    if (a->argc != 5) return CLI_SHOWUSAGE;
    buf = isaac_cli_generator(a->argv[2], a->argv[3], atoi(a->argv[4]));
    if (buf) {
        isaac_cli(a->fd, "%s", buf);
        free(buf);
    } else
        isaac_cli(a->fd, "NULL\n");
    return CLI_SUCCESS;
}

/*****************************************************************************/
char *
handle_commandnummatches(struct isaac_cli_entry *e, int cmd, struct isaac_cli_args *a)
{
    int matches = 0;

    switch (cmd) {
    case CLI_INIT:
        e->command = "_command nummatches";
        e->usage = "Usage: _command nummatches \"<line>\" text \n"
            "       This function is used internally to help with command completion and should.\n"
            "       never be called by the user directly.\n";
        return NULL;
    case CLI_GENERATE:
        return NULL;
    }

    if (a->argc != 4) return CLI_SHOWUSAGE;

    matches = isaac_cli_generatornummatches(a->argv[2], a->argv[3]);

    isaac_cli(a->fd, "%d", matches);

    return CLI_SUCCESS;
}

/*****************************************************************************/
/*! \brief Give how much this IronSC has been up and running */
char *
handle_core_show_uptime(struct isaac_cli_entry *e, int cmd, struct isaac_cli_args *a)
{
    struct timeval curtime = isaac_tvnow();
    int printsec;
    char out[256];

    switch (cmd) {
    case CLI_INIT:
        e->command = "core show uptime [seconds]";
        e->usage = "Usage: core show uptime [seconds]\n"
            "       Shows Isaac uptime information.\n"
            "       The seconds word returns the uptime in seconds only.\n";
        return NULL;

    case CLI_GENERATE:
        return NULL;
    }

    /* regular handler */
    if (a->argc == e->args && !strcasecmp(a->argv[e->args - 1], "seconds")) printsec = 1;
    else if (a->argc == e->args - 1) printsec = 0;
    else
        return CLI_SHOWUSAGE;

    if (isaac_startuptime.tv_sec) {
        print_uptimestr(isaac_tvsub(curtime, isaac_startuptime), printsec, out);
        isaac_cli(a->fd, "\r%s: %s\n", "System uptime", out);
    }

    return CLI_SUCCESS;

}

/*****************************************************************************/
char *
handle_core_show_version(struct isaac_cli_entry *e, int cmd, struct isaac_cli_args *a)
{

    switch (cmd) {
    case CLI_INIT:
        e->command = "core show version";
        e->usage = "Usage: core show version\n"
            "       Show  Isaac version";
        return NULL;
    case CLI_GENERATE:
        return NULL;
    }

    /* Pirnt a welcome message */
    isaac_cli(a->fd, "%s v%s\n", APP_LNAME, APP_VERSION);

    return CLI_SUCCESS;
}

/*****************************************************************************/
char *
handle_show_connections(struct isaac_cli_entry *e, int cmd, struct isaac_cli_args *a)
{
    int sessioncnt = 0;
    struct timeval curtime = isaac_tvnow();
    char idle[256];

    switch (cmd) {
    case CLI_INIT:
        e->command = "show connections";
        e->usage = "Usage: show connections\n"
            "       Show connected session";
        return NULL;
    case CLI_GENERATE:
        return NULL;
    }

    /* Avoid other output for this cli */
    pthread_mutex_lock(&clilock);

    /* Print header for satelites */
    isaac_cli(a->fd, "%-10s%-25s%-20s%s\n", "ID", "Address", "Logged as", "Idle");

    session_iter_t *iter = session_iterator_new();
    session_t *sess;

    /* Print available satelites */
    while ((sess = session_iterator_next(iter))) {
        sessioncnt++;
        print_uptimestr(isaac_tvsub(curtime, sess->last_cmd_time), 1, idle);
        isaac_cli(a->fd, "%-10s%-25s%-20s%s\n", sess->id, sess->addrstr, ((session_test_flag(sess,
                SESS_FLAG_AUTHENTICATED)) ? session_get_variable(sess, "AGENT") : "not logged"),
                idle);
    }

    isaac_cli(a->fd, "%d active sessions.\n", sessioncnt);
    /* Destroy iterator after finishing */
    session_iterator_destroy(iter);

    /* Set cli output unlocked */
    pthread_mutex_unlock(&clilock);

    return CLI_SUCCESS;
}

/*****************************************************************************/
char *
handle_kill_connection(struct isaac_cli_entry *e, int cmd, struct isaac_cli_args *a)
{
    session_t *sess;
    switch (cmd) {
    case CLI_INIT:
        e->command = "kill connection";
        e->usage = "Usage: kill connection [sessionid]\n"
            "       Kill a session connection\n";
        return NULL;
    case CLI_GENERATE:
        if (a->pos == 2) {
            return isaac_complete_session(a->line, a->word, a->pos, a->n, 1);
        }
        return NULL;
    }

    /* Inform all required parameters */
    if (a->argc != 3) {
        return CLI_SHOWUSAGE;
    }

    /* Get satelite */
    if (!(sess = session_by_id(a->argv[2]))) {
        isaac_cli(a->fd, "Unable to find session with id %s\n", a->argv[2]);
    } else {
        session_write(sess, "BYE Connection killed from CLI\r\n");
        session_finish(sess);
    }

    return CLI_SUCCESS;
}

/*****************************************************************************/
char *
handle_debug_connection(struct isaac_cli_entry *e, int cmd, struct isaac_cli_args *a)
{
    session_t *sess;
    switch (cmd) {
    case CLI_INIT:
        e->command = "debug connection";
        e->usage = "Usage: debug connection [sessionid]\n"
            "       debug a session connection\n";
        return NULL;
    case CLI_GENERATE:
        if (a->pos == 2) {
            return isaac_complete_session(a->line, a->word, a->pos, a->n, 1);
        }
        return NULL;
    }

    /* Inform all required parameters */
    if (a->argc != 3) {
        return CLI_SHOWUSAGE;
    }

    /* Get satelite */
    if (!(sess = session_by_id(a->argv[2]))) {
        isaac_cli(a->fd, "Unable to find session with id %s\n", a->argv[2]);
    } else {
        if (session_test_flag(sess, SESS_FLAG_DEBUG)) {
            session_clear_flag(sess, SESS_FLAG_DEBUG);
            isaac_log(LOG_NOTICE, "Debug on session %s \e[1;31mdisabled\e[0m.\n", a->argv[2]);
        } else {
            session_set_flag(sess, SESS_FLAG_DEBUG);
            isaac_log(LOG_NOTICE, "Debug on session %s \e[1;32menabled\e[0m.\n", a->argv[2]);
        }
    }

    return CLI_SUCCESS;

}

