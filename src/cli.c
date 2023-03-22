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
 * @file cli.c
 * @author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source code for functions defined in cli.h
 *
 * @todo Comment this file completely
 */

#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <ctype.h>
#include <unistd.h>
#include "cfg.h"
#include "cli.h"
#include "util.h"
#include "log.h"
#include "remote.h"
#include "app.h"
#include "manager.h"
#include "filter.h"

//! Incoming CLI clients linked list
cli_t *clilist = NULL;
//! Lock for concurrent access to \ref clilist "CLI client list"
pthread_mutex_t clilock;
//! Linked list of available CLI commands an their handleds
cli_entry_t *entries = NULL;
//! Lock for concurrent access to \ref entries "CLI commands list"
pthread_mutex_t entrieslock;
//! Thread for accepting new CLI client connections
pthread_t cli_accept_thread;
//! Socket for accepting new CLI client connections
int cli_sock;
//! General flag to stop cli server
static int running;
//! Starting time, used to count the uptime time
struct timeval startuptime;
// Current configuration
extern cfg_t config;

/**
 * @brief List with all default CLI commands
 *
 * This linked list will have the CLI some core commands using
 * @ref AST_CLI_DEFINE macro.
 * This commands are added into the @ref entries "CLI command list" when
 * CLI servers starts using @ref cli_register_multiple
 */
static cli_entry_t cli_entries[] = {
    AST_CLI_DEFINE(handle_commandcomplete, "Internal use: Complete"),
    AST_CLI_DEFINE(handle_commandmatchesarray, "Internal use: Match Array"),
    AST_CLI_DEFINE(handle_commandnummatches, "Internal use: Match Array"),
    AST_CLI_DEFINE(handle_core_show_version, "Show Isaac version"),
    AST_CLI_DEFINE(handle_core_show_uptime, "Show Isaac uptime"),
    AST_CLI_DEFINE(handle_core_show_settings, "Show Isaac running settings"),
    AST_CLI_DEFINE(handle_core_show_applications, "Show Isaac registered applications"),
    AST_CLI_DEFINE(handle_core_set_verbose, "Change Isaac log level"),
    AST_CLI_DEFINE(handle_show_connections, "Show connected sessions"),
    AST_CLI_DEFINE(handle_show_filters, "Show session filters"),
    AST_CLI_DEFINE(handle_show_variables, "Show session variables"),
    AST_CLI_DEFINE(handle_kill_connection, "Stops a connected session"),
    AST_CLI_DEFINE(handle_debug_connection, "Mark debug flag to a connected session")};

//! Some regexp characters in cli arguments are reserved and used as separators.
static const char cli_rsvd[] = "[]{}|*%";

int
cli_server_start()
{
    struct sockaddr_un sunaddr;

    // Create a new Local socket for incoming connections
    if ((cli_sock = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
        isaac_log(LOG_ERROR, "Cannot create listener socket!: %s\n", strerror(errno));
        return -1;
    }
    memset(&sunaddr, 0, sizeof(sunaddr));
    sunaddr.sun_family = AF_LOCAL;
    strcpy(sunaddr.sun_path, CLI_SOCKET);

    // fixme Drop socket before starting. When ISC crashes it leaves the socket binded.
    unlink(CLI_SOCKET);

    // Bind socket to local address
    if (bind(cli_sock, (struct sockaddr *) &sunaddr, sizeof(sunaddr)) < 0) {
        isaac_log(LOG_ERROR, "Cannot bind to listener socket %s!: %s\n", CLI_SOCKET, strerror(errno));
        return -1;
    }

    // Open the socket to new incoming connections
    if (listen(cli_sock, 5) < 0) {
        isaac_log(LOG_ERROR, "Cannot listen on socket!: %s\n", strerror(errno));
        return -1;
    }

    // Register Core commands
    cli_register_entry_multiple(cli_entries, ARRAY_LEN(cli_entries));

    // Start Accept connections thread
    if (pthread_create(&cli_accept_thread, NULL, (void *) cli_accept, NULL)) {
        fprintf(stderr, "Unable to create CLI Thread!\n");
    }

    return 0;
}

void
cli_server_stop()
{
    // Mark ourselfs as not running
    running = 0;

    // Stop the socket from receiving new connections
    shutdown(cli_sock, SHUT_RDWR);
    // Remove the unix socket file
    unlink(CLI_SOCKET);
    //@todo iterate here
    // Destroy all clients in client list
    while (clilist) {
        cli_destroy(clilist);
    }
    if (cli_accept_thread)
        pthread_join(cli_accept_thread, NULL);
}

void
cli_accept()
{
    struct sockaddr_un sun;
    socklen_t sunlen;
    pthread_attr_t attr;
    struct isaac_cli *cli;
    int clifd;

    // Give some feedback about us
    isaac_log(LOG_VERBOSE, "Launched cli thread [ID %ld].\n", TID);

    // Initialize stored stats
    startuptime = isaac_tvnow();

    // Mark us as running
    running = 1;

    while (running) {
        // Get the next connection
        sunlen = sizeof(sun);
        if ((clifd = accept(cli_sock, (struct sockaddr *) &sun, &sunlen)) < 0) {
            if (errno != EINVAL) {
                isaac_log(LOG_WARNING, "Error accepting new connection: %s\n", strerror(errno));
            }
            break;
        }
        isaac_log(LOG_VERBOSE, "Remote UNIX connection\n");
        int sckopt = 1;
        if (setsockopt(clifd, SOL_SOCKET, SO_PASSCRED, &sckopt, sizeof(sckopt)) < 0) {
            isaac_log(LOG_WARNING, "Unable to turn on socket credentials passing\n");
            continue;
        }
        // Create a new cli structure for this connection
        if (!(cli = cli_create(clifd, sun))) {
            continue;
        }
        // Launch cli thread in detached mode
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&cli->thread, &attr, (void *) cli_do, cli) != 0) {
            cli_destroy(cli);
        }
        pthread_attr_destroy(&attr);
    }
    isaac_log(LOG_VERBOSE, "Shutting down cli thread...\n");

    // Exit cli thread gracefully
    pthread_exit(NULL);
    return;
}

void *
cli_do(cli_t *cli)
{
    char command[256];
    int rbytes;

    for (;;) {
        if ((rbytes = cli_read(cli, command)) <= 0) {
            break;
        }
        if (strncmp(command, "cli quit after ", 15) == 0) {
            cli_command_multiple_full(cli, rbytes - 15, command + 15);
            break;
        }
        cli_command_multiple_full(cli, rbytes, command);
    }
    cli_destroy(cli);
    pthread_exit(NULL);
}

cli_t *
cli_create(int fd, struct sockaddr_un sun)
{
    cli_t *cli;

    // Reserve memory for this client
    if (!(cli = malloc(sizeof(cli_t)))) {
        isaac_log(LOG_ERROR, "Failed to allocate client manager: %s\n", strerror(errno));
        return NULL;
    }

    // Copy all required data to this client
    memset(cli, 0, sizeof(cli_t));
    memcpy(&cli->sun, &sun, sizeof(sun));
    cli->fd = fd;

    // Initialize cli lock
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&cli->lock, &attr);

    // Add client to the client list
    pthread_mutex_lock(&clilock);
    cli->next = clilist;
    clilist = cli;
    pthread_mutex_unlock(&clilock);

    return cli;
}

void
cli_destroy(cli_t *cli)
{
    struct isaac_cli *cur, *prev = NULL;

    // todo Do this with an iterator
    pthread_mutex_lock(&clilock);
    cur = clilist;
    /** Look for the current client in the client list **/
    while (cur) {
        if (cur == cli) {
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
        // This message won't be notify to current cli cause it's no longer
        // in the cli list
        isaac_log(LOG_VERBOSE, "Remote UNIX connection disconnected\n");
        close(cli->fd);
        pthread_cancel(cli->thread);
        pthread_mutex_destroy(&cli->lock);
        isaac_free(cli);
    } else {
        // This should happen!!
        isaac_log(LOG_ERROR, "Trying to destroy non-existent CLI: %d\n", cli->fd);
    }
}

int
cli_read(cli_t *cli, char *readed)
{
    bzero(readed, 256);
    return read(cli->fd, readed, 255);
}

int
cli_write(cli_t *cli, const char *fmt, ...)
{
    char message[MAX_MSG_SIZE];
    va_list ap;
    int ret;

    va_start(ap, fmt);
    vsprintf(message, fmt, ap);
    va_end(ap);
    pthread_mutex_lock(&cli->lock);
    ret = write(cli->fd, message, isaac_strlen(message) + 1);
    pthread_mutex_unlock(&cli->lock);
    return ret;
}

void
cli_broadcast(const char *msg)
{
    cli_t *cur;
    // Loop through the CLIs and writting the message
    for (cur = clilist; cur; cur = cur->next) {
        cli_write(cur, msg);
    }
}

int
cli_register_entry(cli_entry_t *entry)
{
    int i;
    cli_args_t args; /* fake argument */
    char **dst = (char **) entry->cmda; /* need to cast as the entry is readonly */
    char *s;

    memset(&args, '\0', sizeof(args));
    entry->handler(entry, CLI_INIT, &args);

    // XXX check that usage and command are filled up
    s = isaac_skip_blanks(entry->command);
    s = entry->command = strdup(s);
    for (i = 0; !isaac_strlen_zero(s) && i < 100 - 1; i++) {
        *dst++ = s; /* store string */
        s = isaac_skip_nonblanks(s);
        if (*s == '\0') /* we are done */
            break;
        *s++ = '\0';
        s = isaac_skip_blanks(s);
    }
    *dst++ = NULL;

    // Check if already has been registered
    if (cli_find(entry->cmda, 1)) {
        isaac_log(LOG_WARNING, "Command '%s' already registered (or something close enough)\n",
                  (entry->_full_cmd) ? entry->_full_cmd : entry->command);
        return -1;
    }
    if (cli_entry_cmd(entry)) {
        return -1;
    }

    // Push this entry in the top of the list
    pthread_mutex_lock(&entrieslock);
    entry->next = entries;
    entries = entry;
    pthread_mutex_unlock(&entrieslock);

    isaac_log(LOG_VERBOSE_2, "Registered command '%s'\n", entry->_full_cmd);
    return 0;
}

int
cli_register_entry_multiple(cli_entry_t *entry, int len)
{
    int i, res = 0;
    for (i = 0; i < len; i++) {
        res |= cli_register_entry(entry + i);
    }
    return res;
}

int
cli_entry_cmd(cli_entry_t *entry)
{
    int i;
    char buf[80];

    // Build the Full command field from Command Array
    isaac_join(buf, sizeof(buf), entry->cmda);
    entry->_full_cmd = strdup(buf);
    if (!entry->_full_cmd) {
        isaac_log(LOG_WARNING, "-- cannot allocate <%s>\n", buf);
        return -1;
    }
    // Return the comman part avoiding the Arguments
    entry->cmdlen = strcspn(entry->_full_cmd, cli_rsvd);
    for (i = 0; entry->cmda[i]; i++);
    entry->args = i;
    return 0;
}

int
cli_word_match(const char *cmd, const char *cli_word)
{
    int l;
    char *pos;
    if (isaac_strlen_zero(cmd) || isaac_strlen_zero(cli_word)) return -1;
    if (!strchr(cli_rsvd, cli_word[0])) /* normal match */
        return (strcasecmp(cmd, cli_word) == 0) ? 1 : -1;
    // regexp match, takes [foo|bar] or {foo|bar}
    l = strlen(cmd);
    // wildcard match - will extend in the future
    if (l > 0 && cli_word[0] == '%') {
        return 1; /* wildcard */
    }
    //FIXME pos = strcasestr(cli_word, cmd);
    pos = strcasestr(cli_word, cmd);
    if (pos == NULL) /* not found, say ok if optional */
        return cli_word[0] == '[' ? 0 : -1;
    if (pos == cli_word) /* no valid match at the beginning */
        return -1;
    if (strchr(cli_rsvd, pos[-1]) && strchr(cli_rsvd, pos[l])) return 1; /* valid match */
    return -1; /* not found */
}

cli_entry_t *
cli_find(const char *const cmds[], int match_type)
{
    int matchlen = -1; /* length of longest match so far */
    cli_entry_t *cand = NULL, *entry = NULL;

    for (entry = entries; entry; entry = entry->next) {

        /* word-by word regexp comparison *//* word-by word regexp comparison */
        const char *const *src = cmds;
        const char *const *dst = entry->cmda;
        int n = 0;
        for (;; dst++, src += n) {
            n = cli_word_match(*src, *dst);
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
            if (match_type != -1 || !isaac_strlen_zero(src[1]) ||
                !isaac_strlen_zero(dst[1])) /* not the one we look for */
                continue;
            /* good, we are in case match_type == -1 and mismatch on last word */
        }
        if (src - cmds > matchlen) { /* remember the candidate */
            matchlen = src - cmds;
            cand = entry;
        }

    }

    return entry ? entry : cand;
}

char *
cli_complete_number(const char *partial, unsigned int min, unsigned int max, int n)
{
    int i, count = 0;
    unsigned int prospective[2];
    unsigned int part = strtoul(partial, NULL, 10);
    char next[15];

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

char *
cli_parse_args(const char *s, int *argc, const char *argv[], int max, int *trailingwhitespace)
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

char *
cli_find_best(const char *argv[])
{
    static char cmdline[80];
    int x;
    /* See how close we get, then print the candidate */
    const char *myargv[400] = {
        NULL, };

    for (x = 0; argv[x]; x++) {
        myargv[x] = argv[x];
        if (!cli_find(myargv, -1)) break;
    }
    isaac_join(cmdline, sizeof(cmdline), myargv);
    return cmdline;
}

int
cli_command_full(cli_t *cli, const char *s)
{
    const char *args[AST_MAX_ARGS + 1];
    cli_entry_t *entry;
    int x;
    char *duplicate = cli_parse_args(s, &x, args + 1, AST_MAX_ARGS, NULL);
    char *retval = NULL;
    cli_args_t a = {
        .cli = cli,
        .argc = x,
        .argv = args + 1 };

    if (duplicate == NULL) return -1;

    if (x < 1) /* We need at least one entry, otherwise ignore */
        goto done;

    entry = cli_find(args + 1, 0);
    if (entry == NULL) {
        cli_write(cli, "\rNo such command '%s'\n", s, cli_find_best(args + 1));
        goto done;
    }

    /* Within the handler, argv[-1] contains a pointer to the cli_entry_t.
     * Remember that the array returned by parse_args is NULL-terminated.
     */
    args[0] = (char *) entry;

    retval = entry->handler(entry, CLI_HANDLER, &a);

    if (retval == CLI_SHOWUSAGE) {
        cli_write(cli, "%s", (entry->usage) ? entry->usage
                                            : "Invalid usage, but no usage information available.\n");
    } else if (retval == CLI_FAILURE) {
        cli_write(cli, "Command '%s' failed.\n", s);
    }

    done:
    isaac_free(duplicate);
    return 0;
}

int
cli_command_multiple_full(cli_t *cli, size_t size, const char *s)
{
    char cmd[512];
    int x, y = 0, count = 0;

    for (x = 0; x < size; x++) {
        cmd[y] = s[x];
        y++;
        if (s[x] == '\0') {
            cli_command_full(cli, cmd);
            y = 0;
            count++;
        }
    }
    return count;
}

/*! \brief if word is a valid prefix for token, returns the pos-th
 * match as a malloced string, or NULL otherwise.
 * Always tell in *actual how many matches we got.
 */
char *
cli_is_prefix(const char *word, const char *token, int pos, int *actual)
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

int
cli_more_words(const char *const *dst)
{
    int i;
    for (i = 0; dst[i]; i++) {
        if (dst[i][0] != '[') return -1;
    }
    return 0;
}

/*
 * generate the entry at position 'state'
 */
char *
cli_generator(const char *text, const char *word, int state)
{
    const char *argv[AST_MAX_ARGS];
    cli_entry_t *entry = NULL;
    int x = 0, argindex, matchlen;
    int matchnum = 0;
    char *ret = NULL;
    char matchstr[80] = "";
    int tws = 0;

    /* Split the argument into an array of words */
    char *duplicate = cli_parse_args(text, &x, argv, ARRAY_LEN(argv), &tws);

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
    for (entry = entries; entry; entry = entry->next) {
        /* XXX repeated code */
        int src = 0, dst = 0, n = 0;

        /** Skip internal commands **/
        if (entry->command[0] == '_') continue;

        /*
         * Try to match words, up to and excluding the last word, which
         * is either a blank or something that we want to extend.
         */
        for (; src < argindex; dst++, src += n) {
            n = cli_word_match(argv[src], entry->cmda[dst]);
            if (n < 0) break;
        }

        if (src != argindex && cli_more_words(entry->cmda + dst)) /* not a match */
            continue;
        ret = cli_is_prefix(argv[src], entry->cmda[dst], state - matchnum, &n);
        matchnum += n; /* this many matches here */
        if (ret) {
            /*
             * argv[src] is a valid prefix of the next word in this
             * command. If this is also the correct entry, return it.
             */
            if (matchnum > state) break;
            isaac_free(ret);
            ret = NULL;
        } else if (isaac_strlen_zero(entry->cmda[dst])) {
            /*
             * This entry is a prefix of the command string entered
             * (only one entry in the list should have this property).
             * Run the generator if one is available. In any case we are done.
             */
            if (entry->handler) { /* new style command */
                cli_args_t args = {
                    .line = matchstr,
                    .word = word,
                    .pos = argindex,
                    .n = state - matchnum,
                    .argv = argv,
                    .argc = x };
                ret = entry->handler(entry, CLI_GENERATE, &args);
            }
            if (ret) break;
        }
    }
    isaac_free(duplicate);
    return ret;
}

/*! \brief Return the number of unique matches for the generator */
int
cli_generatornummatches(const char *text, const char *word)
{
    int matches = 0, i = 0;
    char *buf = NULL, *oldbuf = NULL;

    while ((buf = cli_generator(text, word, i++))) {
        if (!oldbuf || strcmp(buf, oldbuf)) matches++;
        if (oldbuf) isaac_free(oldbuf);
        oldbuf = buf;
    }
    if (oldbuf) isaac_free(oldbuf);
    return matches;
}

char **
cli_completion_matches(const char *text, const char *word)
{
    char **match_list = NULL, *retstr, *prevstr;
    size_t match_list_len, max_equal, which, i;
    int matches = 0;

    /* leave entry 0 free for the longest common substring */
    match_list_len = 1;
    while ((retstr = cli_generator(text, word, matches)) != NULL) {
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

char *
cli_complete_session(const char *line, const char *word, int pos, int state, int rpos)
{
    int which = 0;
    char notfound = '\0';
    char *ret = &notfound; /* so NULL can break the loop */

    if (pos != rpos) {
        return NULL;
    }

    GSList *sessions = sessions_adquire_lock();
    for (GSList *l = sessions; l; l = l->next) {
        Session *sess = l->data;
        if (ret != &notfound)
            break;
        if (++which > state) {
            ret = sess->id;
        }
    }
    sessions_release_lock();

    return ret == &notfound ? NULL : ret;
}

/******************************************************************************
 *****************************************************************************/
char *
handle_commandmatchesarray(cli_entry_t *entry, int cmd, cli_args_t *args)
{
    char *buf, *obuf;
    int buflen = 2048;
    int len = 0;
    char **matches;
    int x, matchlen;

    switch (cmd) {
        case CLI_INIT:
            entry->command = "_command matchesarray";
            entry->usage = "Usage: _command matchesarray \"<line>\" text \n"
                           "       This function is used internally to help with command completion and should.\n"
                           "       never be called by the user directly.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }

    if (args->argc != 4) return CLI_SHOWUSAGE;
    if (!(buf = malloc(buflen))) return CLI_FAILURE;
    buf[len] = '\0';
    matches = cli_completion_matches(args->argv[2], args->argv[3]);
    if (matches) {
        for (x = 0; matches[x]; x++) {
            matchlen = strlen(matches[x]) + 1;
            if (len + matchlen >= buflen) {
                buflen += matchlen * 3;
                obuf = buf;
                if (!(buf = realloc(obuf, buflen)))
                    /* Memory allocation failure...  Just free old buffer and be done */
                    isaac_free(obuf);
            }
            if (buf) len += sprintf(buf + len, "%s ", matches[x]);
            isaac_free(matches[x]);
            matches[x] = NULL;
        }
        isaac_free(matches);
    }

    if (buf) {
        cli_write(args->cli, "%s%s", buf, AST_CLI_COMPLETE_EOF);
        isaac_free(buf);
    } else
        cli_write(args->cli, "NULL\n");

    return CLI_SUCCESS;
}

char *
handle_commandcomplete(cli_entry_t *entry, int cmd, cli_args_t *args)
{
    char *buf;
    switch (cmd) {
        case CLI_INIT:
            entry->command = "_command complete";
            entry->usage = "Usage: _command complete \"<line>\" text state\n"
                           "       This function is used internally to help with command completion and should.\n"
                           "       never be called by the user directly.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }
    if (args->argc != 5) return CLI_SHOWUSAGE;
    buf = cli_generator(args->argv[2], args->argv[3], atoi(args->argv[4]));
    if (buf) {
        cli_write(args->cli, "%s", buf);
        isaac_free(buf);
    } else {
        cli_write(args->cli, "NULL\n");
    }
    return CLI_SUCCESS;
}

char *
handle_commandnummatches(cli_entry_t *entry, int cmd, cli_args_t *args)
{
    int matches = 0;

    switch (cmd) {
        case CLI_INIT:
            entry->command = "_command nummatches";
            entry->usage = "Usage: _command nummatches \"<line>\" text \n"
                           "       This function is used internally to help with command completion and should.\n"
                           "       never be called by the user directly.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }

    if (args->argc != 4) return CLI_SHOWUSAGE;

    matches = cli_generatornummatches(args->argv[2], args->argv[3]);

    cli_write(args->cli, "%d", matches);

    return CLI_SUCCESS;
}

char *
handle_core_show_uptime(cli_entry_t *entry, int cmd, cli_args_t *args)
{
    struct timeval curtime = isaac_tvnow();
    int printsec;
    char out[256];

    switch (cmd) {
        case CLI_INIT:
            entry->command = "core show uptime [seconds]";
            entry->usage = "Usage: core show uptime [seconds]\n"
                           "       Shows Isaac uptime information.\n"
                           "       The seconds word returns the uptime in seconds only.\n";
            return NULL;

        case CLI_GENERATE:
            return NULL;
    }

    /* regular handler */
    if (args->argc == entry->args && !strcasecmp(args->argv[entry->args - 1], "seconds"))
        printsec
            = 1;
    else if (args->argc == entry->args - 1) printsec = 0;
    else
        return CLI_SHOWUSAGE;

    if (startuptime.tv_sec) {
        isaac_tvelap(isaac_tvsub(curtime, startuptime), printsec, out);
        cli_write(args->cli, "\r%s: %s\n", "System uptime", out);
    }

    return CLI_SUCCESS;

}

char *
handle_core_show_version(cli_entry_t *entry, int cmd, cli_args_t *args)
{

    switch (cmd) {
        case CLI_INIT:
            entry->command = "core show version";
            entry->usage = "Usage: core show version\n"
                           "       Show  Isaac version";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }

    // Print the version string
    cli_write(args->cli, "%s v%s\n", CLI_BANNER, PACKAGE_VERSION);

    return CLI_SUCCESS;
}

char *
handle_core_show_settings(cli_entry_t *entry, int cmd, cli_args_t *args)
{
    char running[256];
    char manconnected[256];

    switch (cmd) {
        case CLI_INIT:
            entry->command = "core show settings";
            entry->usage = "Usage: core show settings\n"
                           "       Show  Isaac configuration options";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }

    isaac_tvelap(isaac_tvsub(isaac_tvnow(), startuptime), 0, running);
    isaac_tvelap(isaac_tvsub(isaac_tvnow(), manager->connectedtime), 0, manconnected);

    cli_write(args->cli, "\n%s Core settings\n----------------------\n", PACKAGE_NAME);
    cli_write(args->cli, "   %-20s: %s\n", "Version", PACKAGE_VERSION);
    cli_write(args->cli, "   %-20s: %d (%s)\n", "Log Type", config.logtype, "syslog");
    cli_write(args->cli, "   %-20s: %d\n", "Log Level", config.loglevel);
    cli_write(args->cli, "   %-20s: %s\n", "Log Tag", config.logtag);
    cli_write(args->cli, "   %-20s: %d apps \n", "Aplications", application_count());
    cli_write(args->cli, "   %-20s:%s\n", "Running since", running);
    cli_write(args->cli, "\nManager settings\n----------------------\n");
    cli_write(args->cli, "   %-20s: %s\n", "Address", config.manaddr);
    cli_write(args->cli, "   %-20s: %d\n", "Port", config.manport);
    cli_write(args->cli, "   %-20s: %s\n", "Username", config.manuser);
    cli_write(args->cli, "   %-20s:%s\n", "Connected since", ((manager->connected) ? manconnected
                                                                                   : " Disconnected"));
    cli_write(args->cli, "\nServer settings\n----------------------\n");
    cli_write(args->cli, "   %-20s: %s\n", "Address", config.listenaddr);
    cli_write(args->cli, "   %-20s: %d\n", "Port", config.listenport);
    cli_write(args->cli, "   %-20s: %d\n", "Keep-Alive", config.keepalive);
    //cli_write(args->cli, "   %-20s: %d\n", "Processed sessions", config.sessioncnt);
    cli_write(args->cli, "   %-20s: %d\n", "Hide local sessions", config.hidelocal);
    cli_write(args->cli, "\n\n");

    return CLI_SUCCESS;
}

char *
handle_core_show_applications(cli_entry_t *entry, int cmd, cli_args_t *args)
{
    switch (cmd) {
        case CLI_INIT:
            entry->command = "core show applications";
            entry->usage = "Usage: core show applications\n"
                           "       Show  Isaac registered applications";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }
    return CLI_SUCCESS;
}

char *
handle_core_set_verbose(cli_entry_t *entry, int cmd, cli_args_t *args)
{
    const char *const *argv = args->argv;
    int newlevel;

    switch (cmd) {
        case CLI_INIT:
            entry->command = "core set verbose";
            entry->usage = "Usage: core set verbose <level>"
                           "       Set verbosity level of core.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }

    if (args->argc != entry->args + 1) return CLI_SHOWUSAGE;

    if (sscanf(argv[entry->args], "%30d", &newlevel) != 1) return CLI_SHOWUSAGE;

    config.loglevel = newlevel;
    cli_write(args->cli, "Verbosity level is %d\n", newlevel);

    return CLI_SUCCESS;
}

char *
handle_show_connections(cli_entry_t *entry, int cmd, cli_args_t *args)
{
    int sessioncnt = 0;
    struct timeval curtime = isaac_tvnow();
    char idle[256];

    switch (cmd) {
        case CLI_INIT:
            entry->command = "show connections";
            entry->usage = "Usage: show connections\n"
                           "       Show connected session";
            return NULL;
        case CLI_GENERATE:
            return NULL;
    }

    /* Avoid other output for this cli */
    pthread_mutex_lock(&clilock);

    /* Print header for sessions */
    cli_write(args->cli, "%-10s%-25s%-20s%s\n", "ID", "Address", "Logged as", "Idle");

    /* Print available sessions */
    GSList *sessions = sessions_adquire_lock();
    for (GSList *l = sessions; l; l = l->next) {
        Session *sess = l->data;
        sessioncnt++;
        isaac_tvelap(isaac_tvsub(curtime, sess->last_cmd_time), 1, idle);
        cli_write(args->cli, "%-10s%-25s%-20s%s\n", sess->id, sess->addrstr, ((session_test_flag(
                sess, SESS_FLAG_AUTHENTICATED)) ? session_get_variable(sess, "AGENT")
                                                : "not logged"), idle);
    }
    sessions_release_lock();

    cli_write(args->cli, "%d active sessions\n", sessioncnt);
    //cli_write(args->cli, "%d processed sessions\n", config.sessioncnt);

    /* Set cli output unlocked */
    pthread_mutex_unlock(&clilock);

    return CLI_SUCCESS;
}

char *
handle_show_filters(cli_entry_t *entry, int cmd, cli_args_t *args)
{
    filter_t *filter = NULL;
    Session *sess;
    int filter_cnt = 0;
    int ccnt = 0;

    switch (cmd) {
        case CLI_INIT:
            entry->command = "show filters";
            entry->usage = "Usage: show filters [sessionid]\n"
                           "       Show connected session active filters\n";
            return NULL;
        case CLI_GENERATE:
            if (args->pos == 2) {
                return cli_complete_session(args->line, args->word, args->pos, args->n, 1);
            }
            return NULL;
    }

    /* Inform all required parameters */
    if (args->argc != 3) {
        return CLI_SHOWUSAGE;
    }

    /* Avoid other output for this cli */
    pthread_mutex_lock(&clilock);

    /* Get session */
    if (!(sess = session_by_id(args->argv[2]))) {
        cli_write(args->cli, "Unable to find session with id %s\n", args->argv[2]);
    } else {
        while ((filter = filter_from_session(sess, filter))) {
            // Print session filters
            cli_write(args->cli, "------------ %s Filter %d %s ------------\n",
                      (filter->type == FILTER_ASYNC) ? "(Async)" : "(Sync)",
                      filter_cnt++,
                      (filter->type == FILTER_ASYNC && filter->data.async.oneshot) ? "(OneShot)" : "");

            for (ccnt = 0; ccnt < filter->condcount; ccnt++) {

                cli_write(args->cli, " %-10s", filter->conds[ccnt].hdr);
                switch (filter->conds[ccnt].type) {
                    case MATCH_EXACT:
                        cli_write(args->cli, "%-5s", "==");
                        break;
                    case MATCH_EXACT_CASE:
                        cli_write(args->cli, "%-5s", "i=");
                        break;
                    case MATCH_START_WITH:
                        cli_write(args->cli, "%-5s", "^=");
                        break;
                    case MATCH_REGEX:
                        cli_write(args->cli, "%-5s", "~");
                        break;
                    case MATCH_REGEX_NOT:
                        cli_write(args->cli, "%-5s", "!~");
                        break;
                }

                cli_write(args->cli, "%-s\n", filter->conds[ccnt].val);
            }
            cli_write(args->cli, "\n");
        }
        if (!filter_cnt) {
            cli_write(args->cli, "---------- No active filters ---------\n");
        }
    }

    /* Set cli output unlocked */
    pthread_mutex_unlock(&clilock);

    return CLI_SUCCESS;
}

char *
handle_show_variables(cli_entry_t *entry, int cmd, cli_args_t *args)
{
    Session *sess;
    int i = 0;

    switch (cmd) {
        case CLI_INIT:
            entry->command = "show variables";
            entry->usage = "Usage: show variables [sessionid]\n"
                           "       Show connected session variables\n";
            return NULL;
        case CLI_GENERATE:
            if (args->pos == 2) {
                return cli_complete_session(args->line, args->word, args->pos, args->n, 1);
            }
            return NULL;
    }

    /* Inform all required parameters */
    if (args->argc != 3) {
        return CLI_SHOWUSAGE;
    }

    /* Avoid other output for this cli */
    pthread_mutex_lock(&clilock);

    /* Get session */
    if (!(sess = session_by_id(args->argv[2]))) {
        cli_write(args->cli, "Unable to find session with id %s\n", args->argv[2]);
    } else {
        cli_write(args->cli, "------------ Variables for session %s ------------\n", args->argv[2]);
        for (i = 0; i < sess->varcount; i++) {
            cli_write(args->cli, "%s = %s\n", sess->vars[i].varname, sess->vars[i].varvalue);
        }
    }

    /* Set cli output unlocked */
    pthread_mutex_unlock(&clilock);

    return CLI_SUCCESS;
}


char *
handle_kill_connection(cli_entry_t *entry, int cmd, cli_args_t *args)
{
    Session *sess;
    switch (cmd) {
        case CLI_INIT:
            entry->command = "kill connection";
            entry->usage = "Usage: kill connection [sessionid]\n"
                           "       Kill a session connection\n";
            return NULL;
        case CLI_GENERATE:
            if (args->pos == 2) {
                return cli_complete_session(args->line, args->word, args->pos, args->n, 1);
            }
            return NULL;
    }

    /* Inform all required parameters */
    if (args->argc != 3) {
        return CLI_SHOWUSAGE;
    }

    /* Get session */
    if (!(sess = session_by_id(args->argv[2]))) {
        cli_write(args->cli, "Unable to find session with id %s\n", args->argv[2]);
    } else {
        session_write(sess, "BYE Connection killed from CLI\r\n");
        session_finish(sess);
    }

    return CLI_SUCCESS;
}

char *
handle_debug_connection(cli_entry_t *entry, int cmd, cli_args_t *args)
{
    Session *sess;
    switch (cmd) {
        case CLI_INIT:
            entry->command = "debug connection";
            entry->usage = "Usage: debug connection [sessionid]\n"
                           "       debug a session connection\n";
            return NULL;
        case CLI_GENERATE:
            if (args->pos == 2) {
                return cli_complete_session(args->line, args->word, args->pos, args->n, 1);
            }
            return NULL;
    }

    /* Inform all required parameters */
    if (args->argc != 3) {
        return CLI_SHOWUSAGE;
    }

    /* Get session */
    if (!(sess = session_by_id(args->argv[2]))) {
        cli_write(args->cli, "Unable to find session with id %s\n", args->argv[2]);
    } else {
        if (session_test_flag(sess, SESS_FLAG_DEBUG)) {
            session_clear_flag(sess, SESS_FLAG_DEBUG);
            isaac_log(LOG_NOTICE, "Debug on session %s \e[1;31mdisabled\e[0m.\n", args->argv[2]);
        } else {
            session_set_flag(sess, SESS_FLAG_DEBUG);
            isaac_log(LOG_NOTICE, "Debug on session %s \e[1;32menabled\e[0m.\n", args->argv[2]);
        }
    }

    return CLI_SUCCESS;

}

