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
 * @file cli.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions for handling Command Line Interface connections and commands
 *
 * Isaac offers a Command Line inferface that can be accessed using the same
 * binary with the "-r" argument.\n
 * This will open a local UNIX socket from where user can see the program log
 * and issue some commands.\n
 * This file include the Server side functions to manage the incoming connections
 * and requested commands outputs.\n
 * Most of this functions code has been taken or adapted from Asterisk main/cli.c
 * file, so thanks Digium for the effort ;)
 * For client side functios see @ref remote.h
 *
 * @see remote.h
 */

#ifndef __ISAAC_CLI_H_
#define __ISAAC_CLI_H_

#include <glib.h>
#include <gio/gio.h>
#include <poll.h>
#include <sys/un.h>
#include <pthread.h>

#define CLI_BANNER "Isaac - Ivozng Simplified Asterisk AMI Connector"
/**
 * @brief Return values for CLI commands
 *
 * This values are used from all command handler as return values an will
 * determine the default CLI behaviour.\n
 */
#define CLI_SUCCESS             (char *)0
#define CLI_SHOWUSAGE           (char *)1
#define CLI_FAILURE             (char *)2

//! Max number of arguments a CLI command can have.
#define AST_MAX_ARGS 64
//! Final tag to signal end of CLI suggestion arrays.
#define AST_CLI_COMPLETE_EOF    "_EOF_"
//! Macro for calculating array len.
#define ARRAY_LEN(a) (size_t) (sizeof(a) / sizeof(0[a]))
//! Macro for easy inclusion of handler functions.
#define AST_CLI_DEFINE(fn, txt, ...)  { .handler = fn, .summary = txt, ## __VA_ARGS__ }

//! Sorter declaration of _CLIClient struct
typedef struct _CLIClient CLIClient;
//! Sorter declaration of _CLIEntry struct
typedef struct _CLIEntry CLIEntry;
//! Sorter declaration of CLIArgs struct
typedef struct _CLIArgs CLIArgs;

/**
 * @brief Structure from an incoming CLI connection.
 *
 * This structure stores all basic information from cli connections.
 * It also works as a node of a linked list in all schoold style.
 */
struct _CLIClient
{
    //! CLI connection
    GSocketConnection *conn;
    //! Connection socket
    GSocket *socket;
    //! CLI Source of events
    GSource *source;
    //! CLI connection socket
    gint fd;
    //! CLI structure lock
    GRecMutex lock;
};

/**
 * @brief Calling arguments for handlers.
 */
enum CLICommand
{
    //! Return the usage string
    CLI_INIT = -2,
    //! Behave as 'generator', remap argv to CLIArgs
    CLI_GENERATE = -3,
    //! Run the normal handler
    CLI_HANDLER = -4,
};

/**
 * @brief Argument for CLI handler
 *
 * @todo Check if all this fields are used.
 */
struct _CLIArgs
{
    //! CLI structure entering this command
    CLIClient *cli;
    //! Number of command arguments (including command)
    const gint argc;
    //! Command argument list (including command)
    const gchar **argv;
    //! Current input line
    const gchar *line;
    //! Word we want to complete
    const gchar *word;
    //! Position of the word to complete
    const gint pos;
    //! Iteration count (n-th entry we generate)
    const gint n;
};

/**
 * @brief Structure for a CLI entry.
 *
 * @todo Check if all this fields are used.
 */
struct _CLIEntry
{
    //! Words making up the command.
    const gchar *const cmda[400];
    //! Summary of the command (< 60 characters)
    const gchar *const summary;
    //! Detailed usage information
    gchar *usage;
    //! For keeping track of usage
    int inuse;
    //! Module this belongs to
    struct module *module;
    //! Built at load time from cmda[]
    gchar *_full_cmd;
    //! Len up to the first invalid char [<{%
    gint cmdlen;
    //! Number of non-null entries in cmda
    gint args;
    //! Command, non-null for new-style entries
    gchar *command;
    //! Handler function for this cli entry
    gchar *
    (*handler)(CLIEntry *e, gint cmd, CLIArgs *a);

    //! For linking
    CLIEntry *next;
};

/**
 * @brief Starts the CLI thread for accepting connections
 *
 * This function will create the local socket and bind it for accepting
 * CLI client connections.\n
 * It will also create an @ref cli_incoming_connection "Accepting connection thread" to
 * manage incoming connections.
 *
 * @return 0 in case of success, -1 otherwise
 */
int
cli_server_start();

/**
 * \brief Stops the CLI thread and closes all active connections
 *
 * This function will stop the CLI server closing the local socket.\n
 * It will also close any active CLI connection and cancel the accept new
 * connections thread.
 */
void
cli_server_stop();

/**
 * @brief Allocate memory for a new CLI and add to CLI lists
 *
 * This function will create a CLI structure with the given parameters
 * and add it to the CLI list.
 *
 * @return A pointer to the allocated CLI structure or NULL in case of error
 */
CLIClient *
cli_create(GSocketConnection *connection);

/**
 * @brief Destroys an active CLI client connection deallocating its memory
 *
 * This function will cleanup the running CLI thread for a given connection.\n
 * Can be used when a client disconnects or when CLI server stops.
 *
 * @param cli CLI client connection
 */
void
cli_destroy(CLIClient *cli);

/**
 * @brief Handle input commands issued from a CLI client connection
 *
 * This function will be launched in a thread for each new CLI connection and
 * will manage all input received from a client.\n
 * Input verification will be done through @ref cli_command_multiple_full
 *
 * @param cli CLI client connection
 */
void *
cli_do(CLIClient *cli);

/**
 * @brief Reads next command from CLI.
 *
 * This function will block till CLI issues a command that will be stored in
 * readed pointer. \n
 * @note This is a blocking function.
 * @note Memory allocation for readed buffer will not be done in this function.
 *
 * @param cli CLI connection
 * @param readed Buffer to store input CLI command
 * @return Number of bytes readed from socket
 */
int
cli_read(CLIClient *cli, char *readed);

/**
 * @brief Writes some text to a CLI client connection
 *
 * This function will write a given text into an active CLI connection socket.
 * Used to respond to issued commands readed from CLI and for logging into all
 * active CLI connections.
 *
 * @param cli CLI connection
 * @param fmt Format and args in printf style
 * @return Number of writen bytes
 */
int
cli_write(CLIClient *cli, const char *fmt, ...);

/**
 * @brief Write some text to all connected CLI clients
 *
 * This function is mostly used for broadcasting log messages to all CLI clients
 * If you want to write only in one client, use @ref cli_write
 *
 * @param msg Textmessage to send to all CLI clients
 */
void
cli_broadcast(const char *msg);

/**
 * @brief Register a new CLI
 *
 * This function is used to add a new command to the \ref entries "CLI list"
 *
 * @param entry CLI command entry pointer
 * @return 0 On success, 1 otherwise
 */
int
cli_register_entry(CLIEntry *entry);

/**
 * @brief Register an array of entries.
 *
 * This function is a wrapper for @ref cli_register_entry that can
 * work with an array of entries.
 *
 * @param entry First Entry pointer (linked list)
 * @param len Length of list of entries
 * @return 0 On success, 1 otherwise
 */
int
cli_register_entry_multiple(CLIEntry *entry, int len);

/**
 * @brief Sets the full command field in passed entry
 *
 * This function joins the CMDA array to build the full command
 * also stores the command part length (without the arguments)
 *
 * @param entry Entry pointer
 * @return 0 On success
 * @return 1 On error
 */
int
cli_entry_cmd(CLIEntry *entry);

/**
 * @brief Match a word in the CLI entry.
 *
 * The pattern can be
 *   any_word           match for equal
 *   [foo|bar|baz]      optionally, one of these words
 *   {foo|bar|baz}      exactly, one of these words
 *   %                  any word
 *
 * @retval -1 On mismatch
 * @retval 0  On match of an optional word,
 * @retval 1  On match of a full word.
 */
int
cli_word_match(const char *cmd, const char *cli_word);

/**
 * @brief Locate a cli command in the 'helpers' list (which must be locked).
 *     The search compares word by word taking care of regexps in e->cmda
 *     This function will return NULL when nothing is matched, or the CLIEntry that matched.
 * @param cmds
 * @param match_type has 3 possible values:
 *      - 0  If the search key is equal or longer than the entry.
 *           note that trailing optional arguments are skipped.
 *      - -1 If the mismatch is on the last word XXX not true!
 *      - 1  Only on complete, exact match.
 *
 * @return The CLI entry or NULL if not found
 */
CLIEntry *
cli_find(const char *const cmds[], int match_type);

char *
cli_complete_number(const char *partial, unsigned int min, unsigned int max, int n);

char *
cli_parse_args(const char *s, int *argc, const char *argv[], int max, int *trailingwhitespace);

char *
cli_find_best(const char *argv[]);

int
cli_command_full(CLIClient *cli, const char *s);

int
cli_command_multiple_full(CLIClient *cli, size_t size, const char *s);

char *
cli_is_prefix(const char *word, const char *token, int pos, int *actual);

int
cli_more_words(const char *const *dst);

char *
cli_generator(const char *text, const char *word, int state);

int
cli_generatornummatches(const char *text, const char *word);

char **
cli_completion_matches(const char *text, const char *word);

char *
cli_complete_session(const char *line, const char *word, int pos, int state, int rpos);

/******************************************************************************
 **                     Handlers for CLI commands                            **
 *****************************************************************************/
char *
handle_commandmatchesarray(CLIEntry *entry, int cmd, CLIArgs *args);

char *
handle_commandcomplete(CLIEntry *entry, int cmd, CLIArgs *args);

char *
handle_commandnummatches(CLIEntry *entry, int cmd, CLIArgs *args);

char *
handle_core_show_version(CLIEntry *entry, int cmd, CLIArgs *args);

char *
handle_core_show_uptime(CLIEntry *entry, int cmd, CLIArgs *args);

char *
handle_core_show_settings(CLIEntry *entry, int cmd, CLIArgs *args);

char *
handle_core_show_applications(CLIEntry *entry, int cmd, CLIArgs *args);

char *
handle_core_set_verbose(CLIEntry *entry, int cmd, CLIArgs *args);

char *
handle_show_connections(CLIEntry *entry, int cmd, CLIArgs *args);

char *
handle_show_filters(CLIEntry *entry, int cmd, CLIArgs *args);

char *
handle_show_variables(CLIEntry *entry, int cmd, CLIArgs *args);

char *
handle_kill_connection(CLIEntry *entry, int cmd, CLIArgs *args);

char *
handle_debug_connection(CLIEntry *entry, int cmd, CLIArgs *args);

#endif /* __ISAAC_CLI_H_ */
