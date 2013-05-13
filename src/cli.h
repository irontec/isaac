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
 * \file cli.h
 * \author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * \brief Functions for handling Command Line Interface connections and commands
 *
 * IronSC offers a Command Line inferface that can be accessed using the same
 * binary with the "-r" argument.\n
 * This will open a local UNIX socket from where user can see the program log
 * and issue some commands.\n
 * This file include the Server side functions to manage the incoming connections
 * and requested commands outputs.\n
 * For client side functios see \ref remote.h
 *
 * \see remote.h
 * \see cli.c
 * \todo Finish commenting this file and \ref cli.c
 */

#ifndef __ISAAC_CLI_H_
#define __ISAAC_CLI_H_

#include <poll.h>
#include <sys/un.h>
#include <pthread.h>

/**
 * \brief Return values for CLI commands
 *
 * This values are used from all command handler as return values an will
 * determine the default CLI behaviour.\n
 * They are available as integer (RESULT) or string (CLI).
 */
#define RESULT_SUCCESS          0
#define RESULT_SHOWUSAGE        1
#define RESULT_FAILURE          2
#define CLI_SUCCESS             (char *)RESULT_SUCCESS
#define CLI_SHOWUSAGE           (char *)RESULT_SHOWUSAGE
#define CLI_FAILURE             (char *)RESULT_FAILURE

//! Max number of arguments a CLI command can have.
#define AST_MAX_ARGS 64
//! Final tag to signal end of CLI suggestion arrays.
#define AST_CLI_COMPLETE_EOF	"_EOF_"
//! Macro for calculating array len.
#define ARRAY_LEN(a) (size_t) (sizeof(a) / sizeof(0[a]))
//! Macro for easy inclusion of handler functions.
#define AST_CLI_DEFINE(fn, txt , ... )  { .handler = fn, .summary = txt, ## __VA_ARGS__ }
//! Macro for writing information back to the CLI clients
#define isaac_cli(...)    cli_write(__VA_ARGS__)

/**
 * \brief Structure from an incoming CLI connection.
 *
 * This structure stores all basic information from cli connections.
 * It also works as a node of a linked list in all schoold style.
 *
 * \todo Check if all this fields are used.
 */
struct isaac_cli
{
    pthread_t t;
    pthread_mutex_t lock;
    //! Conection Address
    struct sockaddr_un sun;
    //! Connection Pipes
    int p[2];
    int fd;
    struct isaac_cli *next;
};

/**
 * \brief Calling arguments for handlers.
 */
enum isaac_cli_command
{
    //! Return the usage string
    CLI_INIT = -2,
    //! Behave as 'generator', remap argv to struct isaac_cli_args
    CLI_GENERATE = -3,
    //! Run the normal handler
    CLI_HANDLER = -4,
};

/**
 * \brief Argument for CLI handler
 *
 * \todo Check if all this fields are used.
 */
struct isaac_cli_args
{
    const int fd;
    const int argc;
    const char* *argv;
    //! Current input line
    const char *line;
    //! Word we want to complete
    const char *word;
    //! Position of the word to complete
    const int pos;
    //! Iteration count (n-th entry we generate)
    const int n;
};

/**
 * \brief Structure for a CLI entry.
 *
 * \todo Check if all this fields are used.
 */
struct isaac_cli_entry
{
    //! Words making up the command.
    const char * const cmda[400];
    //! Summary of the command (< 60 characters)
    const char * const summary;
    //! Detailed usage information
    char * usage;
    //! For keeping track of usage
    int inuse;
    //! Module this belongs to
    struct module *module;
    //! Built at load time from cmda[]
    char *_full_cmd;
    //! Len up to the first invalid char [<{%
    int cmdlen;
    //! Number of non-null entries in cmda
    int args;
    //! Command, non-null for new-style entries
    char *command;
    //! Handler function for this cli entry
    char *
    (*handler)(struct isaac_cli_entry *e, int cmd, struct isaac_cli_args *a);

    //! For linking
    struct isaac_cli_entry* next;
};

/**
 * \brief Starts the CLI thread for accepting connections
 *
 * This function will create the local socket and bind it for accepting
 * CLI client connections.\n
 * It will also create an \ref cli_accept "Accepting connection thread" to
 * manage incoming connections.
 *
 * \warning This function will exit from program using \ref quit if it fails
 */
extern int
cli_server_start();

/**
 * \brief Stops the CLI thread and closes all active connections
 *
 * This function will stop the CLI server closing the local socket.\n
 * It will also close any active CLI connection and cancel the accept new
 * connections thread.
 */
extern void
cli_server_stop();

/**
 * \brief Accepts new connection and launches a \ref cli_do thread to manage it
 *
 * This function will be launched in a new thread by \ref cli_server_start and
 * will manage incoming connections.\n
 * For each connection it will create it's \ref isaac_cli structure and append it
 * to the \ref clilist "CLI client list".\n
 * It will also launcha a \ref cli_do thread to manage that connection in a
 * separated thread.
 */
extern void
cli_accept();

/**
 * \brief Handle input commands issued from a CLI client connection
 *
 * This function will be launched in a thread for each new CLI connection and
 * will manage all input received from a client.\n
 * Input verification will be done through \ref isaac_cli_command_multiple_full
 *
 * \param c CLI client connection
 */
extern void*
cli_do(struct isaac_cli *c);

/**
 * \brief Destroys an active CLI client connection
 *
 * This function will cleanup the running CLI thread for a given connection.\n
 * Can be used when a client disconnects or when CLI server stops.
 *
 * \param c CLI client connection
 */
extern void
cli_destroy(struct isaac_cli *c);

/**
 * \brief Reads next command from CLI.
 *
 * This function will block till CLI issues a command that will be stored in
 * readed pointer. \n
 * \note This is a blocking function.
 * \note Memory allocation for readed buffer will not be done in this function.
 *
 * \param fd CLI connection socket
 * \param readed Buffer to store input CLI command
 * \return Number of bytes readed from socket
 */
extern int
cli_read(int fd, char* readed);

/**
 * \brief Writes some text to a CLI client connection
 *
 * This function will write a given text into an active CLI connection socket.
 * Used to respond to issued commands readed from CLI and for logging into all
 * active CLI connections.
 *
 * \param fd CLI connection socket
 * \param fmt Format and args in printf style
 * \return Number of writen bytes
 *
 * \see log.h
 */
extern int
cli_write(int fd, const char *fmt, ...);


extern void
write_clis(const char *logmsg);

/**
 * \brief Register a new CLI
 *
 * This function is used to add a new command to the \ref entries "CLI list"
 *
 * \param e Entry pointer
 * \return 0 On success
 * \return 1 On error
 */
extern int
isaac_cli_register(struct isaac_cli_entry *e);

/**
 * \brief Register an array of entries.
 *
 * This function is a wrapper for \ref isaac_cli_register that can
 * work with an array of entries.
 *
 * \param e First Entry pointer (linked list)
 * \param len Length of list of entries
 * \return 0 On success
 * \return 1 On error
 */
extern int
isaac_cli_register_multiple(struct isaac_cli_entry *e, int len);

/**
 * \brief Sets the full command field in passed entry
 *
 * This function joins the CMDA array to build the full command
 * also stores the command part length (without the arguments)
 *
 * \param e Entry pointer
 * \return 0 On success
 * \return 1 On error
 */
extern int
set_full_cmd(struct isaac_cli_entry *e);
extern int
isaac_cli_command_multiple_full(int fd, size_t size, const char *s);
extern char **
isaac_cli_completion_matches(const char *text, const char *word);
extern char *
parse_args(const char *s, int *argc, const char *argv[], int max,
        int *trailingwhitespace);

/**
 * \brief Match a word in the CLI entry.
 *
 * The pattern can be
 *   any_word           match for equal
 *   [foo|bar|baz]      optionally, one of these words
 *   {foo|bar|baz}      exactly, one of these words
 *   %                  any word
 *
 * \return -1 On mismatch
 * \return 0  On match of an optional word,
 * \return 1  On match of a full word.
 */
extern int
word_match(const char *cmd, const char *cli_word);

/**
 * \internal
 * \brief Locate a cli command in the 'helpers' list (which must be locked).
 *     The search compares word by word taking care of regexps in e->cmda
 *     This function will return NULL when nothing is matched, or the isaac_cli_entry that matched.
 * \param cmds
 * \param match_type has 3 possible values:
 *      - 0  If the search key is equal or longer than the entry.
 *           note that trailing optional arguments are skipped.
 *      - -1 If the mismatch is on the last word XXX not true!
 *      - 1  Only on complete, exact match.
 *
 * \return The CLI entry or NULL if not found
 */
extern struct isaac_cli_entry *
find_cli(const char * const cmds[], int match_type);

extern char *
isaac_complete_session(const char *line, const char *word, int pos, int state,
        int rpos);

/******************************************************************************
 **                     Handlers for CLI commands                            **
 *****************************************************************************/
extern char *
handle_commandmatchesarray(struct isaac_cli_entry *e, int cmd,
        struct isaac_cli_args *a);

extern char
        *
        handle_commandcomplete(struct isaac_cli_entry *e, int cmd,
                struct isaac_cli_args *a);

extern char *
handle_commandnummatches(struct isaac_cli_entry *e, int cmd,
        struct isaac_cli_args *a);

extern char *
handle_core_show_version(struct isaac_cli_entry *e, int cmd,
        struct isaac_cli_args *a);

extern char *
handle_core_show_uptime(struct isaac_cli_entry *e, int cmd,
        struct isaac_cli_args *a);

extern char *
handle_show_connections(struct isaac_cli_entry *e, int cmd,
        struct isaac_cli_args *a);

extern char *
handle_kill_connection(struct isaac_cli_entry *e, int cmd, struct isaac_cli_args *a);

extern char *
handle_debug_connection(struct isaac_cli_entry *e, int cmd, struct isaac_cli_args *a);

#endif /* __ISAAC_CLI_H_ */
