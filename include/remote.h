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
 * @file remote.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions declaration to manage client connection with Isaac CLI
 *
 * Most of this functions are copied or adapted from Asterisk or Astmanproxy
 * code (or at least the idea).\n
 * This functions use libeditline to manage the user interactive prompt.
 *  https://simtk.org/home/libeditline
 *
 */
#ifndef __ISAAC_REMOTE_H_
#define __ISAAC_REMOTE_H_
#include <histedit.h>

//! End code for client completion
#define AST_CLI_COMPLETE_EOF	"_EOF_"
//! Number of commands in history file
#define MAX_HISTORY_COMMAND_LENGTH 256
//! Max EditLine Input command length
#define EL_BUF_SIZE 512

/**
 *  Remote client flags
 *  This is actually only used to mark CLI as leaving
 */
struct remote_sig_flags
{
    //! The user requested to quit from CLI
    unsigned int need_quit :1;
};

/**
 * @brief Try to connect to CLI socket
 *
 * This function is used when isaac is invoked with -x parameter.
 * It will check if the unix socket for CLIs exists and can connnect to it
 *
 * @return 0 on connect success, 1 otherwise
 */
extern int
remote_tryconnect();

/**
 * @brief Main remote function, reads commands and send them to Isaac
 *
 * This function can be used to create a CLI prompt (passing NULL as data)
 * or execute a command and leave (passing the command as data)
 *
 * @param command to be executed or NULL for an interactive CLI
 */
extern void
remote_control(char* command);

/**
 * @brief Callback to write CLI prompt
 *
 * Editline callback for writting the prompt when required
 *
 * @param editline EditLine structure
 * @return A character string with the cli prompt
 */
extern char *
remote_prompt(EditLine *editline);

/**
 * @brief Send a special command to Isaac requesting command completion
 *
 * When the user press TAB key, special commands will be send to Isaac that
 * will try to complete the command with available possibilities.
 * This possibilities are written back to the CLI client using @ref
 * remote_display_match_list or directly on prompt if only one command
 * matchs the input
 *
 * @param editline EditLine structure
 * @param ch Last input character (Not used)
 * @return code for Editline to refresh or redisplay prompt info
 */
extern char *
remote_complete(EditLine *editline, int ch);

/**
 * @brief Prints a list of available options
 *
 * When @ref remote_complete returns more than one matching options
 * to autocomplete, they are printed back to the CLI using this function.
 *
 * @param matches An array of strings with the options
 * @param len Length of matches array
 * @param max Max output column lines
 * @return Number of options printed
 */
extern int
remote_display_match_list(char **matches, int len, int max);

/**
 * @brief Check if the given command request CLI exit
 *
 * This function will handle the exit command of CLI and also
 * store any input command into EditLine history file
 *
 * @param command Input command
 * @return 1 in case of exit command, 0 otherwise
 */
extern int
remote_consolehandler(char *command);

/**
 * @brief Marks the CLI as leaving
 *
 * Main function (@ref remote_control) will stay into an infinite loop
 * untill this function is called, requesting to leave
 *
 * @param num Signal number (not used)
 */
extern void
remote_quit_handler(int num);

/**
 * @brief Initialize EditLine structures and callbacks
 *
 * Initialize Editline and add all custom callbacks to manage the input,
 * prompt, history, etc
 *
 * @return 0 in case of success, -1 otherwise
 */
extern int
remote_el_initialize(void);

/**
 * @brief Editline callback for reading messages from Isaac
 *
 * This function will lock printing to screen all messages received from
 * Isaac CLI core until connection is closed or CLI finishes
 *
 * @param editline Editline structure
 * @param cp @todo Who knows
 * @return 0 in case of success, 1 otherwise
 */
extern int
remote_el_read_char(EditLine *editline, char *cp);

/**
 * @brief Splits an string with spaces into an array of words
 *
 * Mostly used to convert the response of Isaac matches to a list of
 * strings. @see remote_display_match_list
 *
 * @param buf Isaac return from a command completion
 * @return Given buffer splited into string
 */
extern char **
remote_el_strtoarr(char *buf);

/**
 * @brief Small wrapper to compare two strings
 *
 * Used to sort matched strings from remote_display_match_list
 *
 * @param i1 First string to compare
 * @param i2 Second string to compare
 * @return the same values as strcasecmp
 */
extern int
remote_el_sort_compare(const void *i1, const void *i2);

/**
 * @brief Store session commands to history file
 *
 * Used when CLI quits, stores session commands into history
 * file in user's homedir
 *
 * @param filename Full path to history file
 * @return >=0 on write success
 */
extern int
remote_el_write_history(char *filename);

/**
 * @brief Read previous sessions commands from history file
 *
 * Used when CLI starts, read previous session commands from history
 * file so it can be accesed in editline prompt
 *
 * @param filename Full path to history file
  @return >=0 on read success
 *
 */
extern int
remote_el_read_history(char *filename);

#endif /* __ISAAC_REMOTE_H_ */
