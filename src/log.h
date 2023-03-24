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
 * @file log.h
 * @author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * \brief Functions for sending messages to CLI or syslog
 *
 * This file contains all required functions to properly logging information in
 * Isaac. Most of these functions are taken from Asterisk PBX CLI, so credit them
 * for this fancy output.
 *
 * Log will be writen in the configured medium:
 * @see isaac_config
 *
 * And also to every active CLI interface will receive the logged message.
 *
 * The most used log levels are:
 * - LOG_DEBUG
 * - LOG_NOTICE
 * - LOG_WARNING
 * - LOG_ERROR
 *
 * The general format used for logging is the following
 *      [Date Hour] LEVEL: [ThreadID]: File:Line Function: Message
 *
 * For verbose messages it will be:
 *      -- Message
 *		> Message
 *		* Message
 *
 * @note If you create a new module, make it log through this interface.
 */

#ifndef __ISAAC_LOG_H_
#define __ISAAC_LOG_H_
#include <glib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <sys/syscall.h>

/**
 * @brief Available log mediums
 * This type is readed into @ref congig.log_type from isaac
 * configuration file.
 */
enum log_type
{
    //! Log to local syslog
        LOG_TYPE_SYSLOG = (1 << 1),
    //! Log to local file
        LOG_TYPE_FILE,
};

//#define LOG_EMERG       0       /* system is unusable */
//#define LOG_ALERT       1       /* action must be taken immediately */
//#define LOG_CRIT        2       /* critical conditions */
//#define LOG_ERR         3       /* error conditions */
//#define LOG_WARNING     4       /* warning conditions */
//#define LOG_NOTICE      5       /* normal but significant condition */
//#define LOG_INFO        6       /* informational */
//#define LOG_DEBUG       7       /* debug-level messages */

/**
 * @brief Some defines for LOG_LEVEL numbers
 *
 * We we'll use the numbers defined by syslog and create some new ones
 * because we're used to use them (ex. LOG_ERROR, LOG_VERBOSE,...)
 */
#define LOG_CRITICAL    LOG_CRIT
#define LOG_ERROR       LOG_ERR
#define LOG_VERBOSE     LOG_VERBOSE_1
#define LOG_VERBOSE_1   109
#define LOG_VERBOSE_2   110
#define LOG_VERBOSE_3   111
#define LOG_VERBOSE_4   112
#define LOG_NONE        999

#define DATEFORMAT    "%b %e %T"
#define MAX_MSG_SIZE    8192
#define TID             (long int)syscall(SYS_gettid)

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

/**
 * @brief Some macros for using from all program.
 *
 * You should use isaac_log, isaac_verbose and isaac_debug in the code, instead of invoking

 * isaac_log_location directly, unless it's a launcher log function in which we want to
 * get the origin filename, no the launcher filename to be printed in each message
 *
 */
#define isaac_log(log_type, ...)  isaac_log_location(log_type, __FILENAME__, __LINE__, __PRETTY_FUNCTION__, __VA_ARGS__)

/**
 * @brief Returns the log prefix for given type
 *
 * This will determine the colors of each header level or symbols in case of
 * verbose.
 *
 * @param       log_type        Log level as defined in syslog.h
 * @return Log prefix for selected message
 */
extern const char *
log_type_to_text(int log_type);

/**
 * @brief Prints a message to configured logged medium and CLI connections.
 *
 * This is the main logging function with format.
 * This will log into the configured medium in CFILE and to every active CLI
 * connection. Also, if Isaac is launched in debug mode (using -d) argument, it will
 * print to STDOUT too.
 *
 * Take into account that this will only write messages whose level are equal or less
 * than log_level configuration.
 *
 * @param       log_type        Log level to print the message
 * @param       file            Filename from this function has been invoked
 * @param       line            Line from this function has been invoked
 * @param       function        Function name from this function has been invoked
 * @param       fmt             Format of the message using printf notation
 * @param       ...             Message arguments for fmt
 */
extern void
isaac_log_location(int log_type, const char *file, int line, const char *function, const char *fmt,
                   ...);

/**
 * @brief Opens the log medium: File or Syslog
 *
 * This function open requested file for appending or syslog connection.
 *
 * @param       debug           Send messages to stdout
 * @return      TRUE            On Success opening the medium
 * @return      FALSE           On Opening Failure
 */
gboolean
start_logging(gboolean debug);

/**
 * @brief Closes log medium.
 *
 * This function close last opened log file or syslog connection
 *
 * @return 0 in all cases
 */
extern int
stop_logging();

/**
 * @brief Writes a message to log medium.
 *
 * This function will send the message to file or syslog, depending what medium
 * has been configured.
 *
 * @param       log_type        Log level to print the message
 * @param       message         Message to write to the medium
 */
extern void
write_log(int log_type, const char *message);

/**
 * @brief Remove all color from message
 *
 * This function will remove all color codes from the text to store it in
 * log medium.
 *
 * @param text Text to be cleaned (used for output too)
 */
extern void
clean_text(char *text);

#endif /* __ISAAC_LOG_H_ */
