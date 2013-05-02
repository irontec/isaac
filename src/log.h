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
 * \file log.h
 * \author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * \brief Functions for sending messages to CLI or syslog
 *
 * This file contains all required functions to properly logging information in
 * Isaac. Most of these functions are taken from Asterisk PBX CLI, so credit them
 * for this fancy output.
 *
 * Log will be writen in the configured medium:
 * \see isaac_config
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
 * \note If you create a new module, make it log through this interface.
 */

#ifndef __ISAAC_LOG_H_
#define __ISAAC_LOG_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>

/**
 * \brief Some defines for LOG_LEVEL numbers.
 *
 * We we'll use the numbers defined by syslog and create some new ones
 * because we're used to use them (ex. LOG_ERROR, LOG_VERBOSE,...)
 */
#define DATEFORMAT	"%b %e %T"
#define LOG_TYPE_SYSLOG	"syslog"
#define LOG_TYPE_FILE	"file"
#define LOG_VERBOSE_1 	109
#define LOG_VERBOSE_2 	110
#define LOG_VERBOSE_3 	111
#define LOG_VERBOSE_4	112
#define LOG_NONE	999
#define LOG_CRITICAL	LOG_CRIT
#define LOG_ERROR	LOG_ERR
#define LOG_VERBOSE 	LOG_VERBOSE_1
#define MAX_MSG_SIZE	8192
#define TID             (long int)syscall(SYS_gettid)

/**
 * \brief Some macros for using from all program.
 *
 * You should use isaac_log, isaac_verbose and isaac_debug in the code, instead of invoking
 * isaac_log_location directly, unless it's a launcher log function in which we want to
 * get the origin filename, no the launcher filename to be printed in each message
 *
 */
#define __SHORT_FORM_OF_FILE__  (strrchr(__FILE__,'/')? strrchr(__FILE__,'/')+1 : __FILE__ )
#define isaac_log(log_type, ...)  isaac_log_location(log_type, __SHORT_FORM_OF_FILE__, __LINE__, __PRETTY_FUNCTION__, __VA_ARGS__)
#define isaac_verbose(...) isaac_log(LOG_VERBOSE, __VA_ARGS__)
#define isaac_debug(...) isaac_log(LOG_DEBUG, __VA_ARGS__)

/**
 * \brief Returns the log prefix for given type
 *
 * This will determine the colors of each header level or symbols in case of
 * verbose.
 *
 * \param       log_type        Log level as defined in syslog.h
 * \param       colour          Boolean for output with or without color.
 * \return Log prefix for selected message
 */
extern const char *
log_type_to_text(int log_type, int colour);

/**
 * \brief Prints a message to configured logged medium and CLI connections.
 *
 * This is the main logging function with format.
 * This will log into the configured medium in CFILE and to every active CLI
 * connection. Also, if IronSC is launched in debug mode (using -d) argument, it will
 * print to STDOUT too.
 *
 * Take into account that this will only write messages whose level are equal or less
 * than log_level configuration.
 *
 * \param       log_type        Log level to print the message
 * \param       file            Filename from this function has been invoked
 * \param       line            Line from this function has been invoked
 * \param       function        Function name from this function has been invoked
 * \param       fmt             Format of the message using printf notation
 * \param       ...             Message arguments for fmt
 */
extern void
isaac_log_location(int log_type, const char *file, int line, const char *function, const char *fmt,
        ...);

/**
 * \brief Opens the log medium: File or Syslog
 *
 * This function open requested file for appending or syslog connection.
 *
 * \param	logfile      Full path to log file
 * \return	0            On Success opening the file
 * \return	1            On Opening Failure
 */
extern int
open_log(const char *logfile);

/**
 * \brief Closes log medium.
 *
 * This function close last opened log file or syslog connection
 */
extern void
close_log();

/**
 * \brief Writes a message to log medium.
 *
 * This function will send the message to file or syslog, depending what medium
 * has been configured.
 */
extern void
write_log(int log_type, const char *message);

#endif /* __ISAAC_LOG_H_ */
