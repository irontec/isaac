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
 * @file isaac.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 * @brief Main applications functions,  usable from any part of the program.
 *
 * This file will define the functions that manage the configuration and also
 * the application initialize and exit process
 */

#ifndef __ISAAC_H_
#define __ISAAC_H_

#include "config.h"
#include <stdlib.h>

//! Sorter declaration of isaac_cfg struct
typedef struct isaac_cfg cfg_t;
typedef struct isaac_stats stats_t;

/**
 * @brief Application configuration
 *
 * This structure stores all information readed from CFILE
 * in @ref read_config.
 * It should include manager, server, log configuration.
 *
 */
struct isaac_cfg
{
    char manaddr[18];
    int manport;
    char manuser[20];
    char manpass[20];
    char listenaddr[18];
    int listenport;
    int logtype;
    int loglevel;
    char logfile[256];
    char logtag[20];
};

/**
 * @brief Application stats
 *
 * This structure contains Isaac informational data, that
 * should not be required to be run, but gives extra information
 * for CLI commands.
 */
struct isaac_stats
{
    //! Starting time, used to count the uptime time
    struct timeval startuptime;
    //! Session counter stat
    int sessioncnt;
};

//! Status structure, for information in some commands
extern stats_t stats;
//! Configuration structure, readed from CFILE
extern cfg_t config;
//! Debug flag (for -d argument)
extern int debug;

/**
 * @brief Prints program version and copyright information
 */
extern void
version();

/**
 * @brief Print usage info and exits
 * @param progname binary file name
 */
extern void
usage(const char* progname);

/**
 * @brief Quit handler function
 *
 * This function will do all necesary cleanup before exiting
 * the program. Use this instead of exit() if any session is
 * still running.
 *
 * @param exitcode Received/Forced signal code
 * @todo Implement all services cleanup
 */
extern void
quit(int exitcode);

/**
 * @brief Read configuration in libconfig format from given file
 *
 * This function will manage all readed configurations from
 * configuration file (usually %sysconfdir%/isaac/isaac.conf)
 *
 * @param cfile Configuration file full path
 * @returns 0 in case of read success, -1 otherwise
 */
extern int
read_config(const char *cfile);

/**
 * @brief Main program function
 *
 * This functions parse command line options to determine isaac behaviour
 * This progran can be used as a applications server or a CLI client
 * if -r option is specified.
 *
 * @param argc Argument counter
 * @param argv Array of string arguments passed to the program
 */
extern int
main(int argc, char *argv[]);

#endif /* __ISAAC_H_ */
