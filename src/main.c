/*****************************************************************************
 ** Isaac -- Ivozng simplified Asterisk AMI Connector
 **
 ** Copyright (C) 2013-2015 Irontec S.L.
 ** Copyright (C) 2013-2015 Ivan Alonso (aka Kaian)
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
 * @file isaac.c
 * @author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source code for funtions defined in isaac.h
 *
 * Isaac is a small application that serves as interface and translator for
 * Asterisk Manager Interface (aka AMI). It runs applications that can send
 * request commands through AMI and parse received messages.
 *
 */
#include "config.h"
#include <unistd.h>
#include <signal.h>
#include "module.h"
#include "manager.h"
#include "log.h"
#include "cfg.h"
#include "cli.h"
#include "remote.h"
#include "server.h"
#include "util.h"

//! Isaac configuration options
cfg_t config;

//! Determines CLI behaviour
int opt_execute = 0;
//! Debug flag (for -d argument)
int debug = 0;

void
version()
{
    printf("%s: Version %s, (C) 2013 Irontec S.L. \n", PACKAGE_NAME, PACKAGE_VERSION);
    printf("Created by Ivan Alonso [aka Kaian] <kaian@irontec.com>\n");
}

void
usage()
{
    version();

    printf("\nUsage: %s [-d|-r|-h|-v|-x command]\n", PACKAGE_NAME);
    printf(" -d : Start in Debug Mode\n");
    printf(" -r : Start in CLI client Mode\n");
    printf(" -x : Run CLI command and exit\n");
    printf(" -h : Displays this usage\n");
    printf(" -v : Displays version information\n");
    printf("Start with no options to run as daemon\n");
}

void
quit(int exitcode)
{
    printf("Signal %d received\n", exitcode);
    // Stop server thread
    stop_server();
    // Stop CLI server thread
    cli_server_stop();
    // Stop manager thread
    stop_manager();
    // Remove all loaded modules. They should unregister their apps
    unload_modules();
    // if requested to restart
    //if (sig == SIGHUP) execvp(_argv[0], _argv);
    // Exit the program!
    exit(exitcode);
}

/**
 * \brief Main program function
 *
 * This functions parse command line options to determine Isaac behaviour
 * This progran can be used as a Isaac process or a CLI client
 * if -r option is specified.
 *
 * \param argc Argument counter
 * \param argv Array of string arguments passed to the program
 */
int
main(int argc, char *argv[])
{
    pid_t pid;
    int opt_remote = 0;
    char opt;
    char * xarg = NULL;

    // Parse commandline arguments
    while ((opt = getopt(argc, argv, "dhrvx:")) != EOF) {
        switch (opt) {
        case 'd':
            debug++;
            break;
        case 'r':
            opt_remote++;
            break;
        case 'x':
            opt_execute++;
            opt_remote++; // This is implicit in 'x'
            xarg = strdup(optarg);
            break;
        case 'v':
            version();
            exit(EXIT_SUCCESS);
        case 'h':
        case '?':
            usage();
            exit(EXIT_SUCCESS);
        }
    }

    // Check if there is an Isaac is already running
    if (opt_remote) {
        if (remote_tryconnect() == 0) {
            if (!opt_execute) {
                remote_control(NULL);
                return 0;
            } else {
                remote_control(xarg);
                return 0;
            }
        } else {
            fprintf(stderr, "Unable to connect to remote Isaac (does %s exist?)\n", CLI_SOCKET);
            exit(1);
        }
    } else {
        // Check Isaac is not already running
        if (access(CLI_SOCKET, F_OK) == 0) {
            fprintf(stderr, "%s already running on %s. Use '%s -r' to connect\n", argv[0],
                    CLI_SOCKET, argv[0]);
            exit(1);
        }
    }

    // If we are not in debug mode, then fork to background
    if (!debug) {
        if ((pid = fork()) < 0)
            exit(1);
        else if (pid > 0)
            exit(0);
    }

    cfg_init(&config);

    // Setup signal handlers
    (void) signal(SIGINT, quit);
    (void) signal(SIGTERM, quit);
    (void) signal(SIGPIPE, SIG_IGN);

    // Read configuration files
    if (cfg_read(&config, CFILE) != 0) {
        fprintf(stderr, "Failed to read configuration file %s\n", CFILE);
        quit(EXIT_FAILURE);
    }

    // Initialize logging
    if (start_logging(config.logtype, config.logfile, config.logtag, config.loglevel) != 0) {
        fprintf(stderr, "Failed to read configuration file %s\n", CFILE);
        quit(EXIT_FAILURE);
    }

    // Load Modules. The contain the server Applications
    if (load_modules() != 0) {
        quit(EXIT_FAILURE);
    }

    // Start manager thread
    if (start_manager(config.manaddr, config.manport, config.manuser, config.manpass) != 0) {
        quit(EXIT_FAILURE);
    }

    // Start cli service
    if (cli_server_start() != 0) {
        quit(EXIT_FAILURE);
    }
    
        // Start server thread
    if (start_server(config.listenaddr, config.listenport) == -1) {
        quit(EXIT_FAILURE);
    }

    // All subsystems Up!
    isaac_log(LOG_NONE, "\e[1;37m%s Ready.\e[0m\n", PACKAGE_NAME);

    // Wait here until any signal is sent
    pause();

    // Unreachable code :D
    return 0;
}
