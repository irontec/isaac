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
 * \file main.c
 * \author Iván Alonso [aka Kaian] <kaian@irontec.com>
 */
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "config.h"
#include "pidfile.h"
#include "module.h"
#include "manager.h"
#include "server.h"
#include "log.h"

int debug; ///< Debug level. The more -d, the more debug
int opt_execute = 0; ///< Determines CLI behaviour
struct timeval isaac_startuptime; ///< Starting time, used to count the uptime time

/**
 * \brief Prints program version and exits
 */
void version()
{
    printf("%s: Version %s, (C) 2013 Irontec S.L. \n", PACKAGE_NAME, VERSION);
    printf("Created by Ivan Alonso [aka Kaian] <kaian@irontec.com>\n");
    exit(EXIT_SUCCESS);
}

/**
 * \brief Print usage info and exits
 *
 * \param progname binary file name
 */
void usage(const char* progname)
{
    printf("%s: Version %s, (C) 2013 Irontec S.L. \n", PACKAGE_NAME, VERSION);
    printf("Created by Ivan Alonso [aka Kaian] <kaian@irontec.com>\n\n");
    printf("Usage: %s [-d|-h|-v]\n", progname);
    printf(" -d : Start in Debug Mode\n");
    printf(" -h : Displays this usage\n");
    printf(" -v : Displays version information\n");
    printf("Start with no options to run as daemon\n");
    exit(EXIT_SUCCESS);
}

/**
 * \brief Quit handler function
 *
 * This function will do all necesary cleanup before exiting
 * the program. Use this instead of exit() if launchers, satelites,
 * cli or scheduler are still running.
 *
 * \param sig Received signal code
 * \todo Implement Service cleanup
 */
void quit(int sig)
{
    printf("Signal %d received\n", sig);
    /** Notify clients before closing CLI server thread */
    //if (sig == SIGHUP) sat_log(LOG_VERBOSE, "\e[1;37m%s will restart now.\e[0m\n", APP_NAME);
    /** Remove Pidfile. */
    remove_pid(PIDFILE);

    // if requested to restart
    //if (sig == SIGHUP) execvp(_argv[0], _argv);
    // Exit the program!
    exit(EXIT_SUCCESS);
}

/**
 * \brief Main program function
 *
 * This functions parse command line options to determine satcon behaviour
 * This progran can be used as a Satelite process controler or a CLI client
 * if -r option is specified.
 *
 * \param argc Argument counter
 * \param argv Array of string arguments passed to the program
 */
int main(int argc, char *argv[])
{
    pid_t pid;
    int opt_remote = 0;
    char opt;

    // Parse commandline arguments
    while ((opt = getopt(argc, argv, "dhrvx:")) != EOF) {
        switch (opt) {
        case 'd':
            debug++;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        case 'r':
            opt_remote++;
            break;
        case 'x':
            opt_execute++;
            opt_remote++; // This is implicit in 'x'
            //xarg = strdup(optarg);
            break;
        case 'v':
            version();
            return 0;
        case '?':
            usage(argv[0]);
            return 1;
        }
    }

    // Check if there is an Isaac is already running
    if (0/*cli_tryconnect()*/) {
        if (opt_remote && !opt_execute) {
            //cli_remotecontrol(NULL);
            return 0;
        } else if (opt_remote && opt_execute) {
            //cli_remotecontrol(xarg);
            return 0;
        } else {
            fprintf(stderr, "Isaac already running on %s.  Use '%s -r' to connect.\n", CLI_SOCKET,
                    argv[0]);
            return 1;
        }
    } else if (opt_remote) {
        fprintf(stderr, "Unable to connect to remote Isaac (does %s exist?)\n", CLI_SOCKET);
        exit(1);
    }

    /* If we are not in debug mode, then fork to background */
    if (!debug) {
        if ((pid = fork()) < 0)
            exit(1);
        else if (pid > 0) exit(0);
    }

    // Setup signal handlers
    (void) signal(SIGINT, quit);
    (void) signal(SIGTERM, quit);
    (void) signal(SIGPIPE, SIG_IGN);

    // Write current pid to file.
    write_pid(PIDFILE);

    // Read configuration files
    //read_config();

    // Initialize logging
    //start_logging()

    // scheduler_start

    // Load Modules. The contain the server Applications
    if (load_modules() != 0) {
        exit(EXIT_FAILURE);
    }

    // Start manager thread
    if (start_manager("10.10.9.40",5038,"ironadmin","adminsecret") != 0) {
        exit(EXIT_FAILURE);
    }

    // Start cli service

    // Start server thread
    if (start_server("0.0.0.0", 5138) == -1) {
        exit(EXIT_FAILURE);
    }

    // All subsystems Up!
    isaac_log(LOG_NONE, "\e[1;37m%s Ready.\e[0m\n", PACKAGE_NAME);

    // Wait here until any signal is sent
    pause();

    // Unreachable code :D
    return 0;
}
