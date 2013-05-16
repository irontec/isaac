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
 *
 * \brief Main Initialization and shutdown functions
 */
#include "isaac.h"
#include <unistd.h>
#include <signal.h>
#include <libconfig.h>
#include "pidfile.h"
#include "module.h"
#include "manager.h"
#include "server.h"
#include "log.h"
#include "cli.h"
#include "remote.h"
#include "util.h"


//! Determines CLI behaviour
int opt_execute = 0;
//! Status structure, for information in some commands
stats_t stats;
//! Configuration structure, readed from CFILE
cfg_t config;
//! Debug flag (for -d argument)
int debug = 0;

void
version()
{
    printf("%s: Version %s, (C) 2013 Irontec S.L. \n", APP_NAME, APP_VERSION);
    printf("Created by Ivan Alonso [aka Kaian] <kaian@irontec.com>\n");
}

void
usage(const char* progname)
{
    printf("\nUsage: %s [-d|-r|-h|-v|-x command]\n", progname);
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
    /** Notify clients before closing CLI server thread */
    //if (sig == SIGHUP) sat_log(LOG_VERBOSE, "\e[1;37m%s will restart now.\e[0m\n", APP_NAME);
    // Stop server thread
    stop_server();
    // Remove all loaded modules. They should unregister their apps
    unload_modules();
    // Remove pidfile
    remove_pid(PIDFILE);
    // if requested to restart
    //if (sig == SIGHUP) execvp(_argv[0], _argv);
    // Exit the program!
    exit(exitcode);
}

int
read_config(const char *cfile)
{
    config_t cfg;
    config_setting_t *cat, *sett;
    int i, j;
    const char *catname = "", *settname = "";
    // Initialize configuration
    config_init(&cfg);
    isaac_log(LOG_VERBOSE, "Reading configuration from file %s\n", cfile);

    // Read configuraiton file
    if (config_read_file(&cfg, cfile) == CONFIG_FALSE) {
        isaac_log(LOG_ERROR, "Error parsing configuration file %s on line %d: %s\n", cfile,
                config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return -1;
    }

    // Parse the configuration file to get the known settings
    config_setting_t *root = config_root_setting(&cfg);
    for (i = 0; i < config_setting_length(root); i++) {
        cat = config_setting_get_elem(root, i);
        catname = config_setting_name(cat);

        if (!strcasecmp(catname, "manager")) {
            // Get manager connection settings
            for (j = 0; j < config_setting_length(cat); j++) {
                sett = config_setting_get_elem(cat, j);
                settname = config_setting_name(sett);
                if (!strcasecmp(settname, "address")) {
                    strcpy(config.manaddr, config_setting_get_string(sett));
                } else if (!strcasecmp(settname, "port")) {
                    config.manport = config_setting_get_int(sett);
                } else if (!strcasecmp(settname, "username")) {
                    strcpy(config.manuser, config_setting_get_string(sett));
                } else if (!strcasecmp(settname, "secret")) {
                    strcpy(config.manpass, config_setting_get_string(sett));
                }
            }
        } else if (!strcasecmp(catname, "server")) {
            // Get session server settings
            for (j = 0; j < config_setting_length(cat); j++) {
                sett = config_setting_get_elem(cat, j);
                settname = config_setting_name(sett);
                if (!strcasecmp(settname, "address")) {
                    strcpy(config.listenaddr, config_setting_get_string(sett));
                } else if (!strcasecmp(settname, "port")) {
                    config.listenport = config_setting_get_int(sett);
                }
            }
        } else if (!strcasecmp(catname, "log")) {
            // Get logging settings
            for (j = 0; j < config_setting_length(cat); j++) {
                sett = config_setting_get_elem(cat, j);
                settname = config_setting_name(sett);
                if (!strcasecmp(settname, "type")) {
                    const char *logtype = config_setting_get_string(sett);
                    if (!strcasecmp("syslog", logtype)) {
                        config.logtype = LOG_TYPE_SYSLOG;
                    } else if (!strcasecmp("file", logtype)) {
                        config.logtype = LOG_TYPE_FILE;
                    } else {
                        isaac_log(LOG_WARNING, "Unknown logtype %s\n", logtype);
                    }
                } else if (!strcasecmp(settname, "level")) {
                    config.loglevel = config_setting_get_int(sett);
                } else if (!strcasecmp(settname, "file")) {
                    strcpy(config.logfile, config_setting_get_string(sett));
                } else if (!strcasecmp(settname, "tag")) {
                    strcpy(config.logtag, config_setting_get_string(sett));
                }
            }
        } else {
            isaac_log(LOG_WARNING, "Unkown category %s\n", settname);
        }
    }

    return 0;
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
            version();
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        }
    }

    // Check if there is an Isaac is already running
    if (cli_tryconnect()) {
        if (opt_remote && !opt_execute) {
            cli_remotecontrol(NULL);
            return 0;
        } else if (opt_remote && opt_execute) {
            cli_remotecontrol(xarg);
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

    // If we are not in debug mode, then fork to background
    if (!debug) {
        if ((pid = fork()) < 0) exit(1);
        else if (pid > 0) exit(0);
    }

    // Initialize stored stats
    stats.startuptime = isaac_tvnow();
    stats.sessioncnt = 0;

    // Setup signal handlers
    (void) signal(SIGINT, quit);
    (void) signal(SIGTERM, quit);
    (void) signal(SIGPIPE, SIG_IGN);

    // Write current pid to file.
    write_pid(PIDFILE);

    // Read configuration files
    if (read_config(CFILE) != 0) {
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
    if (cli_server_start() != 0){
        quit(EXIT_FAILURE);
    }

    // Start server thread
    if (start_server(config.listenaddr, config.listenport) == -1) {
        quit(EXIT_FAILURE);
    }

    // All subsystems Up!
    isaac_log(LOG_NONE, "\e[1;37m%s Ready.\e[0m\n", APP_NAME);

    // Wait here until any signal is sent
    pause();

    // Unreachable code :D
    return 0;
}
