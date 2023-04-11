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
#include <glib.h>
#include <glib-unix.h>
#include "module.h"
#include "manager.h"
#include "log.h"
#include "cfg.h"
#include "cli.h"
#include "remote.h"
#include "server.h"
#include "util.h"

//! Program global main loop
GMainLoop *main_loop;

void
print_version()
{
    printf("%s: Version %s, (C) 2013 Irontec S.L. \n", PACKAGE_NAME, PACKAGE_VERSION);
    printf("Created by Ivan Alonso [aka Kaian] <kaian@irontec.com>\n");
}

static gboolean
signal_handler(G_GNUC_UNUSED gpointer user_data)
{
    g_print("Signal Received\n");
    g_main_loop_quit(main_loop);
    return G_SOURCE_REMOVE;
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
    GError *error = NULL;
    gchar *opt_execute = NULL;
    gboolean opt_version = FALSE;
    gboolean opt_debug = FALSE;
    gboolean opt_remote = FALSE;

    GOptionEntry main_entries[] = {
            {"version", 'v', 0, G_OPTION_ARG_NONE,   &opt_version, "Version information",                 NULL},
            {"debug",   'd', 0, G_OPTION_ARG_NONE,   &opt_debug,   "Start in debug mode",                 NULL},
            {"remote",  'r', 0, G_OPTION_ARG_NONE,   &opt_remote,  "Connect CLI to running isaac daemon", NULL},
            {"execute", 'x', 0, G_OPTION_ARG_STRING, &opt_execute, "Execute CLI command and exit",        NULL},
            {NULL}
    };

    /************************** Command Line Parsing **************************/
    GOptionContext *context = g_option_context_new("[-d|-r|-h|-v|-x command]");
    g_option_context_add_main_entries(context, main_entries, NULL);
    g_option_context_set_help_enabled(context, TRUE);
    g_option_context_parse(context, &argc, &argv, &error);
    g_option_context_free(context);

    if (error != NULL) {
        g_printerr("Options parsing failed: %s\n", error->message);
        return 1;
    }

    // Parse command line arguments that have high priority
    if (opt_version) {
        print_version();
        return 0;
    }

    // Check if there is an Isaac is already running
    if (opt_remote) {
        if (remote_tryconnect() == 0) {
            if (!opt_execute) {
                remote_control(NULL);
                return 0;
            } else {
                remote_control(opt_execute);
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
    if (!opt_debug) {
        if ((pid = fork()) < 0)
            exit(1);
        else if (pid > 0)
            exit(0);
    }

    // Setup signal handlers
    g_unix_signal_add(SIGINT, signal_handler, NULL);
    g_unix_signal_add(SIGTERM, signal_handler, NULL);

    // Create main loop for default context
    main_loop = g_main_loop_new(NULL, FALSE);

    // Read configuration files
    if (cfg_read(CFILE) != 0) {
        fprintf(stderr, "Failed to read configuration file %s\n", CFILE);
        return 1;
    }

    // Initialize logging
    if (!start_logging(opt_debug)) {
        fprintf(stderr, "Failed to read configuration file %s\n", CFILE);
        return 1;
    }

    // Load Modules. The contain the server Applications
    if (load_modules() != 0) {
        return 1;
    }

    // Start manager thread
    if (!start_manager()) {
        return 1;
    }

    // Start cli service
    if (!cli_server_start()) {
        return 1;
    }

    // Start server thread
    if (!server_start()) {
        return 1;
    }

    // All subsystems Up!
    isaac_log(LOG_NONE, "\033[1;37m%s is Ready.\033[0m\n", PACKAGE_NAME);

    // Wait here until any signal is sent
    g_main_loop_run(main_loop);

    // Stop server thread
    server_stop();

    // Stop CLI server thread
    cli_server_stop();

    // Stop manager thread
    stop_manager();

    // Remove all loaded modules. They should unregister their apps
    unload_modules();

    return 0;
}
