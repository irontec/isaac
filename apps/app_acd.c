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
 * @file app_acd.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Module for manage IronACD actions
 *
 * @warning This module is customized for Ivoz-NG. If won't work without the
 *  required karma files.
 *
 * This is a special module that spawns a php for its actions.
 * This allow the VoIP developers to work in a more familiar environment.
 */
#include "config.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <libconfig.h>
#include <stdio.h>
#include <stdlib.h>
#include "app.h"
#include "log.h"
#include "util.h"

/**
 * @brief Module configuration readed from ACDCONF file
 *
 * @see read_acd_config
 */
struct app_acd_config
{
    //! PHP File to spawn
    char phpfile[80];

} acd_config;

/**
 * @brief Read module configure options
 *
 * This function will read ACDCONF file and fill app_acd_config
 * structure.
 *
 * @param cfile Full path to configuration file
 * @return 0 in case of read success, -1 otherwise
 */
int
read_acd_config(const char *cfile)
{
    config_t cfg;
    const char *value;

    // Initialize configuration
    config_init(&cfg);

    // Read configuraiton file
    if (config_read_file(&cfg, cfile) == CONFIG_FALSE) {
        isaac_log(LOG_ERROR, "Error parsing configuration file %s on line %d: %s\n", cfile,
                config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return -1;
    }

    // Get PHP file that will be spawned in this module
    if (config_lookup_string(&cfg, "acd.php_file", &value) == CONFIG_TRUE) {
        strcpy(acd_config.phpfile, value);
    }
    // Dealloc libconfig structure
    config_destroy(&cfg);
    isaac_log(LOG_VERBOSE_3, "Readed configuration from %s\n", cfile);
    return 0;
}

/**
 * Copyright 2009-2010 Bart Trojanowski <bart@jukie.net>
 * Licensed under GPLv2, or later, at your choosing.
 *
 * bidirectional popen() call
 *
 * @param rwepipe - int array of sockets
 * @param exe - program to run
 * @param argv - argument list
 * @return pid or -1 on error
 *
 * The caller passes in an array of three integers (rwepipe), on successful
 * execution it can then write to element 0 (stdin of exe), and read from
 * element 1 (stdout) and 2 (stderr).
 */
static int
popenRWE(int *rwepipe, const char *exe, const char * const argv[])
{
    int err[2];
    int pid;
    int rc;

    rc = pipe(err);
    if (rc < 0) return rc;

    pid = fork();
    if (pid > 0) {
        // Parent, store the first side of the pipe
        *rwepipe = err[0];
        // Close the other part, we wont send anything
        close(err[1]);
        return pid;
    } else if (pid == 0) {
        // Child, replace STDERR with the second side of the pipe
        close(2);
        dup(err[1]);
        // Close the other part, we wont send anything
        close(err[0]);
        execvp(exe, (char**) argv);
    } else {
        // Error, close both sides of the pipe
        close(err[0]);
        close(err[1]);
        return -1;
    }

    return pid;
}

/**
 * Copyright 2009-2010 Bart Trojanowski <bart@jukie.net>
 * Licensed under GPLv2, or later, at your choosing.
 *
 * @brief Stops a process opened with popenRWE
 *
 * @param pid The pid of the child process
 */
static int
pcloseRWE(int pid, int *rwepipe)
{
    int status;
    close(*rwepipe);
    waitpid(pid, &status, 0);
    return status;
}

int
acd_exec(session_t *sess, app_t *app, const char *args)
{
    int pid;
    int out = 0;
    FILE *fd;
    char * line = NULL;
    char extraparams[256];
    size_t len = 0;
    char interface[40], action[20];

    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Initialize
    memset(extraparams, 0, 256);
    memset(action, 0, 20);
    memset(interface, 0, 40);

    // Get the ACD Action
    isaac_strcpy(action, app->name);
    sscanf(action, "ACD%s", action);

    if (!strcasecmp(action, "LOGIN")) {
        // Get Login parameteres
        if (sscanf(args, "%s", interface) != 1) {
            return INVALID_ARGUMENTS;
        }
    } else if (!strcasecmp(action, "PAUSE")) {
        // Check if whe have a pausetype
        sscanf(args, "%[^\n]", extraparams);
    } else if (!strcasecmp(app->name, "QueueJoin")) {
        // Get Queue name
        if (sscanf(args, "%[^\n]", extraparams) != 1) {
            return INVALID_ARGUMENTS;
        }
        strcpy(action, "JOIN");
    } else if (!strcasecmp(app->name, "QueueLeave")) {
        // Get Queue name
        if (sscanf(args, "%[^\n]", extraparams) != 1) {
            return INVALID_ARGUMENTS;
        }
        strcpy(action, "LEAVE");
    } else {
        memset(interface, 0, sizeof(interface));
    }

    const char * const php_args[] = {
            "php",
            acd_config.phpfile,
            interface,
            session_get_variable(sess, "AGENT"),
            action,
            extraparams,
            NULL };

    // Some logging
    isaac_log(LOG_DEBUG, "Spawing PHP: %s\n", php_args[1]);

    // Open the requested file, load I/O file descriptors
    pid = popenRWE(&out, php_args[0], php_args);

    // Open file input descriptor and read the php script output
    fd = fdopen(out, "r");
    if (getline(&line, &len, fd) != -1) {
        session_write(sess, "%s", line);
    }
    // Stops spawned php
    pcloseRWE(pid, &out);

    return 0;
}

/**
 * @brief Module load entry point
 *
 * Load module configuration and applications
 *
 * @retval 0 if all applications and configuration has been loaded
 * @retval -1 if any application fails to register or configuration can not be readed
 */
int
load_module()
{
    int res = 0;
    if (read_acd_config(ACDCONF) != 0) {
        isaac_log(LOG_ERROR, "Failed to read app_acd config file %s\n", ACDCONF);
        return -1;
    }
    res |= application_register("ACDStatus", acd_exec);
    res |= application_register("ACDLogin", acd_exec);
    res |= application_register("ACDLogout", acd_exec);
    res |= application_register("ACDPause", acd_exec);
    res |= application_register("ACDUnpause", acd_exec);
    res |= application_register("QueueJoin", acd_exec);
    res |= application_register("QueueLeave", acd_exec);
    return res;
}

/**
 * @brief Module unload entry point
 *
 * Unload module applications
 *
 * @return 0 if all applications are unloaded, -1 otherwise
 */
int
unload_module()
{
    int res = 0;
    res |= application_unregister("ACDStatus");
    res |= application_unregister("ACDLogin");
    res |= application_unregister("ACDLogout");
    res |= application_unregister("ACDPause");
    res |= application_unregister("ACDUnpause");
    res |= application_unregister("QueueJoin");
    res |= application_unregister("QueueLeave");
    return res;
}
