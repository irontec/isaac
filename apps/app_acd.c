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

    isaac_log(LOG_VERBOSE_3, "Readed configuration from %s\n", cfile);
    return 0;
}

/**
 * Copyright 2009-2010 Bart Trojanowski <bart@jukie.net>
 * Licensed under GPLv2, or later, at your choosing.
 *
 * bidirectional popen() call
 *
 * @param rwepipe - int array of size three
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
    int in[2];
    int out[2];
    int err[2];
    int pid;
    int rc;

    rc = pipe(in);
    if (rc < 0) goto error_in;

    rc = pipe(out);
    if (rc < 0) goto error_out;

    rc = pipe(err);
    if (rc < 0) goto error_err;

    pid = fork();
    if (pid > 0) { // parent
        close(in[0]);
        close(out[1]);
        close(err[1]);
        rwepipe[0] = in[1];
        rwepipe[1] = out[0];
        rwepipe[2] = err[0];
        return pid;
    } else if (pid == 0) { // child
        close(in[1]);
        close(out[0]);
        close(err[0]);
        close(0);
        dup(in[0]);
        close(1);
        dup(out[1]);
        close(2);
        dup(err[1]);

        execvp(exe, (char**) argv);
    } else
        goto error_fork;

    return pid;

    error_fork: close(err[0]);
    close(err[1]);
    error_err: close(out[0]);
    close(out[1]);
    error_out: close(in[0]);
    close(in[1]);
    error_in: return -1;
}

static int
pcloseRWE(int pid, int *rwepipe)
{
    int rc, status;
    close(rwepipe[0]);
    close(rwepipe[1]);
    close(rwepipe[2]);
    kill(pid, SIGQUIT);
    rc = waitpid(pid, &status, 0);
    return status;
}

int
acd_exec(session_t *sess, const char * const php_args[])
{
    int pid;
    int fds[3];
    FILE *fd;
    char * line = NULL;
    size_t len = 0;

    // Some logging
    isaac_log(LOG_DEBUG, "Spawing PHP: %s\n", php_args[1]);

    // Open the requested file, load I/O file descriptors
    pid = popenRWE(fds, php_args[0], php_args);

    // Open file input descriptor
    fd = fdopen(fds[1], "r");

    if (getline(&line, &len, fd) != -1) {
        session_write(sess, "%s", line);
    }

    return 0;

}

int
acd_login_exec(session_t *sess, const char *args)
{
    char interface[40];

    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Get Login parameteres
    if (sscanf(args, "%s", interface) != 1) {
        return INVALID_ARGUMENTS;
    }

    const char * const php_args[] = {
            "php",
            acd_config.phpfile,
            interface,
            session_get_variable(sess, "AGENT"),
            "LOGIN",
            NULL };

    return acd_exec(sess, php_args);
}

int
acd_logout_exec(session_t *sess, const char *args)
{

    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    const char * const php_args[] = {
            "php",
            acd_config.phpfile,
            "",
            session_get_variable(sess, "AGENT"),
            "LOGOUT",
            NULL };

    return acd_exec(sess, php_args);
}

int
acd_pause_exec(session_t *sess, const char *args)
{

    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    const char * const php_args[] = {
            "php",
            acd_config.phpfile,
            "",
            session_get_variable(sess, "AGENT"),
            "PAUSE",
            NULL };

    return acd_exec(sess, php_args);
}

int
acd_unpause_exec(session_t *sess, const char *args)
{

    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    const char * const php_args[] = {
            "php",
            acd_config.phpfile,
            "",
            session_get_variable(sess, "AGENT"),
            "UNPAUSE",
            NULL };

    return acd_exec(sess, php_args);
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
    res |= application_register("ACDLOGIN", acd_login_exec);
    res |= application_register("ACDLOGOUT", acd_logout_exec);
    res |= application_register("ACDPAUSE", acd_pause_exec);
    res |= application_register("ACDUNPAUSE", acd_unpause_exec);
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
    return res;
}
