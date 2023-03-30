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
 * @file app.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions for managing loadable applications from @ref isaac_module.
 *
 * This file contains the functions to register new applications into
 * isaac core.\n
 * Be sure to include this file in any application before any other
 * system header, because it has system defines that change the behaviour of
 * standard headers.
 *
 * @todo Create iterator for application list and create, destroy and next funcs
 */

#ifndef _ISAAC_APP_H
#define _ISAAC_APP_H

#include "session.h"

/* Define the actionid Length */
#define ACTIONID_LEN 1024
/* Define maximum argument length */
#define ARGUMENT_LEN 128
/* Define maximum argument count */
#define ARGUMENT_MAX 25

/**
 * @brief Common exit codes for applications.
 *
 * If your application returns any of this common errors, corresponding
 * message generated by apperr2str will be send trough the session
 * connection.
 */
enum ApplicationErrors
{
    //! Session has not been authenticated
    NOT_AUTHENTICATED = 101,
    //! Session requested an application not registered
    UNKNOWN_ACTION = 102,
    //! Application requires different number arguments
    INVALID_ARGUMENTS = 103,
    //! Application requires different arguments types
    INVALID_FORMAT = 104,
    //! Application has encountered some problems during execution
    INTERNAL_ERROR = 105,
};

typedef struct _Application Application;
typedef struct _ApplicationArg ApplicationArg;
typedef gint (*ApplicationFunc)(Session *sess, Application *app, const gchar *args);

/**
 * @brief Application structure
 *
 * Structure with all required information about a loaded application
 * from a @ref isaac_module
 *
 * @todo Add a long description for application. A 'core show applications'
 *      command will be nice.
 */
struct _Application
{
    //! Application exec name. Must be unique.
    const gchar *name;
    //! Application exec function
    ApplicationFunc execute;
};

/**
 * @brief Application argument structure
 */
struct _ApplicationArg
{
    //! Argument name
    gchar *name;
    //! Argument value
    gchar *value;
};


/**
 * @brief Create an application and add to the application list
 *
 * Allocate the necesary memory for a new application, fill with the most
 * basic data and add it to the application list. Applications must have
 * an unique name, and an entry proint function that will be executed
 * when a session runs it. This function is designed to be called from
 * modules that want to certain implement application funcionality
 *
 * @todo Add a description for application as parameter in this function
 *
 * @param name Application name
 * @param execute Application entry point function
 * @return 0 in case of success, -1 if app could not be registered
 */
gint
application_register(const gchar *name, ApplicationFunc execute);

/**
 * @brief Free an application memory and remove from applications list
 *
 * Basically, do the opposite to application_register. Free allocated memory and
 * remove the application from the list. Usually invoked from a unload function
 * of modules
 *
 * @param name Application name
 * @return 0 in case of success, -1 otherwise
 */
gint
application_unregister(const char *name);

/**
 * @brief Get an application structure with the given name
 *
 * This function will search the registered application list (@ref apps) for
 * an application with the given name. If non is found, it will return NULL.
 *
 * @param name Name of the application to serach
 * @return Application structure pointer or NULL if not found
 */
Application *
application_find_by_name(const char *name);

/**
 * @brief Get registered application count
 *
 * Gives the number of applications registered in @ref apps list
 * @return  number of applications registered
 */
guint
application_count();

/**
 * @brief Get a concatenation of all application names available
 *
 * @return string with all Application names separated by space
 *  Returned string must be freed with g_free
 */
gchar *
application_get_names();

/**
 * @brief Run the application execute method for a session
 *
 * Most used fuction for an application. When a session request an
 * application, it will be invoked using this function.
 *
 * @param app Application to be run
 * @param sess Session information that requested the application
 * @param args Extra arguments for the application
 * @return application execute function return code
 */
gint
application_run(Application *app, Session *sess, const gchar *args);

/**
 * @brief Parse application arguments
 *
 * This function will parse arguments and store them in
 * an ApplicationArgs structure given as parameter
 *
 */
GSList *
application_parse_args(const gchar *argstr);

/**
 * @bierf Deallocate memory used for parsing app arguments
 */
void
application_free_args(GSList *args);

/**
 * @brief Return the value of a given argument
 */
const gchar *
application_get_arg(GSList *args, const gchar *name);

/**
 * @brief Return arg name in given position
 */
const gchar *
application_get_nth_arg(GSList *args, gint index);

/**
 * @brief Return if an application arg exists
 */
gboolean
application_arg_exists(GSList *args, const gchar *name);

/**
 * @brief Return if an application arg has a given value
 */
gboolean
application_arg_has_value(GSList *args, const gchar *name, const gchar *value);

/**
 * @brief Common error (@ref ApplicationErrors) to text
 *
 * This will convert a common application error to text (most probably to
 * be written in the requester session).
 *
 * @param apperr Generic error code
 * @return A string with the text corresponding to apper
 **/
const gchar *
apperr2str(enum ApplicationErrors apperr);

#endif /* _ISAAC_APP_H */
