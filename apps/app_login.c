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
 * \file app_login.c
 * \author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * \brief Module for Login and Logout functions of Irontec ivoz-ng
 *
 * This file contains the functions that manage the Isaac authentication methods
 * for ivoz-ng suite.
 *
 * ************************************************************************
 * ** This is not an all purpose module, this is designed to use ivoz-ng **
 * ** database and tables directly from odbc driver                      **
 * ************************************************************************
 */

#include <stdio.h>
#include <sql.h>
#include <sqlext.h>
#include <string.h>
#include "app.h"
#include "session.h"

/**
 * \brief Check Login attempt against asterisk database
 *
 * ivoz-ng callcenter agents are stored in karma_used using a custom salted
 * password with the password stored in MD5 encryption.
 *
 * \param sess  Session structure running the application
 * \param args  Application arguments
 * \return 0 in case of login success, 1 otherwise
 */
int login_exec(session_t *sess, const char *args)
{
    SQLHENV env;
    SQLHDBC dbc;
    SQLHSTMT stmt;
    SQLRETURN ret; /* ODBC API return status */
    SQLSMALLINT columns; /* number of columns in result-set */
    SQLLEN indicator;
    int row = 0;
    int login_num;
    char pass[100];

    /* If session is already authenticated, show an error */
    if (session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        session_write(sess, "ALREADY LOGGED IN\n");
        return -1;
    }

    /* Get login data from application arguments */
    if (sscanf(args, "%d %s", &login_num, pass) != 2) {
        return INVALID_ARGUMENTS;
    }

    /* Allocate an environment handle */
    SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
    /* We want ODBC 3 support */
    SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (void *) SQL_OV_ODBC3, 0);
    /* Allocate a connection handle */
    SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
    /* Connect to the DSN mydsn */
    /* You will need to change mydsn to one you have created and tested */
    SQLDriverConnect(dbc, NULL, "DSN=asterisk;", SQL_NTS, NULL, 0, NULL,
            SQL_DRIVER_COMPLETE);
    /* Allocate a statement handle */
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    /* Prepare login query */
    SQLPrepare(stmt,
            (SQLCHAR *) "SELECT nombre from karma_usuarios WHERE login_num = ?"
                " AND pass = encrypt( ? , SUBSTRING_INDEX(pass, '$', 3));",
            SQL_NTS);
    /* Bind username and password */
    SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 50, 0,
            &login_num, sizeof(login_num), NULL);
    SQLBindParameter(stmt, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_LONGVARCHAR, 50,
            0, pass, sizeof(pass), NULL);

    /* Execute the query */
    SQLExecute(stmt);

    /* Check if we fetched something */
    if (SQL_SUCCEEDED(ret = SQLFetch(stmt))) {
        /* Login successful!! Mark this session as authenticated */
        session_set_flag(sess, SESS_FLAG_AUTHENTICATED);
        session_write(sess, "LOGINOK Welcome back %d\n", login_num);
        return 0;
    } else {
        /* Login failed. This mark should not be required because we're closing the connection */
        session_clear_flag(sess, SESS_FLAG_AUTHENTICATED);
        /* Send the Login failed message and close connection */
        session_write(sess, "LOGINFAIL\n");
        session_finish(sess);
        return 1;
    }
}

/**
 * \brief Logout given session
 *
 * Simple function to close the session connection in a gently way,
 * being polite.
 * \param sess  Session structure running the application
 * \param args  Application arguments
 * \return 0 in all cases
 */
int logout_exec(session_t *sess, const char *args)
{
    session_write(sess, "BYE %s\n", "Thanks for all the fish");
    session_finish(sess);
    return 0;
}

/**
 * \brief Load the module and register its applications
 */
int load_module()
{
    int res = 0;
    res |= application_register("Login", login_exec);
    res |= application_register("Logout", logout_exec);
    res |= application_register("Quit", logout_exec);
    res |= application_register("Exit", logout_exec);
    return res;
}

/**
 * \brief Unload the module and unregister its applications
 */
int unload_module()
{
    int res = 0;
    // res |= application_unregister("LOGIN");
    // res |= application_unregister("LOGOUT");
    // res |= application_unregister("QUIT");
    // res |= application_unregister("EXIT");
    return res;
}
