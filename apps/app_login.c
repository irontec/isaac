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
 * @file app_login.c
 * @author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Module for Login and Logout applications of Irontec ivoz-ng
 *
 * This file contains the functions that manage the Isaac authentication methods
 * for ivoz-ng suite.
 *
 * ************************************************************************
 * ** THIS is not an all purpose module. THIS is designed to use ivoz-ng **
 * ** database and tables directly from odbc driver                      **
 * ************************************************************************
 */

#include "isaac.h"
#include "app.h"
#include "filter.h"
#include "log.h"
#include <stdio.h>
#include <sql.h>
#include <sqlext.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

// Share the connection between all threads. This seems to be thread-safe
static SQLHENV env;
static SQLHDBC dbc;
pthread_t odbc_thread;

/**
 * @brief Test if odbc connection is Up
 * 
 * Do a simple query to test the connection
 * @return 1 if connection is Up, 0 otherwise
 *
 */
int
odbc_test()
{
    int res = 0;
    SQLHSTMT stmt;
    // Execute simple statement to test if 'conn' is still OK
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    SQLExecDirect(stmt, (SQLCHAR*)"SELECT 1;", SQL_NTS);
    res = SQL_SUCCEEDED(SQLFetch(stmt));
    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    return res; 
}

/**
 * @brief Connect to mysql through odbc
 * 
 * Initialize static connection to ivozng database
 *
 * @return 1 if the connection was successfully initializated,
 *         0 otherwise
 */
int
odbc_connect()
{
    
    // Dont connect if we're already connected
    if (odbc_test()) { return 1; }
    // Allocate an environment handle
    SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
    // We want ODBC 3 support */
    SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (void *) SQL_OV_ODBC3, 0);
    // Allocate a connection handle
    SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
    // Connect to the DSN mydsn
    // You will need to change mydsn to one you have created and tested */
    SQLDriverConnect(dbc, NULL, (SQLCHAR *) "DSN=asterisk;", SQL_NTS, NULL, 0, NULL,
            SQL_DRIVER_COMPLETE);
    
    // Check the connection is working
    if(odbc_test()) {
        isaac_log(LOG_NOTICE, "Successfully connected to 'asterisk' database through ODBC\n");
        return 1;
    }
    return 0;
}

/**
 * @brief Disconnects from odbc and free resources
 *
 * Free the global obdc connection structures
 *
 * @return 1 in all cases
 */
int
odbc_disconnect()
{

    // Disconnect ODBC driver and cleanup
    SQLDisconnect(dbc);
    SQLFreeHandle(SQL_HANDLE_DBC, dbc);
    SQLFreeHandle(SQL_HANDLE_ENV, env);
    return 1;   
}

/**
 * @brief Check ODBC connection periodically
 *
 * Reconnect to database if requested.
 *
 */
void *
odbc_watchdog(void *args)
{

    odbc_connect();
    while(config.running) { 
        if (!odbc_test()) {
            isaac_log(LOG_ERROR, "ODBC connection failed!!\n");
            odbc_disconnect();
            odbc_connect();
        }
        sleep(3);
    } 
    odbc_disconnect();
    return NULL;
}

/**
 * @brief Callback for peer status functions
 *
 * After agent login and during the session, peer status will be monitored
 * calling this fuction on every peer status change
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
int
peer_status_check(filter_t *filter, ami_message_t *msg)
{
    session_t *sess = filter->sess;
    const char *interface = session_get_variable(sess, "INTERFACE");
    const char *event = message_get_header(msg, "Event");    

    if (event && !strncasecmp(event, "PeerStatus", 10)) {
        session_write(sess, "BYE Peer %s is no longer registered\r\n", interface);
        session_finish(sess);
    } else {
        const char *response = message_get_header(msg, "Response");
        if (response) {
            const char *agent = session_get_variable(sess, "AGENT");
 
            if (!strncasecmp(response, "Success", 7)) {
                // Send a success message
                session_write(sess, "LOGINOK Welcome back %s %s\r\n", agent, interface);
            } else {
                // Send the Login failed message and close connection
                session_write(sess, "LOGINFAIL %s is not registered\r\n", interface);
                session_finish(sess);
            }
        }
   }

    return 0;
}

/**
 * @brief Check Login attempt against asterisk database
 *
 * ivoz-ng callcenter agents are stored in karma_used using a custom salted
 * password with the password stored in MD5 encryption.
 *
 * @param sess  Session structure running the application
 * @param app The application structure
 * @param args  Application arguments
 * @return 0 in case of login success, 1 otherwise
 */
int
login_exec(session_t *sess, app_t *app, const char *args)
{
    SQLHSTMT stmt;
    SQLLEN indicator;
    int ret = 0;
    int login_num;
    char agent[100], pass[100], interface[100], module[24];

    // If session is already authenticated, show an error
    if (session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        session_write(sess, "ALREADY LOGGED IN\r\n");
        return -1;
    }

    // Get login data from application arguments
    if (sscanf(args, "%d %s", &login_num, pass) != 2) {
        return INVALID_ARGUMENTS;
    }

    // Allocate a statement handle
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    // Prepare login query
    SQLPrepare(stmt, (SQLCHAR *) "SELECT interface, modulo from karma_usuarios as k"
        " INNER JOIN shared_agents_interfaces as s"
        " ON k.login_num = s.agent"
        " WHERE login_num = ?"
        " AND pass = encrypt( ? , SUBSTRING_INDEX(pass, '$', 3));", SQL_NTS);
    // Bind username and password
    SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 50, 0, &login_num,
            sizeof(login_num), NULL);
    SQLBindParameter(stmt, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_LONGVARCHAR, 50, 0, pass,
            sizeof(pass), NULL);

    // Execute the query
    SQLExecute(stmt);

    // Check if we fetched something
    if (SQL_SUCCEEDED(SQLFetch(stmt))) {
        // Get the agent's interface and module
        SQLGetData(stmt, 1, SQL_C_CHAR, interface, sizeof(interface), &indicator);
        SQLGetData(stmt, 2, SQL_C_CHAR, module, sizeof(interface), &indicator);

        session_set_variable(sess, "INTERFACE", interface);
        // Login successful!! Mark this session as authenticated
        session_set_flag(sess, SESS_FLAG_AUTHENTICATED);
        // Store the login agent for later use
        sprintf(agent, "%d", login_num);
        session_set_variable(sess, "AGENT", agent);

        if (!strcasecmp(module, "c")) {
            session_set_variable(sess, "ROL", "AGENTE");
        } else {
            session_set_variable(sess, "ROL", "USUARIO");
        }

        // Check if device is registerd
        filter_t *peerfilter = filter_create_async(sess, peer_status_check);
        filter_new_condition(peerfilter, MATCH_EXACT , "ActionID", interface+4);
        filter_register_oneshot(peerfilter);

        // Request Peer status right now
        ami_message_t peermsg;
        memset(&peermsg, 0, sizeof(ami_message_t));
        message_add_header(&peermsg, "Action: SIPshowpeer");
        message_add_header(&peermsg, "Peer: %s", interface+4);
        message_add_header(&peermsg, "ActionID: %s", interface+4);
        manager_write_message(manager, &peermsg);

        // Also check for status changes
        // Check if device is registerd
        filter_t *monitorfilter = filter_create_async(sess, peer_status_check);
        filter_new_condition(monitorfilter, MATCH_EXACT , "Event", "PeerStatus");
        filter_new_condition(monitorfilter, MATCH_EXACT , "Peer", interface);
        filter_new_condition(monitorfilter, MATCH_EXACT , "PeerStatus", "Unregistered");
        filter_register(monitorfilter);

        ret = 0;
    } else {
        // Login failed. This mark should not be required because we're closing the connection
        session_clear_flag(sess, SESS_FLAG_AUTHENTICATED);
        // Send the Login failed message and close connection
        session_write(sess, "LOGINFAIL\r\n");
        session_finish(sess);
        ret = 1;
    }

   SQLFreeHandle(SQL_HANDLE_STMT, stmt);
   return ret;
}

/**
 * @brief Callback for device status functions
 *
 * Send information of Hint changed to the session
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
int
devicestatus_changed(filter_t *filter, ami_message_t *msg)
{
    session_t *sess = filter->sess;
    int status = atoi(message_get_header(msg, "Status"));

    // Send new device status
    switch(status) {
    case 0:
        session_write(sess, "DEVICESTATE IDLE\r\n");
        break;
    case 1:
        session_write(sess, "DEVICESTATE INUSE\r\n");
        break;
    case 8:
        session_write(sess, "DEVICESTATE RINGING\r\n");
        break;
    default:
        session_write(sess, "DEVICESTATE NOTHANDLED\r\n");
        break;
    }

    return 0;
}

/**
 * @brief Request Device Status change information
 *
 * @param sess  Session structure running the application
 * @param app The application structure
 * @param args  Application arguments
 * @return 0 in case of login success, 1 otherwise
 */
int
devicestatus_exec(session_t *sess, app_t *app, const char *args)
{
    // If session is not authenticated, show an error
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }
    
    const char *agent = session_get_variable(sess, "AGENT");
    const char *interface = session_get_variable(sess, "INTERFACE");

    // If session is already showing devicestatus, leave
    if (session_get_variable(sess, "DEVICESTATUS")) {
        return session_write(sess, "DEVICESTATUSOK Already displaying status for device %s\r\n", agent);
    }

    // Add a filter for handling device state changes
    filter_t *devicefilter = filter_create_async(sess, devicestatus_changed);
    filter_new_condition(devicefilter, MATCH_EXACT , "Context", "cc-hints");
    filter_new_condition(devicefilter, MATCH_EXACT , "Hint", interface);
    filter_new_condition(devicefilter, MATCH_EXACT , "Exten", agent);
    filter_register(devicefilter);

    // Mark this session to avoid multiple device status
    session_set_variable(sess, "DEVICESTATUS", "1");

    // Some feedback
    session_write(sess, "DEVICESTATUSOK for %s will be printed\r\n", agent);

    // Initial status
    ami_message_t devicemsg;
    memset(&devicemsg, 0, sizeof(ami_message_t));
    message_add_header(&devicemsg, "Action: ExtensionState");
    message_add_header(&devicemsg, "Exten: %s", agent);
    message_add_header(&devicemsg, "Context: cc-hints");
    manager_write_message(manager, &devicemsg);

    return 0;
}

/**
 * @brief Logout given session
 *
 * Simple function to close the session connection in a gently way,
 * being polite.
 * @param sess  Session structure running the application
 * @param app The application structure
 * @param args  Application arguments
 * @return 0 in all cases
 */
int
logout_exec(session_t *sess, app_t *app, const char *args)
{
    session_write(sess, "BYE %s\r\n", "Thanks for all the fish");
    session_finish(sess);
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
    res |= application_register("Login", login_exec);
    res |= application_register("Logout", logout_exec);
    res |= application_register("Exit", logout_exec);
    res |= application_register("DEVICESTATUS", devicestatus_exec);
    // Create a new thread for odbc connection
    if (pthread_create(&odbc_thread, NULL, odbc_watchdog, NULL) != 0) {
        isaac_log(LOG_WARNING, "Error creating odbc thread: %s\n", strerror(errno));
        res = 0;
    }
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
    res |= application_unregister("LOGIN");
    res |= application_unregister("LOGOUT");
    res |= application_unregister("DEVICESTATUS");
    res |= application_unregister("EXIT");
    res |= pthread_join(odbc_thread, NULL);
    return res;
}
