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
#include "config.h"
#include <libconfig.h>
#include "app.h"
#include "filter.h"
#include "log.h"
#include <sql.h>
#include <sqlext.h>

#define LOGINCONF CONFDIR "/login.conf"

//! Login application configuration structure
typedef struct _AppLoginConfig
{
    //! Registered flag. 1 = Check Device is registered on login, 0 = don't check
    gboolean validate_registered;
    //! Unregistered flag. 1 = Logout on Unregister event, 0 = ignore Unregister event
    gboolean check_unregistered;
} AppLoginConfig;

//! SQL connection handle
static SQLHENV env;
static SQLHDBC dbc;
//! Exclusive access to connection handle
static GRecMutex odbc_lock;
//! Login application configuration
static AppLoginConfig login_config;

/**
 * @brief Read module configure options
 *
 * This function will read LOGINCONF file and fill app_login_conf
 * structure. Most of these values are using during login action process
 * @see login_exec
 *
 * @param cfile Full path to configuration file
 * @return TRUE in case of read success, FALSE otherwise
 */
static gboolean
read_login_config(const gchar *cfile)
{
    config_t cfg;
    gint intvalue;

    // Initialize configuration
    config_init(&cfg);

    // Read configuration file
    if (config_read_file(&cfg, cfile) == CONFIG_FALSE) {
        isaac_log(LOG_ERROR,
                  "Error parsing configuration file %s on line %d: %s\n",
                  cfile,
                  config_error_line(&cfg),
                  config_error_text(&cfg));
        config_destroy(&cfg);
        return -1;
    }

    // Register variable (0,1) for enforcing registered status on login
    if (config_lookup_int(&cfg, "login.register", &intvalue) == CONFIG_TRUE) {
        login_config.validate_registered = intvalue;
    }

    // Unregister variable (0,1) for checking Unregister event
    if (config_lookup_int(&cfg, "logout.unregister", &intvalue) == CONFIG_TRUE) {
        login_config.check_unregistered = intvalue;
    }

    // Dealloc libconfig structure
    config_destroy(&cfg);

    isaac_log(LOG_VERBOSE_3, "Read configuration from %s\n", cfile);
    return 0;
}

/**
 * @brief Test if odbc connection is Up
 *
 * Do a simple query to test the connection
 * @return TRUE if connection is Up, FALSE otherwise
 *
 */
static gboolean
odbc_test()
{
    gboolean res = FALSE;
    SQLHSTMT stmt;
    // Execute simple statement to test if 'conn' is still OK
    g_rec_mutex_lock(&odbc_lock);
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    SQLExecDirect(stmt, (SQLCHAR *) "SELECT 1;", SQL_NTS);
    res = SQL_SUCCEEDED(SQLFetch(stmt));
    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    g_rec_mutex_unlock(&odbc_lock);
    return res;
}

/**
 * @brief Connect to mysql through odbc
 *
 * Initialize static connection to ivozng database
 *
 * @return TRUE if the connection was successfully initialized,
 *         FALSE otherwise
 */
static gboolean
odbc_connect()
{
    g_rec_mutex_lock(&odbc_lock);
    // Allocate an environment handle
    SQLAllocEnv(&env);
    // We want ODBC 3 support */
    SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (void *) SQL_OV_ODBC3, 0);
    // Allocate a connection handle
    SQLAllocConnect(env, &dbc);
    // Connect to the DSN asterisk
    SQLDriverConnect(dbc, NULL, (SQLCHAR *) "DSN=asterisk;", SQL_NTS, NULL, 0, NULL, SQL_DRIVER_COMPLETE);
    g_rec_mutex_unlock(&odbc_lock);

    // Check the connection is working
    if (odbc_test()) {
        isaac_log(LOG_NOTICE, "Successfully connected to 'asterisk' database through ODBC\n");
        return TRUE;
    }
    return FALSE;
}

/**
 * @brief Disconnects from odbc and free resources
 *
 * Free the global ODBC connection structures
 */
static void
odbc_disconnect()
{
    // Disconnect ODBC driver and cleanup
    g_rec_mutex_lock(&odbc_lock);
    SQLDisconnect(dbc);
    SQLFreeConnect(dbc);
    SQLFreeEnv(env);
    g_rec_mutex_unlock(&odbc_lock);
}

/**
 * @brief Check ODBC connection periodically
 *
 * Reconnect to database if requested.
 *
 * @return TRUE in all cases
 */
static gboolean
odbc_watchdog(G_GNUC_UNUSED gpointer user_data)
{
    // Check if we're still connected to ODBC
    if (odbc_test()) {
        return TRUE;
    }

    isaac_log(LOG_ERROR, "ODBC connection failed!!\n");
    odbc_disconnect();
    odbc_connect();
    return TRUE;
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
static gint
peer_status_check(Filter *filter, AmiMessage *msg)
{
    Session *sess = filter->sess;
    const gchar *interface = session_get_variable(sess, "INTERFACE");
    const gchar *event = message_get_header(msg, "Event");

    if (event) {
        // Agent terminal is no longer registered
        if (g_ascii_strcasecmp(event, "PeerStatus") == 0) {
            session_write(sess, "BYE Peer %s is no longer registered\r\n", interface);
            session_finish(sess);
            return 0;
        }
        // Access is no longer ACD Logged in
        if (g_ascii_strcasecmp(event, "ExtensionStatus") == 0) {
            session_write(sess, "BYE Agent is no longer logged in\r\n", interface);
            session_finish(sess);
            return 0;
        }
    }

    // This is a response to a LOGIN request
    const gchar *response = message_get_header(msg, "Response");
    if (response) {
        const gchar *agent = session_get_variable(sess, "AGENT");

        gboolean registered = FALSE;
        if (g_ascii_strcasecmp(response, "Success") == 0) {
            const gchar *reg_contact = message_get_header(msg, "Reg-Contact");
            if (reg_contact && strlen(reg_contact)) {
                registered = TRUE;
            }
        }

        if (registered) {
            // Send a success message
            session_write(sess, "LOGINOK Welcome back %s %s\r\n", agent, interface);
        } else {
            // Send the Login failed message and close connection
            session_write(sess, "LOGINFAIL %s is not registered\r\n", interface);
            session_finish(sess);
        }
    }

    return 0;
}

/**
 * @brief Callback for broadcast messages
 *
 * Broadcast message sent from another session.
 * It can contain a Variable header to determine the target session
 *
 * @param filter Triggering filter structure
 * @param msg Matching message from Manager
 * @return 0 in all cases
 */
static gint
broadcast_message_check(Filter *filter, AmiMessage *msg)
{
    const gchar *variable = message_get_header(msg, "Variable");
    if (strlen(variable) > 0) {
        const gchar *value = message_get_header(msg, "Value");
        const gchar *sess_value = session_get_variable(filter->sess, variable);
        // Session doesn't have that variable
        if (!sess_value) {
            return 0;
        }
        // Session variable has not that value
        if (g_ascii_strcasecmp(value, sess_value) != 0) {
            return 0;
        }
    }

    // Write the message to the session
    const gchar *message = message_get_header(msg, "Message");
    session_write(filter->sess, "%s\r\n", message);
}

/**
 * @brief Check Login attempt against asterisk database
 *
 * ivoz-ng callcenter agents are stored in karma_used using a custom salted
 * password with the password stored in MD5 encryption.
 *
 * @param sess  Session structure running the application
 * @param app The application structure
 * @param argstr  Application arguments
 * @return 0 in case of login success, 1 otherwise
 */
static gint
login_exec(Session *sess, Application *app, const gchar *argstr)
{
    SQLHSTMT stmt;
    SQLLEN indicator;
    gint ret;
    gchar agent[100], interface[100], module[24];

    // If session is already authenticated, show an error
    if (session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        session_write(sess, "LOGINOK ALREADY LOGGED IN\r\n");
        return APP_RET_SUCCESS;
    }

    // Parse application argument
    GSList *args = application_parse_args(argstr);

    // Get login data from application arguments
    if (g_slist_length(args) != 2) {
        application_free_args(args);
        return INVALID_ARGUMENTS;
    }

    // Get login and password
    gint login_num = atoi(application_get_nth_arg(args, 0));
    const gchar *pass = application_get_nth_arg(args, 1);

    // Allocate a statement handle
    g_rec_mutex_lock(&odbc_lock);
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    if (!strcasecmp(pass, "MASTER")) {
        // Prepare login query
        SQLPrepare(stmt, (SQLCHAR *) "SELECT interface, modulo from karma_usuarios as k"
                                     " INNER JOIN shared_agents_interfaces as s"
                                     " ON k.login_num = s.agent"
                                     " WHERE login_num = ?;", SQL_NTS);
        // Bind username and password
        SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 50, 0, &login_num, sizeof(login_num), NULL);
    } else {
        // Prepare login query
        SQLPrepare(stmt, (SQLCHAR *) "SELECT interface, modulo from karma_usuarios as k"
                                     " INNER JOIN shared_agents_interfaces as s"
                                     " ON k.login_num = s.agent"
                                     " WHERE login_num = ?"
                                     " AND pass = encrypt( ? , SUBSTRING_INDEX(pass, '$', 3));", SQL_NTS);
        // Bind username and password
        SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 50, 0, &login_num, sizeof(login_num), NULL);
        SQLBindParameter(stmt,
                         2,
                         SQL_PARAM_INPUT,
                         SQL_C_CHAR,
                         SQL_LONGVARCHAR,
                         50,
                         0,
                         (gchar *) pass,
                         sizeof(pass),
                         NULL);
    }

    // Execute the query
    SQLExecute(stmt);

    // Check if we fetched something
    if (SQL_SUCCEEDED(SQLFetch(stmt))) {
        // Get the agent's interface and module
        SQLGetData(stmt, 1, SQL_C_CHAR, interface, sizeof(interface), &indicator);
        SQLGetData(stmt, 2, SQL_C_CHAR, module, sizeof(interface), &indicator);

        session_set_variable(sess, "INTERFACE", interface);
        session_set_variable(sess, "INTERFACE_NAME", interface + 4);
        // Login successful!! Mark this session as authenticated
        session_set_flag(sess, SESS_FLAG_AUTHENTICATED);
        // Store the login agent for later use
        sprintf(agent, "%d", login_num);
        session_set_variable(sess, "AGENT", agent);

        if (g_ascii_strcasecmp(module, "c") == 0) {
            session_set_variable(sess, "ROL", "AGENTE");
        } else {
            session_set_variable(sess, "ROL", "USUARIO");
        }

        // Also check for status changes
        // Check if device is registerd
        if (login_config.check_unregistered) {
            Filter *peer_status_filter = filter_create_async(sess, app, "Peer unregistered", peer_status_check);
            filter_new_condition(peer_status_filter, MATCH_EXACT, "Event", "PeerStatus");
            filter_new_condition(peer_status_filter, MATCH_EXACT, "Peer", interface);
            filter_new_condition(peer_status_filter, MATCH_EXACT, "PeerStatus", "Unregistered");
            filter_register(peer_status_filter);
        }

        Filter *acd_status_filter = filter_create_async(sess, app, "Agent Logged out", peer_status_check);
        filter_new_condition(acd_status_filter, MATCH_EXACT, "Event", "ExtensionStatus");
        filter_new_condition(acd_status_filter, MATCH_EXACT, "Exten", "access_%s", interface + 4);
        filter_new_condition(acd_status_filter, MATCH_EXACT, "Status", "1");
        filter_register(acd_status_filter);

        Filter *broadcast_filter = filter_create_async(sess, app, "Broadcast message received", broadcast_message_check);
        filter_new_condition(broadcast_filter, MATCH_EXACT, "Event", "Broadcast");
        filter_register(broadcast_filter);

        if (login_config.validate_registered) {
            // Check if device is registered
            Filter *peer_filter = filter_create_async(sess, app, "Check Initial peer status", peer_status_check);
            g_autofree gchar *actionid = g_uuid_string_random();
            filter_new_condition(peer_filter, MATCH_EXACT, "ActionID", actionid);
            filter_register_oneshot(peer_filter);

            // Request Peer status right now
            AmiMessage peer_msg;
            memset(&peer_msg, 0, sizeof(AmiMessage));
            message_add_header(&peer_msg, "Action: SIPshowpeer");
            message_add_header(&peer_msg, "Peer: %s", interface + 4);
            message_add_header(&peer_msg, "ActionID: %s", actionid);
            manager_write_message(manager, &peer_msg);
        } else {
            session_write(sess, "LOGINOK Welcome back %s SIP/%s\r\n", agent, interface + 4);
        }
        ret = APP_RET_SUCCESS;
    } else {
        // Login failed. This mark should not be required because we're closing the connection
        session_clear_flag(sess, SESS_FLAG_AUTHENTICATED);
        // Send the Login failed message and close connection
        session_write(sess, "LOGINFAIL\r\n");
        session_finish(sess);
        ret = APP_RET_ERROR;
    }

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    g_rec_mutex_unlock(&odbc_lock);

    // Free parsed app arguments
    application_free_args(args);

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
static gint
devicestatus_changed(Filter *filter, AmiMessage *msg)
{
    SQLHSTMT stmt;
    SQLLEN indicator;
    Session *sess = filter->sess;
    gint status = atoi(message_get_header(msg, "Status"));
    const gchar *exten = message_get_header(msg, "Exten");
    gint agent = atoi(session_get_variable(sess, "AGENT"));
    gint id_pausa = -1;
    const gchar *actionid = message_get_header(msg, "ActionID");

    // If there is an ActionID header
    if (strlen(actionid) > 0) {
        // And Its not our session ID, this message is not for ours
        if (g_ascii_strcasecmp(actionid, sess->id))
            return 0;
    }

    // Otherwise, check status changes
    if (g_ascii_strncasecmp(exten, "pause_", 6) == 0) {
        // Send new device status
        switch (status) {
            case 0:
                session_write(sess, "DEVICESTATE UNPAUSED\r\n");
                break;
            case 8:
                // Allocate a statement handle
                SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
                // Prepare login query
                SQLPrepare(stmt, (SQLCHAR *) "SELECT id_pausa FROM shared_agents_interfaces AS s"
                                             " WHERE agent = ?"
                                             " LIMIT 1;", SQL_NTS);
                // Bind username and password
                SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 50, 0, &agent, sizeof(agent), NULL);

                // Execute the query
                SQLExecute(stmt);

                // Check if we fetched something
                if (SQL_SUCCEEDED(SQLFetch(stmt))) {
                    // Get the agent's interface and module
                    SQLGetData(stmt, 1, SQL_INTEGER, &id_pausa, sizeof(id_pausa), &indicator);
                }
                SQLFreeHandle(SQL_HANDLE_STMT, stmt);
                if (id_pausa == -1) {
                    session_write(sess, "DEVICESTATE PAUSED\r\n");
                } else {
                    session_write(sess, "DEVICESTATE PAUSED %d\r\n", id_pausa);
                }
                break;
        }
    } else {
        // Send new device status
        switch (status) {
            case 0:
                session_write(sess, "DEVICESTATE IDLE\r\n");
                break;
            case 1:
            case 2:
                session_write(sess, "DEVICESTATE INUSE\r\n");
                break;
            case 8:
                session_write(sess, "DEVICESTATE RINGING\r\n");
                break;
            case 16:
                session_write(sess, "DEVICESTATE ONHOLD\r\n");
                break;
        }
    }

    return 0;
}

/**
 * @brief Request Device Status change information
 *
 * @param sess  Session structure running the application
 * @param app The application structure
 * @param argstr  Application arguments
 * @return 0 in case of login success, 1 otherwise
 */
static gint
devicestatus_exec(Session *sess, Application *app, G_GNUC_UNUSED const gchar *argstr)
{
    // If session is not authenticated, show an error
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    const gchar *agent = session_get_variable(sess, "AGENT");
    const gchar *interface = session_get_variable(sess, "INTERFACE");

    // If session is already showing devicestatus, leave
    if (session_get_variable(sess, "DEVICESTATUS")) {
        session_write(sess, "DEVICESTATUSOK Already displaying status for device %s\r\n", agent);
        return APP_RET_SUCCESS;
    }

    const char *rol = session_get_variable(sess, "ROL");
    g_return_val_if_fail(rol != NULL, 0);

    // Looks like there is a hard work on complicating everything and now any extension is
    // a mix of pbx and call-center. In that scenario, extension hints can be pbx or cc but
    // pause and access hints will be cc (although these may not exist at all).

    // Add a filter for handling device state changes
    Filter *device_filter = filter_create_async(sess, app, "Pause and Exten events", devicestatus_changed);
    filter_new_condition(device_filter, MATCH_REGEX, "Context", "pbx-hints|cc-hints");
    g_autofree gchar *exten = g_strdup_printf("^%s$|pause_%s", agent, interface + 4);
    filter_new_condition(device_filter, MATCH_REGEX, "Exten", exten);
    filter_register(device_filter);

    // Mark this session to avoid multiple device status
    session_set_variable(sess, "DEVICESTATUS", "1");

    // Some feedback
    session_write(sess, "DEVICESTATUSOK for %s will be printed\r\n", agent);

    // Initial status (device)
    AmiMessage device_msg;
    memset(&device_msg, 0, sizeof(AmiMessage));
    message_add_header(&device_msg, "Action: ExtensionState");
    message_add_header(&device_msg, "Exten: %s", agent);
    message_add_header(&device_msg, "Context: cc-hints");
    message_add_header(&device_msg, "ActionID: %s", sess->id);
    manager_write_message(manager, &device_msg);

    memset(&device_msg, 0, sizeof(AmiMessage));
    message_add_header(&device_msg, "Action: ExtensionState");
    message_add_header(&device_msg, "Exten: %s", agent);
    message_add_header(&device_msg, "Context: pbx-hints");
    message_add_header(&device_msg, "ActionID: %s", sess->id);
    manager_write_message(manager, &device_msg);

    // Initial status (pause)
    memset(&device_msg, 0, sizeof(AmiMessage));
    message_add_header(&device_msg, "Action: ExtensionState");
    message_add_header(&device_msg, "Exten: pause_%s", interface + 4);
    message_add_header(&device_msg, "Context: cc-hints");
    message_add_header(&device_msg, "ActionID: %s", sess->id);
    manager_write_message(manager, &device_msg);

    return APP_RET_SUCCESS;
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
static gint
logout_exec(Session *sess, Application *app, const gchar *args)
{
    session_write(sess, "BYE %s\r\n", "Thanks for all the fish");
    session_finish(sess);
    return APP_RET_SUCCESS;
}

/**
 * @brief Module load entry point
 *
 * Load module configuration and applications
 *
 * @retval 0 if all applications and configuration has been loaded
 * @retval 1 if any application fails to register or configuration can not be readed
 */
gint
load_module()
{
    int res = 0;
    if (read_login_config(LOGINCONF) != 0) {
        isaac_log(LOG_ERROR, "Failed to read app_login config file %s\n", LOGINCONF);
        return -1;
    }

    res |= application_register("LOGIN", login_exec);
    res |= application_register("LOGOUT", logout_exec);
    res |= application_register("EXIT", logout_exec);
    res |= application_register("DEVICESTATUS", devicestatus_exec);

    // Start connected to ODBC
    odbc_connect();

    // Add a timer to verify ODBC connection
    g_timeout_add(5000, (GSourceFunc) odbc_watchdog, NULL);

    return res;
}

/**
 * @brief Module unload entry point
 *
 * Unload module applications
 *
 * @return 0 if all applications are unloaded, -1 otherwise
 */
gint
unload_module()
{
    int res = 0;

    res |= application_unregister("LOGIN");
    res |= application_unregister("LOGOUT");
    res |= application_unregister("DeviceStatus");
    res |= application_unregister("EXIT");

    // Disconnect from ODBC
    odbc_disconnect();

    // Wait threads to end
    return res;
}
