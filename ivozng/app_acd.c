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
 * @warning This module is customized for Ivoz-NG.
 *
 * This is a special module that spawns a php for its actions.
 * This allow the VoIP developers to work in a more familiar environment.
 */
#include "config.h"
#include <glib.h>
#include <libconfig.h>
#include "app.h"
#include "log.h"

#define ACDCONF CONFDIR "/acd.conf"

//! Module configuration read from ACDCONF file
typedef struct
{
    gchar *php_file;
    gchar *api_url;
    gchar *api_user;
    gchar *api_pass;
    gchar *api_token;

} AppAcdConfig;

//! Callback structure data
typedef struct
{
    GIOChannel *channel;
    GSource *source;
    Session *session;
} AppAcdData;

//! Module Configuration
static AppAcdConfig acd_config;

/**
 * @brief Read module configure options
 *
 * This function will read ACDCONF file and fill acd_config
 * structure.
 *
 * @param cfile Full path to configuration file
 * @return 0 in case of read success, -1 otherwise
 */
gboolean
read_acd_config(const char *cfile)
{
    config_t cfg;
    const char *value;

    // Initialize configuration
    config_init(&cfg);

    // Read configuration file
    if (config_read_file(&cfg, cfile) == CONFIG_FALSE) {
        isaac_log(LOG_ERROR, "Error parsing configuration file %s on line %d: %s\n", cfile,
                  config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return FALSE;
    }

    // Get PHP file that will be spawned in this module
    if (config_lookup_string(&cfg, "acd.php_file", &value) == CONFIG_TRUE) {
        acd_config.php_file = g_strdup(value);
    }
    if (config_lookup_string(&cfg, "acd.api_url", &value) == CONFIG_TRUE) {
        acd_config.api_url = g_strdup(value);
    }
    if (config_lookup_string(&cfg, "acd.api_user", &value) == CONFIG_TRUE) {
        acd_config.api_user = g_strdup(value);
    }
    if (config_lookup_string(&cfg, "acd.api_pass", &value) == CONFIG_TRUE) {
        acd_config.api_pass = g_strdup(value);
    }

    // Dealloc libconfig structure
    config_destroy(&cfg);
    isaac_log(LOG_VERBOSE_3, "Read configuration from %s\n", cfile);

    // Validate php_file exists
    if (!g_file_test(acd_config.php_file, G_FILE_TEST_IS_REGULAR)) {
        g_free(acd_config.php_file);
        acd_config.php_file = g_strdup_printf("%s/acd.php", MODDIR);
        isaac_log(LOG_INFO, "Using default ACD script %s\n", acd_config.php_file);
        if (!g_file_test(acd_config.php_file, G_FILE_TEST_IS_REGULAR)) {
            isaac_log(LOG_ERROR, "Unable to locate ACD script %s\n", acd_config.php_file);
        }
    }

    return TRUE;
}

static gboolean
acd_refresh_api_token_response(GIOChannel *channel, G_GNUC_UNUSED GIOCondition condition, AppAcdData *data)
{
    GError *error = NULL;

    g_autoptr(GString) response = g_string_new(NULL);
    if (g_io_channel_read_line_string(channel, response, NULL, &error) != G_IO_STATUS_NORMAL) {
        isaac_log(LOG_ERROR, "Failed to get ivozng API token from response: %s\n", response->str);
    } else {
        // Remove trailing new lines from response
        g_strchomp(response->str);
        // Free old token data
        g_free(acd_config.api_token);
        // Use new retrieved token
        acd_config.api_token = g_strdup(response->str + strlen("ACDTOKENOK") + 1);
        isaac_log(LOG_DEBUG, "Obtained API token %s\n", acd_config.api_token);
    }

    // We're done with this ACD process
    g_source_destroy(data->source);
    g_source_unref(data->source);
    g_io_channel_unref(data->channel);
    g_free(data);

    return G_SOURCE_REMOVE;
}

static gboolean
acd_refresh_api_token(G_GNUC_UNUSED gpointer user_data)
{
    GError *error = NULL;
    gint fd;

    gchar *php_args[] = {
        "/usr/bin/php",
        acd_config.php_file,
        "TOKEN",
        acd_config.api_url,
        acd_config.api_user,
        acd_config.api_pass,
        NULL
    };

    if (!g_spawn_async_with_pipes(NULL, php_args, NULL, G_SPAWN_DEFAULT, NULL, NULL, NULL, NULL, &fd, NULL, &error)) {
        isaac_log(LOG_ERROR, "Failed to spawn PHP ACD script: %s\n", error->message);
        return 1;
    }

    AppAcdData *data = g_new(AppAcdData, 1);
    data->channel = g_io_channel_unix_new(fd);
    g_io_channel_set_close_on_unref(data->channel, TRUE);
    data->source = g_io_create_watch(data->channel, G_IO_IN);

    // Read script response asynchronously
    g_source_set_callback(data->source, (GSourceFunc) acd_refresh_api_token_response, data, NULL);
    g_source_attach(data->source, g_main_context_get_thread_default());

    return G_SOURCE_CONTINUE;
}

static gboolean
acd_exec_response(GIOChannel *channel, G_GNUC_UNUSED GIOCondition condition, AppAcdData *data)
{
    g_return_val_if_fail(data != NULL, G_SOURCE_REMOVE);
    g_return_val_if_fail(data->session != NULL, G_SOURCE_REMOVE);
    g_return_val_if_fail(g_io_channel_get_flags(channel) & G_IO_FLAG_IS_READABLE, G_SOURCE_REMOVE);

    if (condition & G_IO_IN) {
        GError *error = NULL;
        g_autoptr(GString) buffer = g_string_new(NULL);
        if (g_io_channel_read_line_string(channel, buffer, NULL, &error) != G_IO_STATUS_NORMAL) {
            if (error != NULL) {
                isaac_log(LOG_ERROR, "Failed to parse ACD process response: %s\n", error->message);
            }
            session_write(data->session, "ACDERROR\r\n");
        } else {
            session_write(data->session, buffer->str);
        }

        // We're done with this ACD process
        g_io_channel_shutdown(data->channel, FALSE, &error);
        g_io_channel_unref(data->channel);
        g_source_unref(data->source);
        g_free(data);
    }

    return G_SOURCE_REMOVE;
}

static gint
acd_exec(Session *sess, Application *app, const char *argstr)
{
    if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) {
        return NOT_AUTHENTICATED;
    }

    // Check if uniqueid info is requested
    GSList *args = application_parse_args(argstr);

    g_autoptr(GString) args_builder = g_string_new(NULL);
    g_string_append_printf(args_builder, "%s ", "/usr/bin/php");
    g_string_append_printf(args_builder, "%s ", acd_config.php_file);

    if (g_ascii_strcasecmp(app->name, "ACDSTATUS") == 0) {
        g_string_append_printf(args_builder, "%s ", "STATUS");
        g_string_append_printf(args_builder, "%s ", acd_config.api_url);
        g_string_append_printf(args_builder, "%s ", acd_config.api_token);
        g_string_append_printf(args_builder, "%s ", session_get_variable(sess, "AGENT"));
    }

    if (g_ascii_strcasecmp(app->name, "ACDLOGIN") == 0) {
        if (g_slist_length(args) < 1) {
            application_free_args(args);
            return INVALID_ARGUMENTS;
        }
        g_string_append_printf(args_builder, "%s ", "LOGIN");
        g_string_append_printf(args_builder, "%s ", acd_config.api_url);
        g_string_append_printf(args_builder, "%s ", acd_config.api_token);
        g_string_append_printf(args_builder, "%s ", session_get_variable(sess, "AGENT"));
        g_string_append_printf(args_builder, "%s ", application_get_nth_arg(args, 0));
    }

    if (g_ascii_strcasecmp(app->name, "ACDLOGOUT") == 0) {
        g_string_append_printf(args_builder, "%s ", "LOGOUT");
        g_string_append_printf(args_builder, "%s ", acd_config.api_url);
        g_string_append_printf(args_builder, "%s ", acd_config.api_token);
        g_string_append_printf(args_builder, "%s ", session_get_variable(sess, "AGENT"));
        g_string_append_printf(args_builder, "%s ", session_get_variable(sess, "INTERFACE_NAME"));
    }

    if (g_ascii_strcasecmp(app->name, "ACDPAUSE") == 0) {
        g_string_append_printf(args_builder, "%s ", "PAUSE");
        g_string_append_printf(args_builder, "%s ", acd_config.api_url);
        g_string_append_printf(args_builder, "%s ", acd_config.api_token);
        g_string_append_printf(args_builder, "%s ", session_get_variable(sess, "AGENT"));
        g_string_append_printf(args_builder, "%s ", session_get_variable(sess, "INTERFACE_NAME"));
        // Add custom pause code if requested
        if (g_slist_length(args) == 1) {
            g_string_append_printf(args_builder, "%s ", application_get_nth_arg(args, 0));
        }
    }

    if (g_ascii_strcasecmp(app->name, "ACDUNPAUSE") == 0) {
        g_string_append_printf(args_builder, "%s ", "UNPAUSE");
        g_string_append_printf(args_builder, "%s ", acd_config.api_url);
        g_string_append_printf(args_builder, "%s ", acd_config.api_token);
        g_string_append_printf(args_builder, "%s ", session_get_variable(sess, "AGENT"));
        g_string_append_printf(args_builder, "%s ", session_get_variable(sess, "INTERFACE_NAME"));
    }

    if (g_ascii_strcasecmp(app->name, "QUEUEJOIN") == 0) {
        if (g_slist_length(args) < 1) {
            application_free_args(args);
            return INVALID_ARGUMENTS;
        }
        g_string_append_printf(args_builder, "%s ", "JOIN");
        g_string_append_printf(args_builder, "%s ", acd_config.api_url);
        g_string_append_printf(args_builder, "%s ", acd_config.api_token);
        g_string_append_printf(args_builder, "%s ", session_get_variable(sess, "AGENT"));
        // Queue name
        g_string_append_printf(args_builder, "%s ", application_get_nth_arg(args, 0));
        // Add custom priority if requested
        if (g_slist_length(args) == 2) {
            g_string_append_printf(args_builder, "%s ", application_get_nth_arg(args, 1));
        }
    }

    if (g_ascii_strcasecmp(app->name, "QUEUELEAVE") == 0) {
        if (g_slist_length(args) < 1) {
            application_free_args(args);
            return INVALID_ARGUMENTS;
        }
        g_string_append_printf(args_builder, "%s ", "LEAVE");
        g_string_append_printf(args_builder, "%s ", acd_config.api_url);
        g_string_append_printf(args_builder, "%s ", acd_config.api_token);
        g_string_append_printf(args_builder, "%s ", session_get_variable(sess, "AGENT"));
        // Queue name
        g_string_append_printf(args_builder, "%s ", application_get_nth_arg(args, 0));
    }

    GError *error = NULL;
    gint fd;

    g_auto(GStrv) php_args = g_strsplit(args_builder->str, " ", -1);
    if (!g_spawn_async_with_pipes(NULL, php_args, NULL, G_SPAWN_DEFAULT, NULL, NULL, NULL, NULL, &fd, NULL, &error)) {
        isaac_log(LOG_ERROR, "Failed to spawn PHP ACD script: %s\n", error->message);
        return 1;
    }

    AppAcdData *data = g_new(AppAcdData, 1);
    data->channel = g_io_channel_unix_new(fd);
    g_io_channel_set_close_on_unref(data->channel, TRUE);
    data->source = g_io_create_watch(data->channel, G_IO_IN);
    data->session = sess;

    // Read script response asynchronously
    g_source_set_callback(data->source, (GSourceFunc) acd_exec_response, data, NULL);
    g_source_attach(data->source, g_main_context_get_thread_default());

    // Free args app arguments
    application_free_args(args);

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
gint
load_module()
{
    gint res = 0;
    if (!read_acd_config(ACDCONF)) {
        isaac_log(LOG_ERROR, "Failed to read app_acd config file %s\n", ACDCONF);
        return -1;
    }
    res |= application_register("ACDSTATUS", acd_exec);
    res |= application_register("ACDLOGIN", acd_exec);
    res |= application_register("ACDLOGOUT", acd_exec);
    res |= application_register("ACDPAUSE", acd_exec);
    res |= application_register("ACDUNPAUSE", acd_exec);
    res |= application_register("QUEUEJOIN", acd_exec);
    res |= application_register("QUEUELEAVE", acd_exec);

    // Add a timer to get API token periodically
    g_timeout_add_seconds(60 * 60, (GSourceFunc) acd_refresh_api_token, NULL);
    // Retrieve initial token
    acd_refresh_api_token(NULL);

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
    gint res = 0;
    res |= application_unregister("ACDSTATUS");
    res |= application_unregister("ACDLOGIN");
    res |= application_unregister("ACDLOGOUT");
    res |= application_unregister("ACDPAUSE");
    res |= application_unregister("ACDUNPAUSE");
    res |= application_unregister("QUEUEJOIN");
    res |= application_unregister("QUEUELEAVE");

    // Deallocate used memory
    g_free(acd_config.php_file);
    g_free(acd_config.api_url);
    g_free(acd_config.api_user);
    g_free(acd_config.api_pass);
    g_free(acd_config.api_token);

    return res;
}
