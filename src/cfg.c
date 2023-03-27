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
 * @file cfg.c
 * @author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source code for functions defined in cfg.h
 */

#include "config.h"
#include <libconfig.h>
#include "cfg.h"
#include "log.h"


static Config *config;

gboolean
cfg_read(const gchar *cfile)
{
    config_t cfg;
    config_setting_t *cat, *sett;
    const gchar *category = "", *setting_name = "";

    // Allocate memory for configuration settings
    config = g_malloc0(sizeof(Config));

    // Initialize configuration
    config_init(&cfg);

    // Read configuration file
    if (config_read_file(&cfg, cfile) == CONFIG_FALSE) {
        g_printerr("Error parsing configuration file %s on line %d: %s\n",
                  cfile,
                  config_error_line(&cfg),
                  config_error_text(&cfg)
        );
        config_destroy(&cfg);
        return FALSE;
    }

    // Parse the configuration file to get the known settings
    config_setting_t *root = config_root_setting(&cfg);
    for (gint i = 0; i < config_setting_length(root); i++) {
        cat = config_setting_get_elem(root, i);
        category = config_setting_name(cat);

        if (!strcasecmp(category, "manager")) {
            // Get manager connection settings
            for (gint j = 0; j < config_setting_length(cat); j++) {
                sett = config_setting_get_elem(cat, j);
                setting_name = config_setting_name(sett);
                if (!strcasecmp(setting_name, "address")) {
                    config->manager_address = g_strdup(config_setting_get_string(sett));
                } else if (!strcasecmp(setting_name, "port")) {
                    config->manager_port = config_setting_get_int(sett);
                } else if (!strcasecmp(setting_name, "username")) {
                    config->manager_user = g_strdup(config_setting_get_string(sett));
                } else if (!strcasecmp(setting_name, "secret")) {
                    config->manager_pass = g_strdup(config_setting_get_string(sett));
                }
            }
        } else if (!strcasecmp(category, "server")) {
            // Get session server settings
            for (gint j = 0; j < config_setting_length(cat); j++) {
                sett = config_setting_get_elem(cat, j);
                setting_name = config_setting_name(sett);
                if (!strcasecmp(setting_name, "address")) {
                    config->server_address = g_strdup(config_setting_get_string(sett));
                } else if (!strcasecmp(setting_name, "port")) {
                    config->server_port = config_setting_get_int(sett);
                } else if (!strcasecmp(setting_name, "threads")) {
                    config->server_threads = config_setting_get_int(sett);
                } else if (!strcasecmp(setting_name, "hidelocal")) {
                    config->hide_local = config_setting_get_int(sett);
                } else if (!strcasecmp(setting_name, "keepalive")) {
                    config->keepalive = config_setting_get_int(sett);
                } else if (!strcasecmp(setting_name, "idle_timeout")) {
                    config->idle_timeout = config_setting_get_int(sett);
                }
            }
        } else if (!strcasecmp(category, "log")) {
            // Get logging settings
            for (gint j = 0; j < config_setting_length(cat); j++) {
                sett = config_setting_get_elem(cat, j);
                setting_name = config_setting_name(sett);
                if (!strcasecmp(setting_name, "type")) {
                    const char *log_type = config_setting_get_string(sett);
                    if (!strcasecmp("syslog", log_type)) {
                        config->log_type = LOG_TYPE_SYSLOG;
                    } else if (!strcasecmp("file", log_type)) {
                        config->log_type = LOG_TYPE_FILE;
                    } else {
                        g_printerr("Unknown log_type %s\n", log_type);
                    }
                } else if (!strcasecmp(setting_name, "level")) {
                    config->log_level = config_setting_get_int(sett);
                } else if (!strcasecmp(setting_name, "file")) {
                    config->log_file = g_strdup(config_setting_get_string(sett));
                } else if (!strcasecmp(setting_name, "tag")) {
                    config->log_tag = g_strdup(config_setting_get_string(sett));
                }
            }
        } else if (!strcasecmp(category, "modules")) {
            for (gint j = 0; j < config_setting_length(cat); j++) {
                sett = config_setting_get_elem(cat, j);
                config->modules = g_slist_append(config->modules, g_strdup(config_setting_get_string(sett)));
            }
        } else {
            isaac_log(LOG_WARNING, "Unknown category %s\n", setting_name);
        }
    }

    // Dealloc libconfig structure
    config_destroy(&cfg);

    return 0;
}

gchar *
cfg_get_manager_address()
{
    return config->manager_address;
}

gint
cfg_get_manager_port()
{
    return config->manager_port;
}

gchar *
cfg_get_manager_user()
{
    return config->manager_user;
}

gchar *
cfg_get_manager_pass()
{
    return config->manager_pass;
}

gchar *
cfg_get_server_address()
{
    return config->server_address;
}

gint
cfg_get_server_port()
{
    return config->server_port;
}

gint
cfg_get_server_threads()
{
    return config->server_threads;
}

gboolean
cfg_get_hide_local()
{
    return config->hide_local;
}

gboolean
cfg_get_keepalive()
{
    return config->keepalive;
}

gint
cfg_get_idle_timeout()
{
    return config->idle_timeout;
}

gint
cfg_get_log_type()
{
    return config->log_type;
}

gint
cfg_get_log_level()
{
    return config->log_level;
}

void
cfg_set_log_level(gint log_level)
{
    config->log_level = log_level;
}

gchar *
cfg_get_log_file()
{
    return config->log_file;
}

gchar *
cfg_get_log_tag()
{
    return config->log_tag;
}

GSList *
cfg_get_modules()
{
    return config->modules;
}