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
#include <errno.h>
#include "cfg.h"
#include "log.h"

void
cfg_init(cfg_t *config)
{
    // Initialize configuration structure
    memset(config, 0, sizeof(cfg_t));
}

int
cfg_read(cfg_t *config, const char *cfile)
{
    config_t cfg;
    config_setting_t *cat, *sett;
    int i, j;
    const char *catname = "", *settname = "";
    // Initialize configuration
    config_init(&cfg);
    isaac_log(LOG_VERBOSE, "Reading configuration from file %s\n", cfile);
    config->modulecnt = 0;

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
                    isaac_strcpy(config->manaddr, config_setting_get_string(sett));
                } else if (!strcasecmp(settname, "port")) {
                    config->manport = config_setting_get_int(sett);
                } else if (!strcasecmp(settname, "username")) {
                    isaac_strcpy(config->manuser, config_setting_get_string(sett));
                } else if (!strcasecmp(settname, "secret")) {
                    isaac_strcpy(config->manpass, config_setting_get_string(sett));
                }
            }
        } else if (!strcasecmp(catname, "server")) {
            // Get session server settings
            for (j = 0; j < config_setting_length(cat); j++) {
                sett = config_setting_get_elem(cat, j);
                settname = config_setting_name(sett);
                if (!strcasecmp(settname, "address")) {
                    isaac_strcpy(config->listenaddr, config_setting_get_string(sett));
                } else if (!strcasecmp(settname, "port")) {
                    config->listenport = config_setting_get_int(sett);
                } else if (!strcasecmp(settname, "hidelocal")) {
                    config->hidelocal = config_setting_get_int(sett);
                } else if (!strcasecmp(settname, "keepalive")) {
                    config->keepalive = config_setting_get_int(sett);
                } else if (!strcasecmp(settname, "idle_timeout")) {
                    config->idle_timeout = config_setting_get_int(sett);
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
                        config->logtype = LOG_TYPE_SYSLOG;
                    } else if (!strcasecmp("file", logtype)) {
                        config->logtype = LOG_TYPE_FILE;
                    } else {
                        isaac_log(LOG_WARNING, "Unknown logtype %s\n", logtype);
                    }
                } else if (!strcasecmp(settname, "level")) {
                    config->loglevel = config_setting_get_int(sett);
                } else if (!strcasecmp(settname, "file")) {
                    isaac_strcpy(config->logfile, config_setting_get_string(sett));
                } else if (!strcasecmp(settname, "tag")) {
                    isaac_strcpy(config->logtag, config_setting_get_string(sett));
                }
            }
        } else if (!strcasecmp(catname, "modules")) {
            for (j = 0; j < config_setting_length(cat); j++) {
                sett = config_setting_get_elem(cat, j);
                isaac_strcpy(config->modules[config->modulecnt++], config_setting_get_string(sett));
            }
        } else {
            isaac_log(LOG_WARNING, "Unknown category %s\n", settname);
        }
    }

    // Dealloc libconfig structure
    config_destroy(&cfg);

    return 0;
}
