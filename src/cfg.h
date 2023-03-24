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
 * @file manager.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions declaration to manage connection with Asterisk Manager Interface
 *
 * Most of this functions are copied or adapted from Asterisk or Astmanproxy
 * code (or at least the idea).
 *
 */
#ifndef __ISAAC_CFG_H
#define __ISAAC_CFG_H

//! Isaac main configuration file
#define CFILE CONFDIR "/isaac.conf"

#include <glib.h>

//! Sorter declaration of isaac_cfg struct
typedef struct _Config Config;

/**
 * @brief Application configuration
 *
 * This structure stores all information read from CFILE
 * in @ref read_config.
 * It should include manager, server, log and modules configuration.
 */
struct _Config {
    gchar *manager_address;
    gint manager_port;
    gchar *manager_user;
    gchar *manager_pass;
    gchar *server_address;
    gint server_port;
    gboolean hide_local;
    gboolean keepalive;
    gint idle_timeout;
    gint log_type;
    gint log_level;
    gchar *log_file;
    gchar *log_tag;
    GSList *modules;

};

gboolean
cfg_read(const char *cfile);

gchar *
cfg_get_manager_address();

gint
cfg_get_manager_port();

gchar *
cfg_get_manager_user();

gchar *
cfg_get_manager_pass();

gchar *
cfg_get_server_address();

gint
cfg_get_server_port();

gboolean
cfg_get_hide_local();

gboolean
cfg_get_keepalive();

gint
cfg_get_idle_timeout();

gint
cfg_get_log_type();

gint
cfg_get_log_level();

void
cfg_set_log_level(gint log_level);

gchar *
cfg_get_log_file();

gchar *
cfg_get_log_tag();

GSList *
cfg_get_modules();

gint
cfg_get_idle_timeout();

#endif /* __ISAAC_CFG_H */
