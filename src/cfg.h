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

#include <sys/time.h>
#include "util.h"

//! Isaac main configuration file
#define CFILE CONFDIR "/isaac.conf"

//! Sorter declaration of isaac_cfg struct
typedef struct isaac_cfg cfg_t;

/**
 * @brief Application configuration
 *
 * This structure stores all information readed from CFILE
 * in @ref read_config.
 * It should include manager, server, log and modules configuration.
 *
 */
struct isaac_cfg
{
    char manaddr[18];
    int manport;
    char manuser[20];
    char manpass[20];
    char listenaddr[18];
    int listenport;
    int hidelocal;
    int keepalive;
    int logtype;
    int loglevel;
    char logfile[256];
    char logtag[20];
    char modules[256][50];
    int modulecnt;

};

void
cfg_init(cfg_t *config);

int
cfg_read(cfg_t *config, const char *cfile);

#endif /* __ISAAC_CFG_H */
