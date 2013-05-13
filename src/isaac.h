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
 * \file isaac.h
 * \author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 * \brief Functions to manage incoming connections to server
 *
 * Main functions, usable from any part of the program.
 * This file will define the functions that manage the configuration and also
 * the application initialize and exit process
 */
#ifndef __ISAAC_H_
#define __ISAAC_H_
#include "config.h"
#include "log.h"

//! Sorter declaration of isaac_cfg struct
typedef struct isaac_cfg isaac_cfg_t;

struct isaac_cfg
{
    char manaddr[18];
    int manport;
    char manuser[20];
    char manpass[20];
    char listenaddr[18];
    int listenport;
    int logtype;
    int loglevel;
    char logfile[256];
    char logtag[20];
};

extern isaac_cfg_t config;
extern int debug;
extern struct timeval isaac_startuptime;

extern void
version();

extern void
usage(const char* progname);

extern void
quit(int exitcode);

extern int
read_config(const char *cfile);

#endif /* __ISAAC_H_ */
