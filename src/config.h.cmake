/*****************************************************************************
** Isaac -- Ivozng simplified Asterisk AMI Connector
**
** Copyright (C) 2013-2021 Irontec S.L.
** Copyright (C) 2013-2021 Ivan Alonso (aka Kaian)
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
#ifndef ISAAC_CONFIG_H
#define ISAAC_CONFIG_H

/** Program basic information **/
#define PACKAGE_NAME "@PROJECT_NAME@"
#define PACKAGE_VERSION "@PROJECT_VERSION@"

/** Isaac Running socket for local client connect with -r option **/
#cmakedefine CLI_SOCKET "@CLI_SOCKET@"

/** Absolute path where modules are located **/
#cmakedefine MODDIR "@MODDIR@"

/** Absolute path where configuration files are located **/
#cmakedefine CONFDIR "@CONFDIR@"

#endif
