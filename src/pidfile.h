/*
 pidfile.c - interact with pidfiles
 Copyright (c) 1995  Martin Schulze <Martin.Schulze@Linux.DE>

 This file is part of the sysklogd package, a kernel and system log daemon.

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License along
 with this program; if not, write to the Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*****************************************************************************
 ** Isaac -- Ivozng simplified Asterisk AMI Connector
 **
 ** Copyright (C) 2013 Irontec S.L.
 ** Copyright (C) 2013 Ivan Alonso (aka Kaian)
 **
 ** Only change function headers to be documented with Doxygen like the rest of
 ** Isaac source files.
 **
 *****************************************************************************/
/**
 * \file pidfile.h
 * \brief Functions to work with pidfiles.
 * \author Martin Schulze <Martin.Schulze@Linux.DE>
 *
 * This file contains some simple functions to handle program pidfile.
 */
#ifndef PIDFILE_H_
#define PIDFILE_H_

/**
 * \brief Reads PID from file.
 *
 * Reads the specified pidfile and returns the read PID.
 * \note This function is not actually being used.
 *
 * \param pidfile Filename for store the program PID
 * \return 0 If there's no pidfile or it's empty or no pid can be read.
 * \return 1 In any other case
 */
extern int
read_pid(char *pidfile);

/**
 * \brief Check if program is running.
 *
 * Reads the pid using \ref read_pid and looks up the pid in the process
 * table (using /proc) to determine if the process already exists.
 * \note This function is not actually being used.
 *
 * \param pidfile Filename for store the program PID
 * \return 1 If process already exists
 * \return 0 If process is not running
 */
extern int
check_pid(char *pidfile);

/**
 * \brief Writes PID to file.
 *
 * Writes the PID to the specified file.
 *
 * \param pidfile Filename for store the program PID
 * \return 0 If fails
 * \return PID on success
 */
extern int
write_pid(char *pidfile);

/**
 * \brief Removes the specified file.
 *
 * Removes the pidfile using unlink.
 *
 * \param pidfile Filename for store the program PID
 * \return result from unlink(2)
 */
extern int
remove_pid(char *pidfile);

#endif /* PIDFILE_H_ */
