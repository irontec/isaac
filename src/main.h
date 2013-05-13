/****************************************************************************
 **
 ** Copyright (C) 2011 Irontec SL. All rights reserved.
 **
 ** This file may be used under the terms of the GNU General Public
 ** License version 3.0 as published by the Free Software Foundation
 ** and appearing in the file LICENSE.GPL included in the packaging of
 ** this file.  Please review the following information to ensure GNU
 ** General Public Licensing requirements will be met:
 **
 ** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
 ** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 **
 ****************************************************************************/
/**
 * \file main.h
 * \brief Main functions used for program startup and halt
 *
 * This file contains some general defines and the initial functions used to start and stop
 * IronSC.
 *
 * Main program function is also included in this file.
 */

#ifndef MAIN_H_
#define MAIN_H_

/** Short Name for this application */
#define APP_NAME "IronSC"
/** Long Name for this application */
#define APP_LONG_NAME "Irontec Satelite's Controller"

/**
 * \brief Prints program version and exits
 */
extern void
version();

/**
 * \brief Print usage info and exits
 * \param progname binary file name
 */
extern void
usage(const char* progname);

/**
 * \brief Quit handler function
 *
 * This function will do all necesary cleanup before exiting
 * the program. Use this instead of exit() if launchers, satelites,
 * cli or scheduler are still running.
 *
 * \param sig Received signal code
 * \todo Implement Scheduler thread stop
 * \todo Implement Satelites unload
 * \todo Implement Launchers unload
 */
extern void
quit(int sig);

/**
 * \brief Main program function
 *
 * This functions parse command line options to determine satcon behaviour
 * This progran can be used as a Satelite process controler or a CLI client
 * if -r option is specified.
 *
 * \param argc Argument counter
 * \param argv Array of string arguments passed to the program
 */
extern int
main(int argc, char *argv[]);

#endif /* MAIN_H_ */
