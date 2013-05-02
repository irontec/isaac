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
 * \file log.c
 * \author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * \brief Source code for functions defined in log.h
 */

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <pthread.h>
//#include "config.h"
#include "log.h"
//#include "cli.h"

//! Pointer for File descriptor. Only used if logtype is LOG_TYPE_FILE
FILE *logfile;
//! Log lock. Avoid printing more than messages at a time
pthread_mutex_t loglock;
//! Extern debug flag defined in main.c
//extern int debug;

/******************************************************************************
 *****************************************************************************/
const char *
log_type_to_text(int log_type, int colour)
{
    /* Get log prefix depending on log_type */
    switch (log_type) {
    case LOG_DEBUG:
        return (colour) ? "\e[1;34mDEBUG\e[0m" : "DEBUG ";
    case LOG_WARNING:
        return (colour) ? "\e[0;31mWARNING\e[0m" : "WARNING ";
    case LOG_NOTICE:
        return (colour) ? "\e[1;33mNOTICE\e[0m" : "NOTICE ";
    case LOG_ERROR:
        return (colour) ? "\e[1;31mERROR\e[0m" : "ERROR ";
    case LOG_NONE:
        return "";
    case LOG_VERBOSE_1:
        return "  == ";
    case LOG_VERBOSE_2:
        return "\t-- ";
    case LOG_VERBOSE_3:
        return "\t\t> ";
    case LOG_VERBOSE_4:
        return "\t\t\to ";
    }

    /* Something went wrong */
    return NULL;
}

/*****************************************************************************/
void isaac_log_location(int log_type, const char *file, int line, const char *function,
        const char *fmt, ...)
{
#define NOCOLOUR 	0
#define COLOUR		1
    char climsg[MAX_MSG_SIZE];
    char logmsg[MAX_MSG_SIZE];
    char msgva[MAX_MSG_SIZE];
    long int tid = (long int) syscall(SYS_gettid);
    va_list ap;
    time_t t;
    struct tm tm;
    char date[80];
    //struct isaac_cli *cur;
    //const struct isaac_config isaac_cfg = get_config();
    //struct isaac_cli *clilist = (struct isaac_cli *) get_cli_list();

    //if (log_type < LOG_VERBOSE_1 && log_type >= isaac_cfg.loglevel)
    //    return;

    time(&t);
    localtime_r(&t, &tm);
    strftime(date, sizeof(date), DATEFORMAT, &tm);

    pthread_mutex_lock(&loglock);
    va_start(ap, fmt);
    vsprintf(msgva, fmt, ap);
    va_end(ap);

    if (log_type < LOG_VERBOSE_1) {
        sprintf(climsg, "\33[2K\r[%s] %s: [%ld]\e[1;37m: %s:%d %s:\e[0m %s", date,
                log_type_to_text(log_type, COLOUR), tid, file, line, function, msgva);
        sprintf(logmsg, "[%s]: [%ld] %s:%d %s: %s", log_type_to_text(log_type, NOCOLOUR), tid,
                file, line, function, msgva);
    } else {
        sprintf(climsg, "\33[2K\r%s%s", log_type_to_text(log_type, COLOUR), msgva);
        sprintf(logmsg, "%s %s", log_type_to_text(log_type, NOCOLOUR), msgva);
    }

    /* If running in debug mode **/
    printf("%s", climsg);

    /* Write to log **/
    //write_log(log_type, logmsg);

    /* Write to clients **/
    //for (cur = clilist; cur; cur = cur->next) {
    //    pthread_mutex_lock(&cur->lock);
    //    cli_write(cur->fd, climsg);
    //	usleep(100);
    //    pthread_mutex_unlock(&cur->lock);
    //}

    pthread_mutex_unlock(&loglock);
}

///*****************************************************************************/
//int
//open_log(const char *filename)
//{
//    const struct isaac_config isaac_cfg = get_config();
//
//    if (!strcmp(isaac_cfg.logtype, LOG_TYPE_SYSLOG)) {
//        openlog("ironsc", LOG_PID | LOG_CONS, LOG_USER);
//    } else if (!strcmp(isaac_cfg.logtype, LOG_TYPE_FILE)) {
//        // Open requested Log File
//        if (!(logfile = fopen(isaac_cfg.logfile, "a"))) {
//            isaac_log(LOG_ERROR, "Unable to open logfile: %s!\n", isaac_cfg.logfile);
//            return 1;
//        }
//    } else {
//        isaac_log(LOG_ERROR, "Unknown Log file format %s\n", isaac_cfg.logtype);
//        return 1;
//    }
//    // We have succeded opening medium
//    return 0;
//}
//
///*****************************************************************************/
//void
//close_log()
//{
//    const struct isaac_config isaac_cfg = get_config();
//    if (!strcmp(isaac_cfg.logtype, LOG_TYPE_SYSLOG)) {
//        //closelog();
//    } else if (!strcmp(isaac_cfg.logtype, LOG_TYPE_FILE)) {
//        // Close
//        if (logfile) {
//            fflush(logfile);
//            fclose(logfile);
//        }
//    }
//}
//
///*****************************************************************************/
//void
//write_log(int log_type, const char *message)
//{
//    const struct isaac_config isaac_cfg = get_config();
//    if (log_type <= isaac_cfg.loglevel) {
//        if (!strcmp(isaac_cfg.logtype, LOG_TYPE_SYSLOG)) {
//            syslog(log_type, "%s", message);
//        } else if (!strcmp(isaac_cfg.logtype, LOG_TYPE_FILE)) {
//        }
//    }
//}
