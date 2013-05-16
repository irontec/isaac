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

#include "isaac.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <pthread.h>
#include "log.h"
#include "cli.h"

//! Pointer for File descriptor. Only used if logtype is LOG_TYPE_FILE
FILE *logfile;
//! Log lock. Avoid printing more than messages at a time
pthread_mutex_t loglock;

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
        return "    -- ";
    case LOG_VERBOSE_3:
        return "      > ";
    case LOG_VERBOSE_4:
        return "        o ";
    }

    /* Something went wrong */
    return NULL;
}

/*****************************************************************************/
void
isaac_log_location(int log_type, const char *file, int line, const char *function, const char *fmt,
        ...)
{
#define NOCOLOUR 	0
#define COLOUR		1
    char logmsg[MAX_MSG_SIZE];
    char msgva[MAX_MSG_SIZE];
    va_list ap;
    time_t t;
    struct tm tm;
    char date[80];

    if (log_type < LOG_VERBOSE_1 && log_type >= config.loglevel) {
        return;
    }

    time(&t);
    localtime_r(&t, &tm);
    strftime(date, sizeof(date), DATEFORMAT, &tm);

    pthread_mutex_lock(&loglock);
    va_start(ap, fmt);
    vsprintf(msgva, fmt, ap);
    va_end(ap);

    if (log_type < LOG_VERBOSE_1) {
        sprintf(logmsg, "\33[2K\r[%s] %s: [%ld]\e[1;37m: %s:%d %s:\e[0m %s", date,
                log_type_to_text(log_type, COLOUR), TID, file, line, function, msgva);
    } else {
        sprintf(logmsg, "\33[2K\r%s%s", log_type_to_text(log_type, COLOUR), msgva);
    }

    /* If running in debug mode **/
    if (debug) {
        printf("%s", logmsg);
    }

    /* Write to clients **/
    cli_broadcast(logmsg);

    /* Write to log medium**/
    clean_text(logmsg);
    write_log(log_type, logmsg);

    pthread_mutex_unlock(&loglock);
}

int
start_logging(enum log_type type, const char *tag, const char *file, int level)
{
    if (config.logtype == LOG_TYPE_SYSLOG) {
        openlog(config.logtag, LOG_PID | LOG_CONS, LOG_USER);
    } else if (config.logtype == LOG_TYPE_FILE) {
        // Open requested Log File
        if (!(logfile = fopen(config.logfile, "a"))) {
            isaac_log(LOG_ERROR, "Unable to open logfile: %s!\n", config.logfile);
            return -1;
        }
    }
    // We have succeded opening medium
    return 0;
}

/*****************************************************************************/
int
stop_logging()
{
    if (config.logtype == LOG_TYPE_SYSLOG) {
        closelog();
    } else if (config.logtype == LOG_TYPE_FILE) {
        // Close the log file
        if (logfile) {
            fflush(logfile);
            fclose(logfile);
        }
    }
    return 0;
}

//*****************************************************************************/
void
write_log(int log_type, const char *message)
{
    if (log_type <= config.loglevel) {
        if (config.logtype == LOG_TYPE_SYSLOG) {
            syslog(log_type, "%s", message);
        } else if (config.logtype == LOG_TYPE_FILE) {
            //\todo write log to file
        }
    }
}

//*****************************************************************************/
void
clean_text(char *text)
{
    int i, j = 0;
    char clean[MAX_MSG_SIZE];

    for (i = 0; i <= strlen(text); i++) {
        if (text[i] == 27) {
            switch (text[i + 2]) {
            case 48:
                i += 3;
                break;
            case 49:
                i += 6;
                break;
            case 50:
                i += 4;
                break;
            }
            continue;
        }
        clean[j++] = text[i];
    }
    strcpy(text, clean);
}
