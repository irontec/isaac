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
 * @file log.c
 * @author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source code for functions defined in log.h
 */

#include "config.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <pthread.h>
#include "log.h"
#include "cli.h"
#include "util.h"
#include "cfg.h"

//! Debug configuration
gboolean debug_mode;
//! Pointer for File descriptor. Only used if logtype is LOG_TYPE_FILE
FILE *logfile;
//! Log lock. Avoid printing more than messages at a time
pthread_mutex_t loglock;

const char *
log_type_to_text(int log_type)
{
    // Get log prefix depending on log_type
    switch (log_type) {
        case LOG_DEBUG:
            return "\033[1;34mDEBUG\033[0m";
        case LOG_WARNING:
            return "\033[0;31mWARNING\033[0m";
        case LOG_NOTICE:
            return "\033[1;33mNOTICE\033[0m";
        case LOG_ERROR:
            return "\033[1;31mERROR\033[0m";
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

    // Unknown logging type
    return NULL;
}

void
isaac_log_location(int log_level, const char *file, int line, const char *function, const char *fmt,
                   ...)
{
    char logmsg[MAX_MSG_SIZE];
    char msgva[MAX_MSG_SIZE];
    va_list ap;
    time_t t;
    struct tm tm;
    char date[80];

    // Check if the log message has enough level to be printed or it's a verbose message
    // Verbose messages are always printed to CLI but not to syslog mediums
    if (log_level > cfg_get_log_level() && log_level < LOG_VERBOSE_1) {
        return;
    }

    // Get the actual time
    time(&t);
    localtime_r(&t, &tm);
    strftime(date, sizeof(date), DATEFORMAT, &tm);

    // Get the message from the format string
    va_start(ap, fmt);
    vsprintf(msgva, fmt, ap);
    va_end(ap);

    // Build the final message depending on its level
    if (log_level < LOG_VERBOSE_1) {
        sprintf(logmsg, "\33[2K\r[%s] %s: [%ld]\033[1;37m: %s:%d %s:\033[0m %s", date,
                log_type_to_text(log_level), TID, file, line, function, msgva);
    } else {
        sprintf(logmsg, "\33[2K\r%s%s", log_type_to_text(log_level), msgva);
    }

    // Lock here to avoid more than one message write at the same time
    pthread_mutex_lock(&loglock);
    // If running in debug mode just print to the screen
    if (debug_mode) {
        printf("%s", logmsg);
    }

    // Write to all CLI clients
    cli_broadcast(logmsg);

    // Remove all color from the messsage and write to log medium
    clean_text(logmsg);
    write_log(log_level, logmsg);
    pthread_mutex_unlock(&loglock);
}

gboolean
start_logging(gboolean debug)
{
    if (cfg_get_log_type() == LOG_TYPE_SYSLOG) {
        openlog(cfg_get_log_tag(), LOG_PID | LOG_CONS, LOG_USER);
    } else if (cfg_get_log_type() == LOG_TYPE_FILE) {
        // Open requested Log File
        if (!(logfile = fopen(cfg_get_log_file(), "a"))) {
            isaac_log(LOG_ERROR, "Unable to open logfile: %s!\n", cfg_get_log_file());
            return FALSE;
        }
    }

    // Request debug messages to stdout
    debug_mode = debug;

    // We have succeeded opening medium
    return TRUE;
}

int
stop_logging()
{
    if (cfg_get_log_type() == LOG_TYPE_SYSLOG) {
        closelog();
    } else if (cfg_get_log_type() == LOG_TYPE_FILE) {
        // Close the log file
        if (logfile) {
            fflush(logfile);
            fclose(logfile);
        }
    }
    return 0;
}

void
write_log(int log_level, const char *message)
{
    // Only log to medium levels lower or same than configured
    if (log_level <= cfg_get_log_level()) {
        if (cfg_get_log_type() == LOG_TYPE_SYSLOG) {
            syslog(log_level, "%s", message);
        } else if (cfg_get_log_type() == LOG_TYPE_FILE) {
            //\todo write log to file
        }
    }
}

void
clean_text(char *text)
{
    int i, j = 0;
    char clean[MAX_MSG_SIZE];

    // Loop through the text searching for some special characters
    // that give color to the CLIs. Remove them.
    for (i = 0; i <= (gint) strlen(text); i++) {
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
    isaac_strcpy(text, clean);
}
