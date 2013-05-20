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
 * \file pidfile.c
 * \author Martin Schulze <Martin.Schulze@Linux.DE>
 *
 * \brief Source code for functions defined in pidfile.h
 *
 * Minor changes from logging into configured facility in Isaac system.
 * Just using isaac_log instead of printf or fprintf
 *
 */
#include "config.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include "log.h"

int
read_pid(char *pidfile)
{
    FILE *f;
    int pid;

    if (!(f = fopen(pidfile, "r"))) return 0;
    if (fscanf(f, "%d", &pid)) {
        fclose(f);
    } else {
        pid = -1;
    }
    return pid;
}

int
check_pid(char *pidfile)
{
    int pid = read_pid(pidfile);

    /* Amazing ! _I_ am already holding the pid file... */
    if ((!pid) || (pid == getpid())) return 0;

    /*
     * The 'standard' method of doing this is to try and do a 'fake' kill
     * of the process.  If an ESRCH error is returned the process cannot
     * be found -- GW
     */
    /* But... errno is usually changed only on error.. */
    if (kill(pid, 0) && errno == ESRCH) return (0);

    return pid;
}

int
write_pid(char *pidfile)
{
    FILE *f;
    int fd;
    int pid;

    if (((fd = open(pidfile, O_RDWR | O_CREAT, 0644)) == -1) || ((f = fdopen(fd, "r+")) == NULL)) {
        isaac_log(LOG_ERROR, "Can't open or create %s\n", pidfile);
        return 0;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
        if (fscanf(f, "%d", &pid)) {
            fclose(f);
        } else {
            pid = -1;
        }
        isaac_log(LOG_ERROR, "Can't lock, lock is held by pid %d\n", pid);
        return 0;
    }

    pid = getpid();
    if (!fprintf(f, "%d\n", pid)) {
        isaac_log(LOG_ERROR, "Can't write pid , %s\n", strerror(errno));
        close(fd);
        return 0;
    }
    fflush(f);

    if (flock(fd, LOCK_UN) == -1) {
        isaac_log(LOG_ERROR, "Can't unlock pidfile %s, %s\n", pidfile, strerror(errno));
        close(fd);
        return 0;
    }
    close(fd);
    isaac_log(LOG_VERBOSE, "Pidfile written at %s\n", pidfile);

    return pid;
}

int
remove_pid(char *pidfile)
{
    return unlink(pidfile);
}
