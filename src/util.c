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
 * @file util.c
 * @author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source code for functions defined in util.h
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "util.h"
#include "log.h"

/*! \brief Wrapper for strcpy */
int
isaac_strcpy(char *dst, const char *src)
{
    /* We don't malloc memory for you.. */
    if (!dst)
        return 1;
    /* We don't copy null pointers */
    if (!src)
        return 1;

    /* Do the copy */
    strcpy(dst, src);

    return 0;
}

/*! \brief Wrapper for strncpy */
int
isaac_strncpy(char *dst, const char *src, int len)
{
    /* We don't malloc memory for you.. */
    if (!dst)
        return 1;
    /* We don't copy null pointers */
    if (!src)
        return 1;

    /* Do the copy */
    strncpy(dst, src, len);
    /* Close the string properly */
    dst[len] = '\0';

    return 0;
}

/*! \brief Wrapper for free */
void
isaac_free(void *mem)
{
    if (mem)
        free(mem);
    mem = NULL;
}

/*! \brief Wrapper for strlen */
int
isaac_strlen(const char *str)
{
    /* No string, return 0 */
    if (!str)
        return 0;
    else
        return strlen(str);
}

int
isaac_strcmp(const char *s1, const char *s2)
{
    if (!s1 || !s2) return 1;
    return strcmp(s1, s2);
}

int
isaac_strcasecmp(const char *s1, const char *s2)
{
    if (!s1 || !s2) return 1;
    return strcasecmp(s1, s2);
}

int
isaac_strncmp(const char *s1, const char *s2, int len)
{
    if (!s1 || !s2) return 1;
    return strncmp(s1, s2, len);
}

struct timeval
isaac_tvnow(void)
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return t;
}

struct timeval
tvfix(struct timeval a)
{
    if (a.tv_usec >= 1000000) {
        isaac_log(LOG_WARNING, "warning too large timestamp %ld.%ld\n",
                (long)a.tv_sec, (long int) a.tv_usec);
        a.tv_sec += a.tv_usec / 1000000;
        a.tv_usec %= 1000000;
    } else if (a.tv_usec < 0) {
        isaac_log(LOG_WARNING, "warning negative timestamp %ld.%ld\n",
                (long)a.tv_sec, (long int) a.tv_usec);
        a.tv_usec = 0;
    }
    return a;
}

struct timeval
isaac_tvadd(struct timeval a, struct timeval b)
{
    /* consistency checks to guarantee usec in 0..999999 */
    a = tvfix(a);
    b = tvfix(b);
    a.tv_sec += b.tv_sec;
    a.tv_usec += b.tv_usec;
    if (a.tv_usec >= 1000000) {
        a.tv_sec++;
        a.tv_usec -= 1000000;
    }
    return a;
}

struct timeval
isaac_tvsub(struct timeval a, struct timeval b)
{
    /* consistency checks to guarantee usec in 0..999999 */
    a = tvfix(a);
    b = tvfix(b);
    a.tv_sec -= b.tv_sec;
    a.tv_usec -= b.tv_usec;
    if (a.tv_usec < 0) {
        a.tv_sec--;
        a.tv_usec += 1000000;
    }
    return a;
}

char *
isaac_skip_blanks(const char *str)
{
    while (*str && *str < 33)
        str++;
    return (char *) str;
}

char *
isaac_trim_blanks(char *str)
{
    char *work = str;

    if (work) {
        work += strlen(work) - 1;
        /* It's tempting to only want to erase after we exit this loop,
         but since isaac_trim_blanks *could* receive a constant string
         (which we presumably wouldn't have to touch), we shouldn't
         actually set anything unless we must, and it's easier just
         to set each position to \0 than to keep track of a variable
         for it */
        while ((work >= str) && *work < 33)
            *(work--) = '\0';
    }
    return str;
}

char *
isaac_strip(char *s)
{
    s = isaac_skip_blanks(s);
    if (s)
        isaac_trim_blanks(s);
    return s;
}

char *
isaac_skip_nonblanks(const char *str)
{
    while (*str && ((unsigned char) *str) > 32)
        str++;
    return (char *) str;
}

void
isaac_copy_string(char *dst, const char *src, size_t size)
{
    while (*src && size) {
        *dst++ = *src++;
        size--;
    }
    if (__builtin_expect(!size, 0))
        dst--;
    *dst = '\0';
}

void
isaac_join(char *s, size_t len, const char* const w[])
{
    int x, ofs = 0;
    const char *src;

    /* Join words into a string */
    if (!s)
        return;

    for (x = 0; ofs < len && w[x]; x++) {
        if (x > 0)
            s[ofs++] = ' ';
        for (src = w[x]; *src && ofs < len; src++)
            s[ofs++] = *src;
    }
    if (ofs == len)
        ofs--;
    s[ofs] = '\0';
}

int
isaac_strlen_zero(const char *s)
{
    return (!s || (*s == '\0'));
}


void
isaac_tvelap(struct timeval timeval, int printsec, char *out)
{
    int x; /* the main part - years, weeks, etc. */
    char year[256] = "", week[256] = "", day[256] = "", hour[256] = "", minute[256] = "";

    if (timeval.tv_sec < 0) /* invalid, nothing to show */
    return;

    if (printsec) { /* plain seconds output */
        sprintf(out, "%lu", (u_long) timeval.tv_sec);
        return;
    }
    if (timeval.tv_sec > YEAR) {
        x = (timeval.tv_sec / YEAR);
        timeval.tv_sec -= (x * YEAR);
        sprintf(year, " %d year%s%s", x, ESS(x), NEEDCOMMA(timeval.tv_sec));
    }
    if (timeval.tv_sec > WEEK) {
        x = (timeval.tv_sec / WEEK);
        timeval.tv_sec -= (x * WEEK);
        sprintf(week, " %d week%s%s", x, ESS(x), NEEDCOMMA(timeval.tv_sec));
    }
    if (timeval.tv_sec > DAY) {
        x = (timeval.tv_sec / DAY);
        timeval.tv_sec -= (x * DAY);
        sprintf(day, " %d day%s%s", x, ESS(x), NEEDCOMMA(timeval.tv_sec));
    }
    if (timeval.tv_sec > HOUR) {
        x = (timeval.tv_sec / HOUR);
        timeval.tv_sec -= (x * HOUR);
        sprintf(hour, " %d hour%s%s", x, ESS(x), NEEDCOMMA(timeval.tv_sec));
    }
    if (timeval.tv_sec > MINUTE) {
        x = (timeval.tv_sec / MINUTE);
        timeval.tv_sec -= (x * MINUTE);
        sprintf(minute, " %d minute%s%s", x, ESS(x), NEEDCOMMA(timeval.tv_sec));
    }

    x = timeval.tv_sec;
    sprintf(out, "%s%s%s%s%s %d second%s ", year, week, day, hour, minute, x, ESS(x));
}


void
isaac_toupper(char *str)
{
    char *sptr;

    if (!str) return;
    
    for(sptr = str; *sptr != '\0'; sptr++) {
        *sptr = toupper((unsigned char)*sptr);
    }
}
