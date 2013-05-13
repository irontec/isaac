/******************************************************************************
 **
 ** Copyright (C) 2011-2012 Irontec SL. All rights reserved.
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
 ******************************************************************************/
/**
 * \file util.c
 * \author Iván Alonso [aka Kaian] <kaian@irontec.com>
 *
 * \brief Source code for functions defined in util.h
 */

#include "util.h"
#include "log.h"

/// \cond INCLUDE_UTILS

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
    return strcmp(s1, s2);
}

int
isaac_strncmp(const char *s1, const char *s2, int len)
{
    return strncmp(s1, s2, len);
}

struct timeval
isaac_tvnow(void)
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return t;
}

#define ONE_MILLION     1000000

static struct timeval
tvfix(struct timeval a)
{
    if (a.tv_usec >= ONE_MILLION) {
        isaac_log(LOG_WARNING, "warning too large timestamp %ld.%ld\n",
                (long)a.tv_sec, (long int) a.tv_usec);
        a.tv_sec += a.tv_usec / ONE_MILLION;
        a.tv_usec %= ONE_MILLION;
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
    if (a.tv_usec >= ONE_MILLION) {
        a.tv_sec++;
        a.tv_usec -= ONE_MILLION;
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
        a.tv_usec += ONE_MILLION;
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

/// \endcond INCLUDE_UTILS
